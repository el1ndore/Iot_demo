import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from colors import C, step


COLOR = C.RED


class Attacker:

    def __init__(self):
        self.captured = []

    def tamper_packet(self, packet):
        step("ATTACKER", "Перехвачен пакет, изменяю один байт в шифротексте...",
             COLOR)
        target = 14 + (len(packet) - 14 - 32) // 2
        modified = bytearray(packet)
        modified[target] ^= 0xFF
        step("ATTACKER",
             f"Изменён байт #{target}: 0x{packet[target]:02x} -> "
             f"0x{modified[target]:02x}", COLOR)
        return bytes(modified)

    def capture_packet(self, packet):
        step("ATTACKER", f"Сохраняю копию пакета ({len(packet)} байт)", COLOR)
        self.captured.append(packet)

    def replay_last(self):
        step("ATTACKER",
             "Повторно отправляю ранее перехваченный пакет шлюзу", COLOR)
        return self.captured[-1]

    @staticmethod
    def create_fake_gateway():
        from gateway import IoTGateway

        step("ATTACKER",
             "Генерирую самоподписанный сертификат от имени 'gateway.local'...",
             COLOR)

        fake_key = ec.generate_private_key(ec.SECP256R1())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'gateway.local'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Evil Corp'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'XX'),
        ])

        now = datetime.datetime.utcnow()
        fake_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(fake_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .sign(private_key=fake_key, algorithm=hashes.SHA256())
        )

        return IoTGateway(
            ca_cert=fake_cert,
            gateway_cert=fake_cert,
            gateway_key=fake_key,
            accept_any_client=True,
        )
