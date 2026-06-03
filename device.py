import json
import random
import struct
import time
from cryptography.hazmat.primitives.asymmetric import ec

from colors import C, step, hex_dump, info, ok, err
from crypto_utils import (
    derive_session_keys, make_nonce,
    aes_ccm_encrypt, hmac_sha256,
)
from pki import verify_cert


COLOR = C.GREEN


class IoTDevice:

    def __init__(self, serial, ca_cert, device_cert, device_key):
        self.serial = serial
        self.ca_cert = ca_cert
        self.device_cert = device_cert
        self.device_key = device_key

        self.session_aes_key = None
        self.session_hmac_key = None
        self.msg_counter = 0
        self.gateway_pub = None

    def handshake(self, gateway):
        info("Установление защищённого соединения с шлюзом...")
        t_start = time.perf_counter()

        eph_priv = ec.generate_private_key(ec.SECP256R1())
        eph_pub = eph_priv.public_key()

        step("DEVICE", "ClientHello: сертификат устройства + эфемерный ECDH-ключ",
             COLOR)

        gw_eph_pub, gw_cert = gateway.handle_handshake(
            self.device_cert, eph_pub)

        if gw_cert is None:
            err("Шлюз отверг наш сертификат")
            return False

        step("DEVICE", "Принят ответ шлюза: его сертификат + эфемерный ECDH-ключ",
             COLOR)
        step("DEVICE", "Проверка сертификата шлюза по корневому CA...", COLOR)

        if not verify_cert(gw_cert, self.ca_cert):
            err("СЕРТИФИКАТ ШЛЮЗА НЕ ПРОШЁЛ ПРОВЕРКУ ПО ДОВЕРЕННОМУ CA!")
            err("Это означает попытку MITM. Соединение прервано.")
            return False

        ok("Сертификат шлюза валиден: " + gw_cert.subject.rfc4514_string())

        shared = eph_priv.exchange(ec.ECDH(), gw_eph_pub)
        step("DEVICE", f"Общий секрет ECDH вычислен ({len(shared)} байт)", COLOR)

        self.session_aes_key, self.session_hmac_key = derive_session_keys(shared)
        step("DEVICE",
             f"Выработаны сессионные ключи: AES-128 ({len(self.session_aes_key)}Б)"
             f" + HMAC ({len(self.session_hmac_key)}Б)", COLOR)

        elapsed = (time.perf_counter() - t_start) * 1000
        ok(f"Рукопожатие завершено за {elapsed:.1f} мс. "
           f"Канал готов к передаче данных.")
        return True

    def _read_sensor(self):
        temperature = round(20.0 + random.random() * 8.0, 1)
        humidity = round(40.0 + random.random() * 20.0, 1)
        return temperature, humidity

    def create_telemetry_packet(self):
        temp, hum = self._read_sensor()
        self.msg_counter += 1
        ts = int(time.time())

        payload = {
            "t": temp,
            "h": hum,
            "ts": ts,
            "sn": self.serial,
            "c": self.msg_counter,
        }
        plaintext = json.dumps(payload, separators=(',', ':')).encode()
        step("DEVICE", f"Показания: T={temp}°C  H={hum}%  c={self.msg_counter}",
             COLOR)
        step("DEVICE", f"Открытый JSON: {plaintext.decode()} ({len(plaintext)} Б)",
             COLOR)

        # заголовок одновременно служит nonce и AAD
        header = struct.pack('>IQ', self.serial, self.msg_counter)

        nonce = make_nonce(self.serial, self.msg_counter)
        ct_and_tag = aes_ccm_encrypt(self.session_aes_key, nonce, plaintext, header)
        step("DEVICE",
             f"Зашифровано AES-128-CCM: {len(ct_and_tag)} Б (включая 8-байт тег)",
             COLOR)
        hex_dump(ct_and_tag, label="шифротекст+тег")

        body = header + ct_and_tag
        hmac_tag = hmac_sha256(self.session_hmac_key, body)
        step("DEVICE", f"Прикладная подпись HMAC-SHA256: {len(hmac_tag)} Б", COLOR)

        length = struct.pack('>H', len(ct_and_tag))
        packet = header + length + ct_and_tag + hmac_tag
        step("DEVICE", f"Отправка пакета размером {len(packet)} байт", COLOR)
        return packet
