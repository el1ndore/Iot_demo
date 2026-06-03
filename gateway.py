import json
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidTag, InvalidSignature

from colors import C, step, ok, err
from crypto_utils import (
    derive_session_keys, make_nonce,
    aes_ccm_decrypt, hmac_verify,
)
from pki import verify_cert


COLOR = C.MAGENTA


class IoTGateway:

    def __init__(self, ca_cert, gateway_cert, gateway_key, accept_any_client=False):
        self.ca_cert = ca_cert
        self.gateway_cert = gateway_cert
        self.gateway_key = gateway_key
        self.accept_any_client = accept_any_client

        self.session_aes_key = None
        self.session_hmac_key = None
        self.seen_counters = set()
        self.max_seen_counter = 0

    def handle_handshake(self, device_cert, device_eph_pub):
        step("GATEWAY", "Получен ClientHello от устройства", COLOR)

        if not self.accept_any_client:
            step("GATEWAY", "Проверка сертификата устройства по корневому CA...",
                 COLOR)
            if not verify_cert(device_cert, self.ca_cert):
                err("Сертификат устройства отвергнут!")
                return None, None
            ok("Сертификат устройства валиден: " +
               device_cert.subject.rfc4514_string())
        else:
            step("GATEWAY",
                 "(поддельный шлюз: принимаю любого клиента без проверки)",
                 COLOR)

        eph_priv = ec.generate_private_key(ec.SECP256R1())
        eph_pub = eph_priv.public_key()

        step("GATEWAY", "ServerHello: свой сертификат + эфемерный ECDH-ключ",
             COLOR)

        shared = eph_priv.exchange(ec.ECDH(), device_eph_pub)
        step("GATEWAY", f"Общий секрет ECDH вычислен ({len(shared)} байт)", COLOR)

        self.session_aes_key, self.session_hmac_key = derive_session_keys(shared)
        step("GATEWAY", "Выработаны сессионные ключи: AES-128 + HMAC", COLOR)

        return eph_pub, self.gateway_cert

    def receive_packet(self, packet):
        step("GATEWAY", f"Принят пакет размером {len(packet)} байт", COLOR)

        if len(packet) < 14 + 32:
            err("Пакет слишком короткий")
            return False

        header = packet[:12]
        serial, counter = struct.unpack('>IQ', header)
        ct_len = struct.unpack('>H', packet[12:14])[0]
        ct_and_tag = packet[14:14 + ct_len]
        hmac_tag = packet[14 + ct_len:]
        step("GATEWAY",
             f"Заголовок: serial=0x{serial:08X}, counter={counter}", COLOR)

        if counter in self.seen_counters:
            err(f"REPLAY ОБНАРУЖЕН! Счётчик {counter} уже встречался. "
                f"Пакет ОТВЕРГНУТ.")
            return False
        if counter < self.max_seen_counter - 32:
            err(f"Счётчик {counter} слишком старый "
                f"(текущий максимум {self.max_seen_counter}). Пакет ОТВЕРГНУТ.")
            return False

        body = header + ct_and_tag
        try:
            hmac_verify(self.session_hmac_key, body, hmac_tag)
            step("GATEWAY", "HMAC-SHA256 проверен", COLOR)
        except InvalidSignature:
            err("HMAC НЕ СОВПАЛ! Пакет ОТВЕРГНУТ.")
            return False

        nonce = make_nonce(serial, counter)
        try:
            plaintext = aes_ccm_decrypt(
                self.session_aes_key, nonce, ct_and_tag, header)
            step("GATEWAY", "Тег AES-CCM проверен (целостность подтверждена)",
                 COLOR)
        except InvalidTag:
            err("ТЕГ AES-CCM НЕ СОШЁЛСЯ! Пакет повреждён или подделан. "
                "ОТВЕРГНУТ.")
            return False

        self.seen_counters.add(counter)
        self.max_seen_counter = max(self.max_seen_counter, counter)

        try:
            data = json.loads(plaintext.decode())
            ok(f"Данные приняты: T={data['t']}°C  H={data['h']}%  "
               f"ts={data['ts']}  c={data['c']}")
        except Exception as e:
            err(f"Ошибка разбора JSON: {e}")
            return False

        return True
