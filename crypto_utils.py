import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


AES_KEY_LEN = 16
NONCE_LEN = 12
TAG_LEN = 8          # 64-битный тег: компромисс размера пакета и стойкости
HMAC_KEY_LEN = 32


def derive_session_keys(shared_secret, context=b'iot-demo-v1'):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN + HMAC_KEY_LEN,
        salt=b'iot-handshake-salt',
        info=context,
    )
    out = hkdf.derive(shared_secret)
    return out[:AES_KEY_LEN], out[AES_KEY_LEN:]


def make_nonce(device_sn, counter):
    # serial (4 байта) + counter (8 байт); монотонный счётчик исключает повтор nonce
    return struct.pack('>IQ', device_sn, counter)


def aes_ccm_encrypt(key, nonce, plaintext, aad):
    aesccm = AESCCM(key, tag_length=TAG_LEN)
    return aesccm.encrypt(nonce, plaintext, aad)


def aes_ccm_decrypt(key, nonce, ct_and_tag, aad):
    aesccm = AESCCM(key, tag_length=TAG_LEN)
    return aesccm.decrypt(nonce, ct_and_tag, aad)


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_verify(key, data, tag):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(tag)
