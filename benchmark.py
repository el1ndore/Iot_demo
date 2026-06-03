import os
import time
from cryptography.hazmat.primitives import hashes, hmac as hmac_mod
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec

from colors import C, banner, info


def _measure(func, iterations):
    for _ in range(min(10, iterations)):
        func()
    t0 = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - t0
    return elapsed / iterations


def _format_time(seconds):
    if seconds < 1e-6:
        return f"{seconds * 1e9:.1f} нс"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f} мкс"
    if seconds < 1.0:
        return f"{seconds * 1e3:.2f} мс"
    return f"{seconds:.2f} с"


def _format_throughput(seconds, size_bytes):
    bps = size_bytes / seconds
    if bps > 1e9:
        return f"{bps / 1e9:.2f} ГБ/с"
    if bps > 1e6:
        return f"{bps / 1e6:.2f} МБ/с"
    return f"{bps / 1e3:.2f} КБ/с"


def run_benchmark():
    banner("ЗАМЕР ПРОИЗВОДИТЕЛЬНОСТИ КРИПТОГРАФИЧЕСКИХ ОПЕРАЦИЙ")
    info("Все замеры — на текущем ноутбуке. На реальном ESP32")
    info("значения будут другими (см. главу 6 курсовой).")
    print()

    rows = []

    key = os.urandom(16)
    nonce = os.urandom(12)
    aesccm = AESCCM(key, tag_length=8)

    pt64 = os.urandom(64)
    t = _measure(lambda: aesccm.encrypt(nonce, pt64, b''), 5000)
    rows.append(('AES-128-CCM шифрование, 64 байта',
                 _format_time(t), _format_throughput(t, 64)))

    pt1k = os.urandom(1024)
    t = _measure(lambda: aesccm.encrypt(nonce, pt1k, b''), 2000)
    rows.append(('AES-128-CCM шифрование, 1024 байта',
                 _format_time(t), _format_throughput(t, 1024)))

    def sha256_64():
        h = hashes.Hash(hashes.SHA256())
        h.update(pt64)
        h.finalize()
    t = _measure(sha256_64, 10000)
    rows.append(('SHA-256, 64 байта',
                 _format_time(t), _format_throughput(t, 64)))

    hkey = os.urandom(32)

    def do_hmac():
        h = hmac_mod.HMAC(hkey, hashes.SHA256())
        h.update(pt64)
        h.finalize()
    t = _measure(do_hmac, 5000)
    rows.append(('HMAC-SHA256, 64 байта',
                 _format_time(t), _format_throughput(t, 64)))

    sk = ec.generate_private_key(ec.SECP256R1())
    digest = os.urandom(32)
    t = _measure(lambda: sk.sign(digest, ec.ECDSA(hashes.SHA256())), 200)
    rows.append(('ECDSA подпись (P-256)', _format_time(t), '—'))

    sig = sk.sign(digest, ec.ECDSA(hashes.SHA256()))
    pk = sk.public_key()
    t = _measure(lambda: pk.verify(sig, digest, ec.ECDSA(hashes.SHA256())), 200)
    rows.append(('ECDSA проверка (P-256)', _format_time(t), '—'))

    sk2 = ec.generate_private_key(ec.SECP256R1())
    pk2 = sk2.public_key()
    t = _measure(lambda: sk.exchange(ec.ECDH(), pk2), 200)
    rows.append(('ECDH вычисление общего секрета', _format_time(t), '—'))

    def handshake():
        a_sk = ec.generate_private_key(ec.SECP256R1())
        b_sk = ec.generate_private_key(ec.SECP256R1())
        a_sk.exchange(ec.ECDH(), b_sk.public_key())
        b_sk.exchange(ec.ECDH(), a_sk.public_key())
        a_sig = a_sk.sign(digest, ec.ECDSA(hashes.SHA256()))
        a_sk.public_key().verify(a_sig, digest, ec.ECDSA(hashes.SHA256()))
    t = _measure(handshake, 100)
    rows.append(('Полное ECDHE+ECDSA рукопожатие', _format_time(t), '—'))

    col1 = max(len(r[0]) for r in rows)
    col2 = max(len(r[1]) for r in rows + [('', 'Время', '')])
    col3 = max(len(r[2]) for r in rows + [('', '', 'Пропускная способность')])

    print(f"  {C.BOLD}{'Операция':<{col1}}  {'Время':<{col2}}  "
          f"{'Пропускная способность':<{col3}}{C.RST}")
    print(f"  {'-' * col1}  {'-' * col2}  {'-' * col3}")
    for op, t_str, tp_str in rows:
        print(f"  {op:<{col1}}  {C.CYAN}{t_str:<{col2}}{C.RST}  "
              f"{C.GREEN}{tp_str:<{col3}}{C.RST}")
    print()
