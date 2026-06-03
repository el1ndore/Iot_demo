import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def _gen_key():
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert(subject_name, issuer_name, subject_pub_key,
               issuer_priv_key, is_ca=False, days=365):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'IoT-Demo'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'RU'),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'IoT-Demo'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'RU'),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
    )
    return builder.sign(private_key=issuer_priv_key, algorithm=hashes.SHA256())


def build_pki():
    ca_key = _gen_key()
    ca_cert = _make_cert(
        subject_name='IoT-Demo Root CA',
        issuer_name='IoT-Demo Root CA',
        subject_pub_key=ca_key.public_key(),
        issuer_priv_key=ca_key,
        is_ca=True,
        days=3650,
    )

    gateway_key = _gen_key()
    gateway_cert = _make_cert(
        subject_name='gateway.local',
        issuer_name='IoT-Demo Root CA',
        subject_pub_key=gateway_key.public_key(),
        issuer_priv_key=ca_key,
    )

    device_key = _gen_key()
    device_cert = _make_cert(
        subject_name='sensor-A5F3B201',
        issuer_name='IoT-Demo Root CA',
        subject_pub_key=device_key.public_key(),
        issuer_priv_key=ca_key,
    )

    return {
        'ca_key': ca_key,
        'ca_cert': ca_cert,
        'gateway_key': gateway_key,
        'gateway_cert': gateway_cert,
        'device_key': device_key,
        'device_cert': device_cert,
    }


def cert_info(cert):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if hasattr(cert, 'not_valid_after_utc'):
        not_after = cert.not_valid_after_utc
    else:
        not_after = cert.not_valid_after
    return {
        'cn': cn,
        'issuer': issuer_cn,
        'serial': cert.serial_number,
        'fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
        'not_after': not_after,
        'self_signed': cn == issuer_cn,
    }


def verify_cert(cert, ca_cert):
    try:
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return True
    except Exception:
        return False
