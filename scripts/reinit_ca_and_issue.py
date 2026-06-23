"""
重新初始化CA证书和密钥，然后签发所有已批准的CSR
"""
import sys, os
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "pki_demo"))

# 设置开发密码
os.environ["PKI_CA_KEY_PASSWORD"] = "DEV_ONLY_change_me"
os.environ["PKI_USER_KEY_PASSWORD"] = "DEV_ONLY_change_me"

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from security_crypto import (
    generate_keypair, sign_certificate_with_hash,
    get_signature_hash, get_signature_algorithm
)
from config import CFG
from ra import ra_manager

BASE_DIR = Path(__file__).parent.parent / "pki_demo"

def create_root_ca():
    """创建根CA"""
    print("\n=== 1. 创建根CA ===")
    cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"
    key_path = BASE_DIR / "keys" / "root_ca_private.pem"

    if cert_path.exists() and key_path.exists():
        print("根CA已存在，跳过")
        return True

    key = generate_keypair()
    algo = get_signature_algorithm()
    print(f"  算法: {algo}")

    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    key_path.parent.mkdir(exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(ca_pwd)
        ))
    print(f"  [OK] 根CA私钥已保存")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI演示系统"),
        x509.NameAttribute(NameOID.COMMON_NAME, "演示根CA"),
    ])
    now = datetime.now(timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign