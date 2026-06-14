"""
中间CA签发模块 (inter_ca.py)
功能：使用根CA签发中间CA证书，实现CA层级分离
优化项：FIX-11（无中间CA -> 两级CA架构）
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from config import CFG
from security_crypto import get_hash_algorithm, get_rsa_key_size

BASE_DIR = Path(__file__).parent.resolve()

def generate_intermediate_ca():
    """使用根CA签发中间CA证书"""
    ca_cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"
    ca_key_path = BASE_DIR / "keys" / "root_ca_private.pem"
    inter_key_path = BASE_DIR / "keys" / "inter_ca_private.pem"
    inter_cert_path = BASE_DIR / "certs" / "inter_ca_cert.pem"

    if not ca_cert_path.exists():
        return False, "根CA尚未创建，请先创建根CA"

    if inter_cert_path.exists():
        return True, "中间CA证书已存在，跳过"

    # 加载根CA密钥和证书
    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        raise RuntimeError("环境变量 PKI_CA_KEY_PASSWORD 未设置，无法加载CA私钥")
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=ca_pwd, backend=default_backend()
        )
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 生成中间CA密钥对
    inter_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=get_rsa_key_size(),
        backend=default_backend()
    )

    # 保存中间CA私钥
    inter_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not inter_pwd:
        raise RuntimeError("环境变量 PKI_CA_KEY_PASSWORD 未设置，无法保护中间CA私钥")
    pem_data = inter_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(inter_pwd)
    )
    with open(inter_key_path, "wb") as f:
        f.write(pem_data)

    # 由根CA签发中间CA证书
    now = datetime.now(timezone.utc)
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI演示系统"),
            x509.NameAttribute(NameOID.COMMON_NAME, "演示中间CA"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True,
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, get_hash_algorithm(), default_backend())
    )

    with open(inter_cert_path, "wb") as f:
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))

    return True, "中间CA证书已签发，信任链: 根CA -> 中间CA -> 用户"
