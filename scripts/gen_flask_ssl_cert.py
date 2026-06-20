"""
生成 Flask 原生 HTTPS SSL 证书
替代原来的 Nginx 代理方案，让 Flask 直接支持 HTTPS
"""
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address

from pki_demo.security_crypto import generate_keypair, get_signature_hash

BASE_DIR = Path(__file__).parent.parent
SSL_DIR = BASE_DIR / "pki_demo" / "certs"


def main():
    print("=" * 60)
    print("  生成 Flask HTTPS SSL 证书")
    print("=" * 60)

    cert_path = SSL_DIR / "flask_ssl_cert.pem"
    key_path = SSL_DIR / "flask_ssl_key.pem"

    # 检查是否已存在
    if cert_path.exists() and key_path.exists():
        print("\n[OK] SSL证书已存在，跳过生成")
        print(f"  证书: {cert_path}")
        print(f"  密钥: {key_path}")
        return

    SSL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 生成密钥对
    print("\n[1/3] 生成密钥对...")
    key = generate_keypair()
    print("  [OK] 密钥对生成完成")

    # 2. 创建自签证书
    print("[2/3] 签发自签名证书...")
    now = datetime.now(timezone.utc)
    san_names = [
        DNSName("localhost"),
        DNSName("127.0.0.1"),
        DNSName("*.localhost"),
        IPAddress(ip_address("127.0.0.1")),
        IPAddress(ip_address("::1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI System"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI System"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, get_signature_hash(), default_backend())
    )

    # 3. 保存文件
    print("[3/3] 保存证书文件...")

    # 私钥（未加密，供Flask SSL上下文使用）
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  [OK] 私钥: {key_path}")

    # 证书
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] 证书: {cert_path}")

    print(f"""
{'=' * 60}
  Flask HTTPS SSL 证书生成完成！
{'=' * 60}
  证书信息:
    CN: localhost
    SAN: localhost, 127.0.0.1, *.localhost, ::1
    有效期: 5年

  使用方式:
    python api_server.py --https       # 使用现有证书
    python api_server.py --https --gen-ssl   # 自动生成证书并启动
    python start_dev.py --https        # 通过启动脚本使用
{'=' * 60}
""")


if __name__ == "__main__":
    main()
