"""
为localhost签发TLS服务器证书
用于Nginx HTTPS反向代理
"""
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "pki_demo"))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address

from config import CFG
from security_crypto import get_hash_algorithm, get_rsa_key_size

BASE_DIR = Path(__file__).parent.parent
PKI_DEMO = BASE_DIR / "pki_demo"
NGINX_CERT_DIR = BASE_DIR / "nginx" / "certs"

def main():
    print("=" * 60)
    print("  为localhost签发TLS服务器证书")
    print("=" * 60)

    # 1. 加载CA（优先中间CA，其次根CA）
    ca_cert_path = PKI_DEMO / "certs" / "inter_ca_cert.pem"
    ca_key_path = PKI_DEMO / "keys" / "inter_ca_private.pem"
    ca_type = "中间CA"

    if not ca_cert_path.exists():
        ca_cert_path = PKI_DEMO / "certs" / "root_ca_cert.pem"
        ca_key_path = PKI_DEMO / "keys" / "root_ca_private.pem"
        ca_type = "根CA"

    if not ca_cert_path.exists():
        print("[FAIL] 未找到CA证书，请先创建根CA")
        sys.exit(1)

    print(f"\n[1/4] 加载{ca_type}...")
    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        print("[FAIL] PKI_CA_KEY_PASSWORD 环境变量未设置")
        sys.exit(1)

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=ca_pwd, backend=default_backend()
        )
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    print(f"  [OK] 已加载{ca_type}: {ca_cert.subject.rfc4514_string()}")

    # 2. 生成服务器密钥对
    print("\n[2/4] 生成服务器RSA 2048密钥对...")
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=get_rsa_key_size(),
        backend=default_backend()
    )

    # 保存服务器私钥（不加密，供Nginx使用）
    NGINX_CERT_DIR.mkdir(parents=True, exist_ok=True)
    server_key_path = NGINX_CERT_DIR / "pki_server_key.pem"
    pem_data = server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Nginx需要未加密的私钥
    )
    with open(server_key_path, "wb") as f:
        f.write(pem_data)
    print(f"  [OK] 服务器私钥已保存: {server_key_path}")

    # 3. 签发服务器证书（含SAN: localhost, 127.0.0.1）
    print("\n[3/4] 签发TLS服务器证书...")
    now = datetime.now(timezone.utc)

    # SAN列表：支持localhost和各种本地地址
    san_names = [
        DNSName("localhost"),
        DNSName("127.0.0.1"),
        DNSName("*.localhost"),
        IPAddress(ip_address("127.0.0.1")),
        IPAddress(ip_address("::1")),
    ]

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI演示系统"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 2))  # 2年有效期
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]), critical=False)
        .sign(ca_key, get_hash_algorithm(), default_backend())
    )

    server_cert_path = NGINX_CERT_DIR / "pki_server_cert.pem"
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] 服务器证书已保存: {server_cert_path}")

    # 4. 复制根CA证书供客户端信任
    print("\n[4/4] 复制根CA证书供客户端信任...")
    root_ca_src = PKI_DEMO / "certs" / "root_ca_cert.pem"
    root_ca_dst = NGINX_CERT_DIR / "root_ca_cert.pem"
    if root_ca_src.exists():
        import shutil
        shutil.copy2(root_ca_src, root_ca_dst)
        print(f"  [OK] 根CA证书已复制: {root_ca_dst}")

    print(f"""
{'=' * 60}
  ✅ TLS服务器证书签发完成！
{'=' * 60}
  证书文件:
    服务器证书: {server_cert_path}
    服务器私钥: {server_key_path}
    根CA证书:   {root_ca_dst}

  证书信息:
    CN: localhost
    SAN: localhost, 127.0.0.1, *.localhost, ::1
    有效期: 2年
    颁发者: {ca_cert.subject.rfc4514_string()}

  浏览器信任根CA后即可访问: https://localhost/
{'=' * 60}
""")

if __name__ == "__main__":
    main()
