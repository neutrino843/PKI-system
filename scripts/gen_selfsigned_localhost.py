"""
生成自签名localhost TLS证书（自签证书）
用于Nginx HTTPS反向代理，不依赖PKI系统的CA
"""
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address

BASE_DIR = Path(__file__).parent.parent
NGINX_CERT_DIR = BASE_DIR / "nginx" / "certs"

def main():
    print("=" * 60)
    print("  生成自签名localhost TLS证书")
    print("=" * 60)

    NGINX_CERT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 生成密钥对
    print("\n[1/3] 生成RSA 2048密钥对...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Local Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Local Development"),
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
        .sign(key, hashes.SHA256(), default_backend())
    )

    # 3. 保存文件
    print("[3/3] 保存证书文件...")

    # 私钥（Nginx需要未加密的PEM格式）
    key_path = NGINX_CERT_DIR / "pki_server_key.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  [OK] 私钥: {key_path}")

    # 证书
    cert_path = NGINX_CERT_DIR / "pki_server_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] 证书: {cert_path}")

    print(f"""
{'=' * 60}
  自签名证书生成完成！
{'=' * 60}
  证书信息:
    CN: localhost
    SAN: localhost, 127.0.0.1, *.localhost, ::1
    有效期: 5年
    类型: 自签名 (Self-Signed)

  使用方式:
    1. 将根CA证书 [root_ca_cert.pem] 安装到浏览器的"受信任的根证书颁发机构"
    2. 访问 https://localhost/
    （首次访问会提示安全警告，因为这是自签证书）

  注意: 浏览器首次访问会提示"您的连接不是私密连接"，
        这是因为证书是自签名的，未被公开CA信任。
        点击"高级" → "继续前往localhost" 即可。
{'=' * 60}
""")

if __name__ == "__main__":
    main()
