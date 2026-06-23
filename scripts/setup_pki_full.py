"""
重新初始化PKI系统CA + 为localhost签发TLS服务器证书
完整流程：根CA → 中间CA → localhost服务器证书 → 配置 Nginx/Flask HTTPS
"""
import sys
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(Path(__file__).parent.parent / "pki_demo"))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address

# 导入算法工厂
from pki_demo.security_crypto import generate_keypair, get_signature_hash, get_signature_algorithm

BASE_DIR = Path(__file__).parent.parent
PKI_DEMO = BASE_DIR / "pki_demo"
NGINX_CERT_DIR = BASE_DIR / "nginx" / "certs"

# 从环境变量读取CA密码，避免硬编码
CA_PWD = os.environ.get("PKI_CA_KEY_PASSWORD", "CHANGE_ME_IN_PRODUCTION").encode()

def backup_old():
    """备份旧CA文件"""
    for sub in ["certs", "keys"]:
        src = PKI_DEMO / sub
        if src.exists():
            for f in src.glob("*"):
                if f.name not in ("root_ca_cert.pem", "inter_ca_cert.pem",
                                   "root_ca_private.pem", "inter_ca_private.pem"):
                    continue
                backup = f.with_suffix(f.suffix + ".bak")
                if backup.exists():
                    backup.unlink()
                f.rename(backup)
                print(f"  [备份] {f.name} -> {backup.name}")

def create_root_ca():
    """创建根CA"""
    print("\n[1/4] 创建根CA（发证总局）...")
    algo = os.environ.get("PKI_SIGNATURE_ALGORITHM", "RSA")
    key = generate_keypair()
    print(f"  算法: {algo}")

    # 保存私钥
    key_path = PKI_DEMO / "keys" / "root_ca_private.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(CA_PWD)
        ))
    print(f"  [OK] 根CA私钥: {key_path}")

    # 生成自签证书
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI演示系统"),
        x509.NameAttribute(NameOID.COMMON_NAME, "演示根CA"),
    ])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 15))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True,
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
    )
    cert_pem = sign_certificate_with_hash(cert_builder, key, get_signature_hash(), default_backend())
    cert_serial = cert_builder._serial_number

    cert_path = PKI_DEMO / "certs" / "root_ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    print(f"  [OK] 根CA证书: {cert_path} (序列号: {cert_serial})")
    return key, cert_pem

def create_intermediate_ca(root_key, root_cert):
    """创建中间CA"""
    print("\n[2/4] 创建中间CA（二级发证机构）...")
    key = generate_keypair()

    # 保存私钥
    key_path = PKI_DEMO / "keys" / "inter_ca_private.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(CA_PWD)
        ))
    print(f"  [OK] 中间CA私钥: {key_path}")

    # 由根CA签发中间CA证书
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI演示系统"),
            x509.NameAttribute(NameOID.COMMON_NAME, "演示中间CA"),
        ]))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True,
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(root_key, get_signature_hash(), default_backend())
    )

    cert_path = PKI_DEMO / "certs" / "inter_ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] 中间CA证书: {cert_path}")
    return key, cert

def issue_localhost_cert(ca_key, ca_cert, ca_type="中间CA"):
    """为localhost签发TLS服务器证书"""
    print(f"\n[3/4] 使用{ca_type}为localhost签发TLS服务器证书...")
    key = generate_keypair()

    # 保存服务器私钥（不加密，供Nginx直接使用）
    NGINX_CERT_DIR.mkdir(parents=True, exist_ok=True)
    key_path = NGINX_CERT_DIR / "pki_server_key.pem"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    now = datetime.now(timezone.utc)
    san_names = [
        DNSName("localhost"),
        DNSName("127.0.0.1"),
        IPAddress(ip_address("127.0.0.1")),
        IPAddress(ip_address("::1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI演示系统"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * 2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, get_signature_hash(), default_backend())
    )

    cert_path = NGINX_CERT_DIR / "pki_server_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] 服务器证书: {cert_path}")
    print(f"  [OK] 服务器私钥: {key_path}")
    return key_path, cert_path

def copy_to_nginx():
    """复制证书到Nginx目录（避免路径空格问题）"""
    print("\n[4/4] 复制证书到Nginx目录...")
    nginx_dir = Path(os.environ.get("PKI_NGINX_HTML_DIR", "C:/path/to/nginx/html"))
    certs = {
        "pki_server_cert.pem": NGINX_CERT_DIR / "pki_server_cert.pem",
        "pki_server_key.pem": NGINX_CERT_DIR / "pki_server_key.pem",
        "root_ca_cert.pem": PKI_DEMO / "certs" / "root_ca_cert.pem",
    }
    for name, src in certs.items():
        dst = nginx_dir / name
        shutil.copy2(src, dst)
        print(f"  [OK] {name} -> {dst}")

def main():
    print("=" * 60)
    print("  PKI系统完整初始化 + localhost证书签发")
    print("=" * 60)
    print(f"  CA密码: {CA_PWD.decode()}")
    print()

    # 备份旧的CA文件
    backup_old()

    # 创建根CA
    root_key, root_cert = create_root_ca()

    # 创建中间CA
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)

    # 使用中间CA为localhost签发TLS证书
    issue_localhost_cert(inter_key, inter_cert, "中间CA")

    # 复制到Nginx
    copy_to_nginx()

    print(f"""
{'=' * 60}
  全部完成!
{'=' * 60}
  信任链: 根CA -> 中间CA -> localhost服务器证书
  生成的文件:
    根CA私钥:   pki_demo/keys/root_ca_private.pem
    根CA证书:   pki_demo/certs/root_ca_cert.pem
    中间CA私钥: pki_demo/keys/inter_ca_private.pem
    中间CA证书: pki_demo/certs/inter_ca_cert.pem
    Nginx证书:  nginx/certs/pki_server_cert.pem
    Nginx私钥:  nginx/certs/pki_server_key.pem

  使用步骤:
    1. 导入根CA到浏览器受信任存储:
       双击 pki_demo/certs/root_ca_cert.pem
       -> 安装证书 -> 受信任的根证书颁发机构
    2. 重启 PKI 服务和 Nginx
    3. 访问 https://localhost/ (浏览器不再警告!)
{'=' * 60}
""")

if __name__ == "__main__":
    main()
