"""导出PKCS#12证书（可在浏览器/系统中导入使用）
用法: PKI_USER_KEY_PASSWORD=your_pwd python export_maomao_p12.py
"""
from pathlib import Path
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

BASE_DIR = Path(__file__).parent.parent.resolve()
PKI = BASE_DIR / "pki_demo"
EXPORT_DIR = BASE_DIR / "export"
EXPORT_DIR.mkdir(exist_ok=True)

# 证书和密钥文件
cert_file = PKI / "certs" / "user_941326814856_20260615195513_cert.pem"
key_file = PKI / "keys" / "user_941326814856_20260615195513_private.pem"
inter_cert = PKI / "certs" / "inter_ca_cert.pem"
root_cert = PKI / "certs" / "root_ca_cert.pem"

# 1. 加载用户证书
with open(cert_file, "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())
cn = user_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
print(f"证书CN: {cn[0].value}")

# 2. 加载用户私钥（从环境变量读取密码）
user_pwd = os.environ.get("PKI_USER_KEY_PASSWORD", "user_pwd").encode()
with open(key_file, "rb") as f:
    user_key = serialization.load_pem_private_key(f.read(), password=user_pwd)
print("私钥: 已加载")

# 3. 加载CA证书链
with open(inter_cert, "rb") as f:
    inter = x509.load_pem_x509_certificate(f.read())
with open(root_cert, "rb") as f:
    root = x509.load_pem_x509_certificate(f.read())
print("CA链: 中间CA + 根CA")

# 4. 导出PKCS#12
p12_pwd = os.environ.get("PKI_P12_EXPORT_PASSWORD", "p12_export_pwd").encode()
p12_data = pkcs12.serialize_key_and_certificates(
    name=b"User Cert",
    key=user_key,
    cert=user_cert,
    cas=[inter, root],
    encryption_algorithm=serialization.BestAvailableEncryption(p12_pwd)
)

p12_path = EXPORT_DIR / "user_cert.p12"
with open(p12_path, "wb") as f:
    f.write(p12_data)
print(f"PKCS#12已导出: {p12_path} ({len(p12_data)} bytes)")

# 5. 也导出单独的PEM（证书+CA链）
chain_path = EXPORT_DIR / "user_fullchain.pem"
with open(chain_path, "wb") as f:
    f.write(user_cert.public_bytes(serialization.Encoding.PEM))
    f.write(b"\n")
    f.write(inter.public_bytes(serialization.Encoding.PEM))
    f.write(b"\n")
    f.write(root.public_bytes(serialization.Encoding.PEM))
print(f"完整链PEM: {chain_path}")

print(f"""
====================================
  导出完成!
====================================
  文件:
    PKCS#12: {p12_path}
    完整链:  {chain_path}

  浏览器导入:
    设置 → 隐私和安全 → 管理证书 → 导入
    选择 PKCS#12 文件，输入导出密码
====================================
""")
