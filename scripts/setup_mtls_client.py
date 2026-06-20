"""
================================================================
  mTLS 客户端证书一键签发 + Nginx 配置
  功能：
  1. 生成客户端 RSA 密钥对
  2. 用中间CA签发客户端证书（ExtendedKeyUsage=CLIENT_AUTH）
  3. 导出 PKCS#12（供浏览器导入）
  4. 配置 Nginx 要求客户端证书
================================================================
"""

import os, sys, subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
PKI_DEMO_DIR = BASE_DIR / "pki_demo"
EXPORT_DIR = BASE_DIR / "export"
EXPORT_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(PKI_DEMO_DIR))
from config import CFG
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12

# 导入算法工厂
sys.path.insert(0, str(PKI_DEMO_DIR))
from pki_demo.security_crypto import generate_keypair, get_signature_hash, get_signature_algorithm

# ============================================================
# 配置
# ============================================================
CN_NAME = "PKI Admin"           # 证书通用名称（可通过命令行参数修改）
P12_PASSWORD = os.environ.get("PKI_P12_EXPORT_PASSWORD", "CHANGE_ME_IN_PRODUCTION")  # .p12导出密码
NGINX_DIR = os.environ.get("PKI_NGINX_DIR", r"C:\path\to\nginx")        # Nginx目录（请修改为实际路径）

print("=" * 60)
print("  mTLS 客户端证书签发工具")
print("=" * 60)

# ============================================================
# 1. 加载 CA
# ============================================================
print("\n[1/5] 加载 CA 证书...")
ca_cert_path = PKI_DEMO_DIR / "certs" / "inter_ca_cert.pem"
ca_key_path = PKI_DEMO_DIR / "keys" / "inter_ca_private.pem"
if not ca_cert_path.exists():
    ca_cert_path = PKI_DEMO_DIR / "certs" / "root_ca_cert.pem"
    ca_key_path = PKI_DEMO_DIR / "keys" / "root_ca_private.pem"
    print("  [使用根CA]")

ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
if not ca_pwd:
    ca_pwd = os.environ.get("PKI_CA_KEY_PASSWORD", "CHANGE_ME_IN_PRODUCTION").encode()

with open(ca_cert_path, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
with open(ca_key_path, "rb") as f:
    ca_key = serialization.load_pem_private_key(
        f.read(), password=ca_pwd, backend=default_backend()
    )
print(f"  CA: {ca_cert.subject}")

# ============================================================
# 2. 生成客户端密钥
# ============================================================
print("\n[2/5] 生成客户端密钥对...")
algo = get_signature_algorithm()
print(f"  算法: {algo}")
client_key = generate_keypair()

# 保存私钥（加密）
key_path = PKI_DEMO_DIR / "keys" / "client_admin_private.pem"
with open(key_path, "wb") as f:
    f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(ca_pwd),
    ))
print(f"  私钥已保存: {key_path}")

# ============================================================
# 3. 签发客户端证书
# ============================================================
print("\n[3/5] 签发客户端证书...")
from datetime import datetime, timezone, timedelta
now = datetime.now(timezone.utc)

client_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI System"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, CN_NAME),
    ]))
    .issuer_name(ca_cert.subject)
    .public_key(client_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=True, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    ), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
        ),
        critical=False,
    )
    .sign(ca_key, get_signature_hash(), default_backend())
)

cert_path = PKI_DEMO_DIR / "certs" / "client_admin_cert.pem"
with open(cert_path, "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))
print(f"  证书已保存: {cert_path}")
print(f"  主题: CN={CN_NAME}")
print(f"  有效期: 365天")
print(f"  用途: TLS Web Client Authentication")

# ============================================================
# 4. 导出 PKCS#12
# ============================================================
print("\n[4/5] 导出 PKCS#12（供浏览器导入）...")

# 加载 CA 链
ca_chain = []
for fn in ["inter_ca_cert.pem", "root_ca_cert.pem"]:
    p = PKI_DEMO_DIR / "certs" / fn
    if p.exists():
        with open(p, "rb") as f:
            ca_chain.append(x509.load_pem_x509_certificate(f.read(), default_backend()))

p12_data = pkcs12.serialize_key_and_certificates(
    name=b"PKI Admin Client",
    key=client_key,
    cert=client_cert,
    cas=ca_chain,
    encryption_algorithm=serialization.BestAvailableEncryption(P12_PASSWORD.encode()),
)

p12_path = EXPORT_DIR / "client_admin.p12"
with open(p12_path, "wb") as f:
    f.write(p12_data)
print(f"  PKCS#12: {p12_path} ({len(p12_data)/1024:.1f}KB)")
print(f"  导入密码: {P12_PASSWORD}")

# ============================================================
# 5. 配置 Nginx 开启 mTLS
# ============================================================
print("\n[5/5] 配置 Nginx...")

nginx_conf = Path(NGINX_DIR) / "conf" / "nginx.conf"
if nginx_conf.exists():
    content = nginx_conf.read_text(encoding="utf-8")

    # 确保 ssl_client_certificate 指向根CA
    root_ca_path = str(BASE_DIR / "pki_demo" / "certs" / "root_ca_cert.pem")

    # 替换 ssl_verify_client optional -> on
    if "ssl_verify_client      optional" in content:
        content = content.replace(
            "ssl_verify_client      optional",
            "ssl_verify_client      on"
        )
        print("  Nginx: ssl_verify_client → on (要求客户端证书)")

        # 同时也更新 cert-login 位置的检查（不再需要，因为全局已要求）
        content = content.replace(
            'if ($ssl_client_verify != "SUCCESS") {',
            '# [已启用全局mTLS] if ($ssl_client_verify != "SUCCESS") {'
        )

        nginx_conf.write_text(content, encoding="utf-8")
        print("  Nginx: 配置文件已更新")
    else:
        print("  Nginx: ssl_verify_client 已经是 on，无需修改")
else:
    print("  Nginx: 未找到配置文件，请手动修改")
    print(f"    将 ssl_verify_client 设为 on")

# 重载 Nginx
print("\n  重载 Nginx...")
try:
    result = subprocess.run(
        ["nginx", "-s", "reload"],
        cwd=NGINX_DIR,
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        print("  Nginx: 重载成功")
    else:
        print(f"  Nginx: 重载可能失败 ({result.stderr.strip()})")
        print(f"  可以手动执行: cd {NGINX_DIR} && nginx -s reload")
except Exception as e:
    print(f"  Nginx: 重载异常: {e}")
    print(f"  请手动执行: cd {NGINX_DIR} && nginx -s reload")

# ============================================================
# 完成
# ============================================================
print()
print("=" * 60)
print("  mTLS 配置完成！")
print("=" * 60)
print(f"""
现在访问 https://localhost/ 需要出示客户端证书。

浏览器导入步骤：
  1. 找到文件: {p12_path}
  2. 双击打开
  3. 导入到「个人」证书存储
  4. 输入P12导出密码
  5. 完成导入

  然后访问 https://localhost/
  浏览器会弹窗让您选择证书，选中「PKI Admin Client」即可。

如果浏览器未弹窗要求选择证书，请重启浏览器后重试。
""")
