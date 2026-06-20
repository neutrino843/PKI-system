"""
================================================================
  生成内部测试访问证书
  功能：由项目中间CA签发一张内部测试专用的 access_cert.pem
  用途：持有此证书的人才能启动 PKI 管理系统
================================================================

使用方法：
  python scripts/gen_internal_access_cert.py

输出：
  pki_demo/certs/access_cert.pem           - 访问证书（分发给内部测试人员）
  pki_demo/keys/access_private.pem         - 私钥（管理员保留，不对外分发）

环境变量：
  ACCESS_CERT_DAYS=365                     - 证书有效期天数（默认365）
  ACCESS_CERT_CN=Internal-Access-Cert      - 证书通用名称
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 将项目根目录加入 sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# ============================================================
# 获取中间CA私钥密码（与 api_server.py 保持一致）
# ============================================================
CA_KEY_PASSWORD = os.environ.get(
    "PKI_CA_KEY_PASSWORD",
    "DEV_ONLY_change_me",  # 默认开发密码
).encode("utf-8")

# ============================================================
# 路径
# ============================================================
CERTS_DIR = BASE_DIR / "pki_demo" / "certs"
KEYS_DIR = BASE_DIR / "pki_demo" / "keys"

INTER_CA_CERT_PATH = CERTS_DIR / "inter_ca_cert.pem"
INTER_CA_KEY_PATH = KEYS_DIR / "inter_ca_private.pem"

OUTPUT_CERT_PATH = CERTS_DIR / "access_cert.pem"
OUTPUT_KEY_PATH = KEYS_DIR / "access_private.pem"


def main():
    print("=" * 60)
    print("  内部测试访问证书生成工具")
    print("=" * 60)
    print()

    # 1. 加载中间CA证书和私钥
    print(f"[1/4] 加载中间CA证书: {INTER_CA_CERT_PATH}")
    if not INTER_CA_CERT_PATH.exists():
        print(f"  ❌ 错误: 中间CA证书不存在: {INTER_CA_CERT_PATH}")
        print(f"  请先运行 pki_demo/main.py 初始化 CA 体系")
        sys.exit(1)

    with open(INTER_CA_CERT_PATH, "rb") as f:
        inter_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    print(f"[2/4] 加载中间CA私钥: {INTER_CA_KEY_PATH}")
    if not INTER_CA_KEY_PATH.exists():
        print(f"  ❌ 错误: 中间CA私钥不存在: {INTER_CA_KEY_PATH}")
        sys.exit(1)

    with open(INTER_CA_KEY_PATH, "rb") as f:
        inter_ca_key = serialization.load_pem_private_key(
            f.read(),
            password=CA_KEY_PASSWORD,
            backend=default_backend(),
        )

    # 2. 生成访问证书密钥对
    print("[3/4] 生成访问证书密钥对 (RSA 2048)...")
    access_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # 3. 构建并签发访问证书
    days = int(os.environ.get("ACCESS_CERT_DAYS", "365"))
    cn = os.environ.get("ACCESS_CERT_CN", "Internal-Access-Cert")
    now = datetime.now(timezone.utc)

    print(f"[4/4] 签发访问证书 (CN={cn}, 有效期={days}天)...")
    access_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Internal Testing"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
        )
        .issuer_name(inter_ca_cert.subject)  # 由中间CA签发
        .public_key(access_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(access_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_ca_key.public_key()),
            critical=False,
        )
        .sign(
            private_key=inter_ca_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    )

    # 4. 输出证书和私钥
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    # 写证书
    with open(OUTPUT_CERT_PATH, "wb") as f:
        f.write(access_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  ✅ 访问证书已生成: {OUTPUT_CERT_PATH}")

    # 写私钥
    with open(OUTPUT_KEY_PATH, "wb") as f:
        f.write(
            access_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"  ✅ 私钥已生成: {OUTPUT_KEY_PATH}")

    # 5. 打印摘要
    print()
    print("=" * 60)
    print("  证书摘要")
    print("=" * 60)
    print(f"  序列号:     {access_cert.serial_number}")
    print(f"  通用名称:   {cn}")
    print(f"  签发者:     {inter_ca_cert.subject}")
    print(f"  有效期:     {access_cert.not_valid_before_utc}")
    print(f"  至:         {access_cert.not_valid_after_utc}")
    print(f"  签名算法:   SHA256")
    print(f"  密钥长度:   2048-bit RSA")
    print()
    print(f"  ⚠  分发说明:")
    print(f"      ✅ 分发: {OUTPUT_CERT_PATH.name} 给内部测试人员")
    print(f"      🔒 保密: {OUTPUT_KEY_PATH.name} 由管理员保留")
    print("=" * 60)


if __name__ == "__main__":
    main()
