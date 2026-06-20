"""
================================================================
  TSA 签名证书签发脚本
  功能：为时间戳服务签发符合 X.509 标准的专用 TSA 签名证书
  证书类型：由中间CA签发，ExtendedKeyUsage=TIMESTAMPING
  标准：RFC 3161, RFC 5280, X.509 v3
================================================================
"""

import os
import sys
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

# 确保能导入pki_demo模块
BASE_DIR = Path(__file__).parent.parent.resolve()
PKI_DEMO_DIR = BASE_DIR / "pki_demo"
sys.path.insert(0, str(PKI_DEMO_DIR))

from config import CFG
from database import transaction
from audit import audit_logger, EVENT_TSA_CERT_ISSUE

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import SubjectAlternativeName, DNSName

# 导入算法工厂
from security_crypto import generate_keypair, get_hash_algorithm, get_signature_algorithm


def issue_tsa_certificate(common_name="PKI TSA Server",
                          validity_days=None,
                          key_size=None):
    """
    签发 TSA 签名证书

    Args:
        common_name: TSA证书 CN 字段
        validity_days: 证书有效期（天），默认从config读取
        key_size: RSA密钥长度，默认从config读取

    Returns:
        (cert_path, key_path) 或 抛出异常
    """
    if validity_days is None:
        tsa_config = CFG._config.get("tsa", {})
        validity_days = tsa_config.get("tsa_cert_validity_days", 1825)
    if key_size is None:
        algo_config = CFG.get_algorithm_config()
        key_size = algo_config.get("rsa_key_size", 2048)
    hash_algo = CFG.get_algorithm_config().get("hash_algorithm", "SHA256")

    # 确定 CA 证书路径
    ca_cert_path = PKI_DEMO_DIR / "certs" / "inter_ca_cert.pem"
    ca_key_path = PKI_DEMO_DIR / "keys" / "inter_ca_private.pem"
    if not ca_cert_path.exists():
        ca_cert_path = PKI_DEMO_DIR / "certs" / "root_ca_cert.pem"
        ca_key_path = PKI_DEMO_DIR / "keys" / "root_ca_private.pem"
        print("[警告] 未找到中间CA证书，使用根CA签发TSA证书")

    if not ca_cert_path.exists():
        raise FileNotFoundError("CA证书不存在，请先初始化CA: scripts/setup_pki_full.py")

    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        raise RuntimeError("请设置 PKI_CA_KEY_PASSWORD 环境变量")

    print(f"[1/5] 加载CA证书: {ca_cert_path.name}")
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=ca_pwd, backend=default_backend()
        )

    algo = get_signature_algorithm()
    print(f"[2/5] 生成 TSA 密钥对 ({algo})")
    tsa_key = generate_keypair()

    print(f"[3/5] 保存 TSA 私钥")
    key_path = PKI_DEMO_DIR / "keys" / "tsa_private.pem"
    tsa_key_pem = tsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(ca_pwd),
    )
    with open(key_path, "wb") as f:
        f.write(tsa_key_pem)
    print(f"    私钥已保存: {key_path}")

    print(f"[4/5] 构建 TSA 证书 (有效期: {validity_days}天)")
    now = datetime.now(timezone.utc)
    hash_instance = get_hash_algorithm(hash_algo)

    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Time-Stamp Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                DNSName("tsa.pki.internal"),
                DNSName("localhost"),
            ]),
            critical=False,
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
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.TIME_STAMPING,  # 1.3.6.1.5.5.7.3.8
            ]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
            ),
            critical=False,
        )
        # 添加证书策略扩展（TSA 策略 OID）
        .add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    policy_identifier=x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.48.1.1"),
                    policy_qualifiers=None,
                ),
            ]),
            critical=False,
        )
        .sign(ca_key, hash_instance, default_backend())
    )

    print(f"[5/5] 保存 TSA 证书")
    cert_path = PKI_DEMO_DIR / "certs" / "tsa_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(tsa_cert.public_bytes(serialization.Encoding.PEM))
    print(f"    证书已保存: {cert_path}")

    # 验证证书
    print("\n验证 TSA 证书:")
    print(f"  主题: {tsa_cert.subject}")
    print(f"  签发者: {tsa_cert.issuer}")
    print(f"  序列号: {tsa_cert.serial_number}")
    print(f"  有效期: {tsa_cert.not_valid_before_utc} ~ {tsa_cert.not_valid_after_utc}")

    # 检查 ExtendedKeyUsage
    try:
        eku = tsa_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if ExtendedKeyUsageOID.TIME_STAMPING in eku.value:
            print(f"  扩展密钥用法: [OK] 包含时间戳用途 (1.3.6.1.5.5.7.3.8)")
    except Exception:
        print("  [警告] 未找到 ExtendedKeyUsage 扩展")

    audit_logger.log(
        EVENT_TSA_CERT_ISSUE, "system", "CREATE",
        "tsa_cert.pem", "SUCCESS",
        f"签发TSA签名证书: {common_name}, 序列号: {tsa_cert.serial_number}",
        "ca_admin"
    )

    print(f"\n✓ TSA 证书签发完成!")
    print(f"  证书: {cert_path}")
    print(f"  私钥: {key_path}")

    return cert_path, key_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="签发 TSA 签名证书")
    parser.add_argument("--cn", default="PKI TSA Server",
                       help="TSA证书CN字段（默认: PKI TSA Server）")
    parser.add_argument("--days", type=int, default=None,
                       help="证书有效期（天，默认: 1825天/5年）")
    parser.add_argument("--key-size", type=int, default=None,
                       help="RSA密钥长度（默认: 2048）")
    args = parser.parse_args()

    print("=" * 60)
    print("  TSA 签名证书签发工具")
    print("=" * 60)
    print()

    try:
        issue_tsa_certificate(
            common_name=args.cn,
            validity_days=args.days,
            key_size=args.key_size,
        )
    except Exception as e:
        print(f"\n[错误] {e}")
        sys.exit(1)
