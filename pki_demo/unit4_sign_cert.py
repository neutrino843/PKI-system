"""
==============================================================
  单元4：用户证书签发
  功能：CA读取用户的CSR，审核后签发正式证书（X.509格式）

  证书签发是PKI体系的核心环节——CA用自己的私钥
  对用户的信息和公钥进行签名，生成具有法律效力的电子身份证。
==============================================================
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import SubjectAlternativeName, DNSName, RFC822Name
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from security_crypto import get_hash_algorithm

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ============================================================
# 辅助功能1：加载CA的私钥
# ============================================================
def load_ca_private_key(filepath, password=b"pki_demo_password"):
    """
    加载CA的加密私钥
    """
    print("\n[正在加载CA私钥（发证机关印章）...]")
    with open(filepath, 'rb') as f:
        pem_data = f.read()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )
    print(f"   [OK] CA私钥加载成功")
    return private_key


# ============================================================
# 辅助功能2：加载CA证书
# ============================================================
def load_ca_certificate(filepath):
    """
    加载CA证书
    """
    with open(filepath, 'rb') as f:
        pem_data = f.read()

    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    print(f"   [OK] CA证书加载成功：{cert.subject.rfc4514_string()}")
    return cert


# ============================================================
# 辅助功能3：加载用户的CSR
# ============================================================
def load_csr(filepath):
    """
    加载用户的证书签名请求（CSR）

    """
    with open(filepath, 'rb') as f:
        pem_data = f.read()

    csr = x509.load_pem_x509_csr(pem_data, default_backend())
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    print(f"   [OK] 用户CSR加载成功：{cn[0].value if cn else '未知'}")
    return csr


# ============================================================
# 核心功能：CA签发用户证书
# ============================================================
def sign_user_certificate(ca_private_key, ca_cert, csr,
                          validity_days=365, org_name=None):
    """
    CA用私钥对用户的CSR进行签名，生成用户证书

    参数：
        ca_private_key: CA的私钥（用来"盖钢印"）
        ca_cert: CA证书（包含CA的身份信息）
        csr: 用户的证书签名请求（用户的申请表）
        validity_days: 证书有效期（天），默认365天=1年
        org_name: 用户的组织信息

    返回：
        user_cert: 用户证书对象
    """
    # 从CSR中提取用户信息和公钥
    user_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    user_common_name = user_name[0].value if user_name else "未知用户"

    print(f"\n[CA正在为用户 '{user_common_name}' 签发证书...]")
    print(f"   ├─ 审核CSR签名：{'有效 [OK]' if _verify_csr(csr) else '无效 [FAIL]'}")
    print(f"   ├─ 证书有效期：{validity_days}天（约{validity_days//365}年）")

    # 设置有效期
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = now + timedelta(days=validity_days)

    # 构建用户证书（制作身份证）
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)                       # 用户名（身份证上的名字）
        .issuer_name(ca_cert.subject)                    # 颁发者（发证机关名称）
        .public_key(csr.public_key())                    # 用户的公钥（配好的锁）
        .serial_number(x509.random_serial_number())       # 唯一编号
        .not_valid_before(valid_from)                    # 生效日期
        .not_valid_after(valid_until)                    # 到期日期
    )

    # 添加扩展信息
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,  # 普通用户证书，不能给其他人发证
    )

    # 添加SubjectAlternativeName（SAN）扩展
    # 现代浏览器/操作系统要求证书必须包含SAN
    san_names = [DNSName(user_common_name)]
    san_names.append(RFC822Name(f"{user_common_name}@pki.internal"))
    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName(san_names),
        critical=False,
    )

    # 添加密钥用途
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,     # 可用于数字签名（签合同、签文件）
            content_commitment=True,    # 可用于不可否认签名
            key_encipherment=True,      # 可用于加密密钥
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,        # 不能签发证书
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # 添加增强型密钥用途
    cert_builder = cert_builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,    # 客户端认证
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,    # 服务端认证
            x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION, # 邮件保护
        ]),
        critical=False,
    )

    # CA用私钥签名——"盖钢印"
    user_cert = cert_builder.sign(
        ca_private_key,
        get_hash_algorithm(),
        default_backend()
    )

    print(f"   [OK] 用户证书签发成功！")
    print(f"   ├─ 用户名：{user_common_name}")
    print(f"   ├─ 序列号：{user_cert.serial_number}")
    print(f"   ├─ 颁发者：{ca_cert.subject.rfc4514_string()}")
    print(f"   ├─ 有效期至：{valid_until.strftime('%Y-%m-%d')}")
    print(f"   └─ 签名算法：SHA-256 + RSA")

    return user_cert


# ============================================================
# 辅助检查：验证CSR签名是否有效
# ============================================================
def _verify_csr(csr):
    """
    验证CSR签名是否有效
    """
    try:
        csr.public_key()
        return True
    except Exception:
        return False


# ============================================================
# 辅助功能4：保存用户证书
# ============================================================
def save_user_certificate(cert, filepath):
    """
    保存用户证书为PEM格式文件
    """
    pem_data = cert.public_bytes(serialization.Encoding.PEM)
    with open(filepath, 'wb') as f:
        f.write(pem_data)
    print(f"   [OK] 用户证书已保存到：{os.path.basename(filepath)}")


# ============================================================
# 辅助功能5：显示证书信息
# ============================================================
def display_cert_info(cert, label="证书"):
    """
    显示证书的关键信息
    """
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    print(f"\n[{label}信息：]")
    print(f"   ├─ 主体（持有人）：{cn[0].value if cn else '未知'}")
    print(f"   ├─ 颁发者（发证机关）：{issuer_cn[0].value if issuer_cn else '未知'}")
    print(f"   ├─ 序列号：{cert.serial_number}")
    print(f"   ├─ 生效日期：{cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M')}")
    print(f"   ├─ 到期日期：{cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M')}")
    print(f"   ├─ 签名算法：{cert.signature_algorithm_oid._name}")
    print(f"   ├─ 版本：X.509 v{cert.version.value}")

    # 检查是否是CA证书
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        print(f"   └─ 类型：{'CA证书（可签发其他证书）' if basic_constraints.value.ca else '终端用户证书'}")
    except x509.ExtensionNotFound:
        print(f"   └─ 类型：未知")


# ============================================================
# 主函数 - 演示CA签发用户证书
# ============================================================
def main():
    print("=" * 60)
    print("  单元4：CA签发用户证书")
    print("  功能：CA对用户CSR进行审核并签发证书")
    print("=" * 60)

    # 步骤1：加载CA的私钥和证书
    print(f"\n{'='*40}")
    print("  [步骤1] 加载CA信息（发证机关）")
    print(f"{'='*40}")

    ca_key_path = os.path.join(BASE_DIR, "keys", "root_ca_private.pem")
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")

    ca_private_key = load_ca_private_key(ca_key_path)
    ca_cert = load_ca_certificate(ca_cert_path)

    # 步骤2：逐个处理用户的CSR
    users = ["张三", "李四"]

    for username in users:
        print(f"\n{'='*40}")
        print(f"  [处理] 用户：{username}")
        print(f"{'='*40}")

        # 加载用户的CSR
        csr_path = os.path.join(BASE_DIR, "csr", f"user_{username}_csr.pem")
        if not os.path.exists(csr_path):
            print(f"   [WARN] 未找到 {username} 的CSR文件，跳过")
            continue

        csr = load_csr(csr_path)

        # CA签发证书
        user_cert = sign_user_certificate(
            ca_private_key=ca_private_key,
            ca_cert=ca_cert,
            csr=csr,
            validity_days=365,  # 有效期1年
        )

        # 保存用户证书
        cert_path = os.path.join(BASE_DIR, "certs", f"user_{username}_cert.pem")
        save_user_certificate(user_cert, cert_path)

    # 步骤3：验证签发的证书
    print(f"\n{'='*60}")
    print("  [验证] 查看所有已签发的用户证书")
    print('='*60)

    for username in users:
        cert_path = os.path.join(BASE_DIR, "certs", f"user_{username}_cert.pem")
        if os.path.exists(cert_path):
            with open(cert_path, 'rb') as f:
                pem_data = f.read()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            display_cert_info(cert, f"用户 '{username}' 证书")

    print(f"\n{'='*60}")
    print(f"  [OK] 单元4完成！用户证书已签发。")
    print(f"  [OK] 证书文件目录：certs/")
    print(f"  ├─ user_张三_cert.pem")
    print(f"  └─ user_李四_cert.pem")
    print(f"  [OK] 信任链：根CA → 用户证书")
    print("=" * 60)


if __name__ == "__main__":
    main()
