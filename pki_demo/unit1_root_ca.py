"""
==============================================================
  单元1：根CA自签证书签发
  功能：生成根CA的密钥对，并签发根CA自签名证书
==============================================================
"""

import os
import sys
from datetime import datetime, timedelta, timezone

# 添加项目根目录到系统路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from security_crypto import get_hash_algorithm


# ============================================================
# 配置区（你可以在这里修改参数）
# ============================================================
CA_NAME = "演示根CA"          # 根CA的名称
CA_COUNTRY = "CN"             # 国家代码
CA_ORG = "PKI演示系统"        # 组织名称
CA_VALIDITY_YEARS = 10        # 证书有效期（年）
KEY_SIZE = 2048               # RSA密钥长度（位，2048=安全标准）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # 项目根目录


# ============================================================
# 核心功能1：生成RSA密钥对
# ============================================================
def generate_key_pair(key_size=KEY_SIZE):
    """
    生成RSA密钥对（即一对配对的密码）


    参数：
        key_size: 密钥长度，2048位是当前安全标准

    返回：
        private_key: 私钥对象
    """
    print("\n [步骤1] 正在生成RSA密钥对（2048位）...")
    print("   └─ 就像在造一把高安全性的锁和配套的钥匙")

    private_key = rsa.generate_private_key(
        public_exponent=65537,      # 公开指数，65537是标准值
        key_size=key_size,          # 密钥长度
        backend=default_backend()
    )

    print("   密钥对生成成功！")
    print(f"   ├─ 私钥：已安全保存在内存中")
    print(f"   └─ 公钥：已从私钥中提取")
    return private_key


# ============================================================
# 核心功能2：保存私钥到文件（加密存储）
# ============================================================
def save_private_key(private_key, filepath, password=None):
    if password is None:
        from config import CFG
        pwd = CFG.get_password("CA_KEY_PASSWORD")
        password = pwd or b"pki_demo_password"
    """
    将私钥加密保存到文件
    参数：
        private_key: 私钥对象
        filepath: 保存路径
        password: 加密密码（生产环境要用更复杂的密码）
    """
    # 将私钥序列化为PEM格式（用密码加密）
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    with open(filepath, 'wb') as f:
        f.write(pem_data)

    print(f"    私钥已加密保存到：{os.path.basename(filepath)}")
    print(f"   └─ 使用AES-256加密，密码保护")


# ============================================================
# 核心功能3：生成并保存公钥
# ============================================================
def save_public_key(public_key, filepath):
    """
    保存公钥到文件（公钥可以公开）
    参数：
        public_key: 公钥对象
        filepath: 保存路径
    """
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filepath, 'wb') as f:
        f.write(pem_data)

    print(f"   公钥已保存到：{os.path.basename(filepath)}")


# ============================================================
# 核心功能4：生成根CA自签名证书
# ============================================================
def generate_root_ca_certificate(private_key, subject_name=CA_NAME,
                                  country=CA_COUNTRY, org=CA_ORG,
                                  validity_years=CA_VALIDITY_YEARS):
    """
    生成根CA自签名证书

    证书（X.509格式）包含：
    - 颁发者：谁发的证（这里就是自己）
    - 主体：这个证发给谁（这里也是自己）
    - 公钥：配对的"锁"
    - 有效期：从哪天到哪天有效
    - 签名：用私钥"盖章"，确保证书内容不能被篡改

    参数：
        private_key: 根CA的私钥（用来签名）
        subject_name: 根CA名称
        country: 国家代码
        org: 组织名称
        validity_years: 有效期（年）

    返回：
        certificate: 根CA证书对象
    """
    print(f"\n [步骤2] 正在签发根CA自签名证书...")
    print(f"   └─ 相当于'发证总局'给自己颁发'成立证书'")

    # 构建证书主体信息
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    # 设置证书有效期
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = now + timedelta(days=365 * validity_years)

    print(f"   ├─ 证书名称：{subject_name}")
    print(f"   ├─ 组织：{org}")
    print(f"   ├─ 有效期：{validity_years}年")
    print(f"   ├─ 生效：{valid_from.strftime('%Y-%m-%d %H:%M')}")
    print(f"   └─ 到期：{valid_until.strftime('%Y-%m-%d %H:%M')}")

    # 构建证书（这就是"制作身份证"的过程）
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)                          # 证书发给谁
        .issuer_name(issuer)                            # 谁发的（根CA自签，所以一样）
        .public_key(private_key.public_key())            # 公钥（配套的"锁"）
        .serial_number(x509.random_serial_number())      # 唯一编号（像身份证号）
        .not_valid_before(valid_from)                   # 生效日期
        .not_valid_after(valid_until)                    # 到期日期
        # 添加扩展项（额外信息）
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,  # 标记为CA证书，可以给其他CA发证
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,     # 可以签发证书
                crl_sign=True,          # 可以签名CRL
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # 用私钥签名——相当于在证书上"盖钢印"
        .sign(private_key, get_hash_algorithm(), default_backend())
    )

    print(f"   [OK] 根CA自签证书签发成功！")
    print(f"   ├─ 证书序列号：{cert.serial_number}")
    print(f"   ├─ 签名算法：SHA-256 + RSA")
    print(f"   └─ 这是整个PKI体系的信任基石")

    return cert


# ============================================================
# 核心功能5：保存证书到PEM文件
# ============================================================
def save_certificate(certificate, filepath):
    """
    将证书保存为PEM格式文件

    PEM格式是一种用文本表示的证书文件，
    以 -----BEGIN CERTIFICATE----- 开头，
    以 -----END CERTIFICATE----- 结尾。

    参数：
        certificate: 证书对象
        filepath: 保存路径
    """
    pem_data = certificate.public_bytes(serialization.Encoding.PEM)

    with open(filepath, 'wb') as f:
        f.write(pem_data)

    print(f"    证书已保存到：{os.path.basename(filepath)}")
    print(f"   └─ 格式：PEM (X.509 v3)")


# ============================================================
# 核心功能6：读取并显示证书信息
# ============================================================
def load_and_display_certificate(filepath):
    """
    从文件读取证书并显示其信息

    参数：
        filepath: 证书文件路径
    """
    print(f"\n [验证] 读取证书信息...")

    with open(filepath, 'rb') as f:
        pem_data = f.read()

    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    print(f"   ├─ 证书名称：{cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"   ├─ 颁发者：{cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"   ├─ 序列号：{cert.serial_number}")
    print(f"   ├─ 有效起始：{cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M')}")
    print(f"   ├─ 有效截止：{cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M')}")
    print(f"   ├─ 签名算法：{cert.signature_algorithm_oid._name}")
    print(f"   ├─ 版本：X.509 v{cert.version.value}")

    # 检查是否是CA证书
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = basic_constraints.value.ca
        print(f"   ├─ 是否CA证书：{'是 ' if is_ca else '否 '}")
    except x509.ExtensionNotFound:
        print(f"   ├─ 是否CA证书：未知")

    print(f"   └─ 验证状态：自签名证书（信任锚点）")

    return cert


# ============================================================
# 主函数 - 运行此文件即可生成根CA
# ============================================================
def main():
    """运行单元1：生成根CA证书"""
    print("=" * 60)
    print("  单元1：根CA自签证书签发")
    print("  功能：生成根CA密钥对并签发自签名证书")
    print("=" * 60)

    # 设置文件路径
    ca_key_path = os.path.join(BASE_DIR, "keys", "root_ca_private.pem")
    ca_pub_path = os.path.join(BASE_DIR, "keys", "root_ca_public.pem")
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")

    # 步骤1：生成密钥对
    private_key = generate_key_pair()

    # 步骤2：保存密钥
    save_private_key(private_key, ca_key_path)
    save_public_key(private_key.public_key(), ca_pub_path)

    # 步骤3：生成自签证书
    certificate = generate_root_ca_certificate(private_key)

    # 步骤4：保存证书
    save_certificate(certificate, ca_cert_path)

    # 步骤5：验证证书
    print("\n" + "=" * 60)
    print("  验证根CA证书")
    print("=" * 60)
    load_and_display_certificate(ca_cert_path)

    print("\n" + "=" * 60)
    print("  [OK] 单元1完成！根CA已成功创建。")
    print(f"  [OK] 私钥文件：keys/root_ca_private.pem")
    print(f"  [OK] 公钥文件：keys/root_ca_public.pem")
    print(f"  [OK] 证书文件：certs/root_ca_cert.pem")
    print("=" * 60)


# 当直接运行此文件时执行main()
if __name__ == "__main__":
    main()
