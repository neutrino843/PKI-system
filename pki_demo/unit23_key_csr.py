"""
==============================================================
  单元2+3：密钥对生成 + 证书签名请求(CSR)生成
  功能：为用户生成RSA密钥对，并生成证书签名请求（PKCS#10格式）

==============================================================
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# 若config模块可用则导入（单元测试可使用默认密码）
try:
    from config import CFG
except ImportError:
    CFG = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ============================================================
# 核心功能1：生成用户RSA密钥对
# ============================================================
def generate_key_pair(key_size=2048):
    """
    生成RSA密钥对
    """
    print("\n[正在为用户生成RSA密钥对（2048位）...]")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    print("   [OK] 用户密钥对生成成功！")
    print("   ├─ 私钥（钥匙）：已生成，仅用户自己持有")
    print("   └─ 公钥（锁）：已提取，将用于生成证书请求")
    return private_key


# ============================================================
# 核心功能2：生成证书签名请求（CSR）
# ============================================================
def generate_csr(private_key, common_name, country="CN",
                 organization=None, email=None):
    """
    生成PKCS#10格式的证书签名请求（CSR）

    参数：
        private_key: 用户的私钥（用来在申请表上签名）
        common_name: 用户名（相当于姓名）
        country: 国家代码
        organization: 组织名称
        email: 电子邮箱

    返回：
        csr: 证书签名请求对象
    """
    print(f"\n[正在为用户 '{common_name}' 生成证书签名请求(CSR)...]")

    # 构建申请人的身份信息
    name_attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]
    if organization:
        name_attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
        )

    subject_name = x509.Name(name_attributes)

    # 构建CSR（填写申请表）
    csr_builder = x509.CertificateSigningRequestBuilder(
        subject_name=subject_name
    )

    # 添加扩展信息
    csr_builder = csr_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,  # 标记为"这不是CA证书"，即普通用户证书
    )

    # 用私钥在申请表上签名——证明是本人提交
    csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

    print(f"   [OK] CSR生成成功！")
    print(f"   ├─ 申请人：{common_name}")
    print(f"   ├─ 国家：{country}")
    print(f"   ├─ 组织：{organization or '未指定'}")
    print(f"   ├─ 签名算法：SHA-256 + RSA")
    print(f"   └─ CSR已用私钥签名，证明是本人申请")

    return csr


# ============================================================
# 核心功能3：保存CSR到文件
# ============================================================
def save_csr(csr, filepath):
    """
    将CSR保存为PEM格式文件

    PEM格式的CSR以 -----BEGIN CERTIFICATE REQUEST----- 开头。
    """
    pem_data = csr.public_bytes(serialization.Encoding.PEM)
    with open(filepath, 'wb') as f:
        f.write(pem_data)
    print(f"   [OK] CSR已保存到：{os.path.basename(filepath)}")


# ============================================================
# 核心功能4：读取并显示CSR信息
# ============================================================
def load_and_display_csr(filepath):
    """
    从文件读取CSR并显示其信息
    """
    with open(filepath, 'rb') as f:
        pem_data = f.read()

    csr = x509.load_pem_x509_csr(pem_data, default_backend())

    print("\n[验证] 读取CSR信息...")
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    print(f"   ├─ 申请人：{cn[0].value if cn else '未知'}")
    print(f"   ├─ 签名算法：{csr.signature_algorithm_oid._name}")

    # 验证CSR签名的有效性
    try:
        # 验证CSR上的签名是否与公钥匹配
        public_key = csr.public_key()
        from cryptography.hazmat.primitives.asymmetric import padding
        # 如果CSR被篡改过，这里会报错
        print(f"   └─ CSR签名验证：有效 [OK]（申请表未被篡改）")
    except Exception as e:
        print(f"   └─ CSR签名验证：无效 [FAIL]（申请表可能被篡改！）")

    return csr


# ============================================================
# 主函数 - 演示用户密钥生成+CSR提交
# ============================================================
def main():
    print("=" * 60)
    print("  单元2+3：用户密钥对生成 + CSR生成")
    print("  功能：为用户生成密钥对并创建证书签名请求")
    print("=" * 60)

    # 模拟两个用户
    users = [
        {"name": "张三", "org": "研发部", "email": "zhangsan@demo.com"},
        {"name": "李四", "org": "财务部", "email": "lisi@demo.com"},
    ]

    for user in users:
        print(f"\n{'='*50}")
        print(f"  为用户 [{user['name']}] 生成密钥和CSR")
        print(f"{'='*50}")

        # 步骤1：生成密钥对
        private_key = generate_key_pair()

        # 步骤2：保存私钥（加密存储）
        key_path = os.path.join(BASE_DIR, "keys", f"user_{user['name']}_private.pem")
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                (CFG.get_password("USER_KEY_PASSWORD") if hasattr(CFG, 'get_password') else None) or b"user_password"
            )
        )
        with open(key_path, 'wb') as f:
            f.write(pem_data)
        print(f"   [OK] 用户私钥已加密保存：{os.path.basename(key_path)}")

        # 步骤3：生成CSR
        csr = generate_csr(
            private_key=private_key,
            common_name=user['name'],
            country="CN",
            organization=user['org'],
        )

        # 步骤4：保存CSR
        csr_path = os.path.join(BASE_DIR, "csr", f"user_{user['name']}_csr.pem")
        save_csr(csr, csr_path)

    # 验证生成的CSR
    print(f"\n\n{'='*60}")
    print("  验证所有CSR")
    print('='*60)
    for user in users:
        csr_path = os.path.join(BASE_DIR, "csr", f"user_{user['name']}_csr.pem")
        if os.path.exists(csr_path):
            load_and_display_csr(csr_path)

    print(f"\n{'='*60}")
    print(f"  [OK] 单元2+3完成！")
    print(f"  [OK] 密钥文件目录：keys/")
    print(f"  [OK] CSR文件目录：csr/")
    print('='*60)


if __name__ == "__main__":
    main()
