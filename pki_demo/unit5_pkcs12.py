"""
==============================================================
  单元5：PKCS#12证书导出（个人证书打包）
  功能：将用户的私钥和证书打包成一个.p12文件（带密码保护）

  通俗解释：
  - PKCS#12（.p12/.pfx）= 个人身份证保险箱
  - 把"钥匙（私钥）"和"身份证（证书）"放在一起
  - 用密码锁起来，方便携带和导入其他系统

  就像把身份证和银行卡放在一个带密码的钱包里，
  走到哪里都能用，但别人捡到也打不开。
==============================================================
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

try:
    from config import CFG
except ImportError:
    CFG = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ============================================================
# 核心功能1：将用户证书和私钥打包为PKCS#12格式
# ============================================================
def export_pkcs12(private_key, user_cert, ca_cert=None,
                  password=b"export_password", friendly_name=None):
    """
    将私钥和证书打包为PKCS#12格式

    参数：
        private_key: 用户的私钥（钥匙）
        user_cert: 用户的证书（身份证）
        ca_cert: CA证书（发证机关的证书，可选，用于构建证书链）
        password: 保护私钥的密码（钱包密码）
        friendly_name: 友好名称（便于识别的别名）

    返回：
        p12_data: PKCS#12格式的二进制数据

    通俗解释：
        把私钥（钥匙）、用户证书（身份证）、CA证书（发证机关证明）
        一起打包成一个.p12文件，用密码保护。
        以后导入浏览器或系统时，只需要这个文件和密码就行。
    """
    # 将私钥转换为PKCS#8格式
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 将证书转换为DER格式
    user_cert_bytes = user_cert.public_bytes(serialization.Encoding.DER)

    ca_cert_bytes = None
    if ca_cert:
        ca_cert_bytes = ca_cert.public_bytes(serialization.Encoding.DER)

    # 构建PKCS#12数据
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates
    )
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption
    )

    # 准备CA证书链（可选）
    ca_certs = [ca_cert] if ca_cert else None

    p12_data = serialize_key_and_certificates(
        name=friendly_name.encode('utf-8') if friendly_name else None,
        key=private_key,
        cert=user_cert,
        cas=ca_certs,
        encryption_algorithm=BestAvailableEncryption(password)
    )

    return p12_data


# ============================================================
# 核心功能2：保存PKCS#12文件
# ============================================================
def save_pkcs12(p12_data, filepath):
    """
    保存PKCS#12格式的个人证书文件
    """
    with open(filepath, 'wb') as f:
        f.write(p12_data)
    print(f"   [OK] PKCS#12证书已保存到：{os.path.basename(filepath)}")


# ============================================================
# 核心功能3：从PKCS#12文件提取信息（验证）
# ============================================================
def load_and_verify_pkcs12(filepath, password=b"export_password"):
    """
    加载并验证PKCS#12文件

    通俗解释：
    打开"个人证书保险箱"，检查里面的东西是否完整。
    """
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_key_and_certificates
    )

    print("\n[验证] 打开PKCS#12保险箱...")

    with open(filepath, 'rb') as f:
        p12_data = f.read()

    private_key, cert, additional_certs = load_key_and_certificates(
        p12_data,
        password,
        default_backend()
    )

    if private_key:
        print(f"   [OK] 私钥：提取成功（钥匙完好）")

    if cert:
        cn = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )
        name = cn[0].value if cn else "未知"
        print(f"   [OK] 用户证书：提取成功（持有人：{name}）")

    if additional_certs:
        print(f"   [OK] CA证书链：包含 {len(additional_certs)} 个证书")

    print(f"   └─ PKCS#12文件验证通过！内容完整。")
    return private_key, cert, additional_certs


# ============================================================
# 主函数 - 导出用户证书
# ============================================================
def main():
    print("=" * 60)
    print("  单元5：PKCS#12证书导出")
    print("  功能：将用户私钥和证书打包为.p12个人证书文件")
    print("=" * 60)

    # 加载CA证书
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 处理每个用户
    users = ["张三", "李四"]

    for username in users:
        print(f"\n{'='*40}")
        print(f"  导出用户 '{username}' 的个人证书")
        print(f"{'='*40}")

        # 加载用户私钥
        key_path = os.path.join(BASE_DIR, "keys", f"user_{username}_private.pem")
        with open(key_path, 'rb') as f:
            key_data = f.read()
        private_key = serialization.load_pem_private_key(
            key_data,
            password=b"user_password",
            backend=default_backend()
        )
        print(f"   [OK] 加载用户私钥成功")

        # 加载用户证书
        cert_path = os.path.join(BASE_DIR, "certs", f"user_{username}_cert.pem")
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        user_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        print(f"   [OK] 加载用户证书成功")

        # 导出为PKCS#12格式
        print("   [正在打包为PKCS#12格式（带密码保护）...]")

        p12_data = export_pkcs12(
            private_key=private_key,
            user_cert=user_cert,
            ca_cert=ca_cert,
            password=b"p12_password_123",
            friendly_name=username
        )

        # 保存文件
        p12_path = os.path.join(BASE_DIR, "export", f"user_{username}.p12")
        save_pkcs12(p12_data, p12_path)

        # 验证导出的文件
        p12_pwd = (CFG.get_password("P12_EXPORT_PASSWORD") if hasattr(CFG, 'get_password') else None) or b"p12_password_123"
        load_and_verify_pkcs12(p12_path, password=p12_pwd)

    print(f"\n{'='*60}")
    print(f"  [OK] 单元5完成！PKCS#12证书已导出。")
    print(f"  [OK] 导出目录：export/")
    print(f"  ├─ user_张三.p12（密码：p12_password_123）")
    print(f"  └─ user_李四.p12（密码：p12_password_123）")
    print(f"  [INFO] 提示：这些.p12文件可以导入到浏览器或系统中使用")
    print("=" * 60)


if __name__ == "__main__":
    main()
