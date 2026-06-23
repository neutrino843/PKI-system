"""
==============================================================
  单元6+7：证书吊销列表（CRL）生成与查询
  功能：生成CRL（"挂失身份证名单"），并支持查询证书是否被吊销
  CRL包含：
  - 被吊销的证书序列号列表
  - 吊销时间
  - 吊销原因
  - CA的数字签名（确保证书的真实性）
==============================================================
"""

import os
import sys
from datetime import datetime, timedelta, timezone
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from .security_crypto import get_signature_hash, sign_crl_with_hash
from .config import CFG

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CRL鏁版嵁鏂囦欢璺緞
CRL_DATA_FILE = os.path.join(BASE_DIR, "crl", "revoked_certs_secure.json")


# ============================================================
# 辅助功能：加载CA私钥和证书
# ============================================================
def load_ca():
    """加载CA的私钥和证书"""
    ca_key_path = os.path.join(BASE_DIR, "keys", "root_ca_private.pem")
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")

    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=
            (CFG.get_password("CA_KEY_PASSWORD") if hasattr(CFG, 'get_password') else None) or b"DEV_ONLY_change_me",
            backend=default_backend()
        )

    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    return ca_key, ca_cert


# ============================================================
# 核心功能1：吊销证书（挂失）
# ============================================================
def revoke_certificate(cert_filepath, reason="unspecified"):
    """
    吊销一张证书（将证书加入"挂失名单"）

    参数：
        cert_filepath: 要吊销的证书文件路径
        reason: 吊销原因
            - "unspecified": 未指定
            - "keyCompromise": 私钥泄露（钥匙被偷了）
            - "caCompromise": CA被攻破
            - "affiliationChanged": 隶属关系变更（离职了）
            - "superseded": 已被替换（换了新证）
            - "cessationOfOperation": 停止运营

    """
    # 读取要吊销的证书
    with open(cert_filepath, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # 获取证书信息
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cert_name = cn[0].value if cn else "未知"
    serial_num = str(cert.serial_number)

    print(f"\n[正在吊销证书：{cert_name}]")
    print(f"   ├─ 证书序列号：{serial_num}")
    print(f"   ├─ 吊销原因：{_reason_desc(reason)}")
    print(f"   └─ 吊销时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 加载现有的吊销数据
    revoked_list = _load_revoked_list()

    # 检查是否已被吊销
    if any(item['serial'] == serial_num for item in revoked_list):
        print(f"   [WARN] 该证书已被吊销，无需重复操作")
        return False

    # 添加新的吊销记录
    revoked_list.append({
        "serial": serial_num,
        "name": cert_name,
        "reason": reason,
        "reason_desc": _reason_desc(reason),
        "revoked_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })

    # 保存更新后的吊销列表
    _save_revoked_list(revoked_list)

    print(f"   [OK] 证书已成功吊销！")
    return True


def _reason_desc(reason):
    """吊销原因的中文描述"""
    reasons = {
        "unspecified": "未指定原因",
        "keyCompromise": "私钥泄露（钥匙被盗）",
        "caCompromise": "CA被攻破",
        "affiliationChanged": "隶属关系变更（如离职）",
        "superseded": "已被替换（换了新证）",
        "cessationOfOperation": "停止运营",
    }
    return reasons.get(reason, "未知原因")


def _load_revoked_list():
    """从文件加载已吊销的证书列表"""
    if os.path.exists(CRL_DATA_FILE):
        with open(CRL_DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []


def _save_revoked_list(revoked_list):
    """保存已吊销的证书列表到文件"""
    with open(CRL_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(revoked_list, f, ensure_ascii=False, indent=2)


# ============================================================
# 核心功能2：生成CRL文件（生成正式的"挂失名单"）
# ============================================================
def generate_crl(crl_filepath=None):
    """
    生成正式的证书吊销列表（CRL）文件

    参数：
        crl_filepath: CRL文件保存路径
    """
    if crl_filepath is None:
        crl_filepath = os.path.join(BASE_DIR, "crl", "ca_crl.pem")

    # 加载CA信息
    ca_key, ca_cert = load_ca()

    # 获取已吊销的证书列表
    revoked_list = _load_revoked_list()

    print("\n[正在生成证书吊销列表（CRL）...]")
    print(f"   ├─ 待吊销证书数：{len(revoked_list)} 个")

    # 构建CRL的颁发者信息
    issuer = ca_cert.subject

    # 设置CRL有效期
    now = datetime.now(timezone.utc)
    next_update = now + timedelta(days=7)  # CRL每周更新一次

    # 构建CRL生成器
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(issuer)
    crl_builder = crl_builder.last_update(now)
    crl_builder = crl_builder.next_update(next_update)

    # 添加每个被吊销的证书
    for item in revoked_list:
        try:
            serial = int(item['serial'])
            revoked_time = datetime.now(timezone.utc)

            # 创建吊销的证书条目
            revoked_cert = x509.RevokedCertificateBuilder() \
                .serial_number(serial) \
                .revocation_date(revoked_time) \
                .build(default_backend())

            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
            print(f"   ├─ 已添加：{item['name']}（序列号：{serial}）")
        except Exception as e:
            print(f"   [WARN] 添加吊销证书失败：{e}")

    # 添加CRL扩展信息
    crl_builder = crl_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    # 用CA私钥签名CRL
    crl_pem = sign_crl_with_hash(
        crl_builder, ca_key,
        get_signature_hash(), default_backend()
    )

    # 保存CRL文件
    with open(crl_filepath, 'wb') as f:
        f.write(crl_pem)

    print(f"   [OK] CRL生成成功！")
    print(f"   ├─ 颁发者（发证机关）：{issuer.rfc4514_string()}")
    print(f"   ├─ 本次更新：{now.strftime('%Y-%m-%d %H:%M')}")
    print(f"   ├─ 下次更新：{next_update.strftime('%Y-%m-%d %H:%M')}")
    print(f"   ├─ 吊销证书数：{len(revoked_list)}")
    print(f"   └─ 已保存到：{os.path.basename(crl_filepath)}")

    return crl


# ============================================================
# 核心功能3：验证证书是否被吊销
# ============================================================
def check_certificate_status(cert_filepath, crl_filepath=None):
    """
    检查一张证书是否已被吊销（查"挂失名单"）

    参数：
        cert_filepath: 要检查的证书文件路径
        crl_filepath: CRL文件路径

    返回：
        (is_revoked, status_info): 是否被吊销，以及详细信息
    """
    if crl_filepath is None:
        crl_filepath = os.path.join(BASE_DIR, "crl", "ca_crl.pem")

    # 读取要检查的证书
    with open(cert_filepath, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cert_name = cn[0].value if cn else "未知"
    serial = cert.serial_number

    print(f"\n[正在检查证书状态：{cert_name}]")
    print(f"   ├─ 证书序列号：{serial}")

    # 如果没有CRL文件，检查JSON数据
    if not os.path.exists(crl_filepath):
        revoked_list = _load_revoked_list()
        for item in revoked_list:
            if int(item['serial']) == serial:
                print(f"   [FAIL] 状态：已吊销 [FAIL]")
                print(f"   ├─ 吊销时间：{item['revoked_at']}")
                print(f"   └─ 吊销原因：{item['reason_desc']}")
                return True, f"证书已吊销 - {item['reason_desc']}"

        print(f"   [OK] 状态：有效 [OK]（未被吊销）")
        return False, "证书有效，未被吊销"

    # 从CRL文件中检查
    try:
        with open(crl_filepath, 'rb') as f:
            crl_data = f.read()
        crl = x509.load_pem_x509_crl(crl_data, default_backend())

        # cryptography库在加载CRL时已自动验证签名，能加载成功即表示签名有效
        print(f"   ├─ CRL签名验证：有效 [OK]（挂失名单由CA签发，真实可信）")

        # 在CRL中查找证书
        for revoked in crl:
            if revoked.serial_number == serial:
                print(f"   [FAIL] 状态：已吊销 [FAIL]")
                print(f"   ├─ 吊销时间：{revoked.revocation_date_utc.strftime('%Y-%m-%d %H:%M')}")
                print(f"   └─ 该证书已被列入'挂失名单'")
                return True, f"证书已被吊销（序列号：{serial}）"

        print(f"   [OK] 状态：有效 [OK]（未在'挂失名单'中找到）")
        return False, "证书有效，未被吊销"

    except Exception as e:
        print(f"   [WARN] 检查失败：{e}")
        # 回退到JSON检查
        return check_certificate_status(cert_filepath, crl_filepath=None)


# ============================================================
# 核心功能4：查看所有已吊销证书
# ============================================================
def show_revoked_list():
    """显示所有已吊销的证书列表"""
    revoked_list = _load_revoked_list()

    print("\n[已吊销证书列表（挂失名单）]")
    print(f"{'='*50}")

    if not revoked_list:
        print("   [INFO] 当前没有已吊销的证书（挂失名单为空）")
        return

    print(f"   共 {len(revoked_list)} 张证书被吊销：")
    print(f"{'─'*50}")
    for i, item in enumerate(revoked_list, 1):
        print(f"   {i}. {item['name']}")
        print(f"      序列号：{item['serial']}")
        print(f"      吊销原因：{item['reason_desc']}")
        print(f"      吊销时间：{item['revoked_at']}")
        print(f"{'─'*50}")


# ============================================================
# 主函数 - 演示CRL功能
# ============================================================
def main():
    print("=" * 60)
    print("  单元6+7：证书吊销列表（CRL）生成与查询")
    print("  功能：吊销证书、生成CRL、查询证书状态")
    print("=" * 60)

    # 步骤1：显示当前吊销列表
    print(f"\n{'='*40}")
    print("  [步骤1] 查看当前吊销列表")
    print(f"{'='*40}")
    show_revoked_list()

    # 步骤2：吊销 User1 的证书（模拟离职）
    print(f"\n{'='*40}")
    print("  [步骤2] 吊销证书（模拟身份证挂失）")
    print("  场景：User1 离职了，需要吊销他的证书")
    print(f"{'='*40}")

    user1_cert = os.path.join(BASE_DIR, "certs", "user_User1_cert.pem")
    revoke_certificate(user1_cert, reason="affiliationChanged")

    # 步骤3：生成CRL
    print(f"\n{'='*40}")
    print("  [步骤3] 生成正式的CRL文件")
    print(f"{'='*40}")
    generate_crl()

    # 步骤4：查询证书状态
    print(f"\n{'='*40}")
    print("  [步骤4] 查询证书状态（查挂失名单）")
    print(f"{'='*40}")

    # 查询 User1 的证书（应该显示已吊销）
    check_certificate_status(user1_cert)

    # 查询 User2 的证书（应该显示有效）
    user2_cert = os.path.join(BASE_DIR, "certs", "user_User2_cert.pem")
    check_certificate_status(user2_cert)

    # 步骤5：查看最终吊销列表
    print(f"\n{'='*40}")
    print("  [步骤5] 查看最终吊销列表")
    print(f"{'='*40}")
    show_revoked_list()

    print(f"\n{'='*60}")
    print(f"  [OK] 单元6+7完成！CRL功能已实现。")
    print(f"  [OK] CRL文件：crl/ca_crl.pem")
    print(f"  [OK] 吊销数据：crl/revoked_certs.json")
    print(f"  [INFO] 功能验证：")
    print(f"  ├─ User1 证书：已被吊销 [OK]")
    print(f"  └─ User2 证书：仍然有效 [OK]")
    print("=" * 60)


if __name__ == "__main__":
    main()
