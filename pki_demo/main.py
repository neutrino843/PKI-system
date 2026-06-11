"""
==============================================================
  PKI演示系统 - 完整集成版（CLI菜单式操作）
  功能：整合所有单元，提供一站式PKI功能演示

  通俗解释：
  这个系统就像"电子身份证管理局"的自助服务终端——
  - 管理员可以发证、吊销、查状态
  - 所有操作都有清晰提示和通俗解释
  - 无需专业知识，按菜单一步步操作即可
==============================================================
"""

import os
import sys
from datetime import datetime, timedelta, timezone
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRL_DATA_FILE = os.path.join(BASE_DIR, "crl", "revoked_certs.json")


# ============================================================
#  公用工具函数
# ============================================================
def clear_screen():
    """清屏"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """打印美观的标题"""
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def print_step(step_num, description):
    """打印步骤提示"""
    print(f"\n  [PLAY] [步骤{step_num}] {description}")
    print("-" * 50)

def wait_user():
    """等待用户按回车继续"""
    input("\n  [ENTER] 按回车键继续...")

def get_input(prompt, default=None):
    """获取用户输入"""
    if default:
        val = input(f"  {prompt}（默认：{default}）: ").strip()
        return val if val else default
    return input(f"  {prompt}: ").strip()


# ============================================================
#  模块A：根CA管理
# ============================================================
def module_a_root_ca():
    """根CA管理——创建和查看根CA"""
    while True:
        clear_screen()
        print_header("模块A：根CA管理（发证总局管理）")
        print("""
  [1] 创建根CA（首次初始化，生成发证总局的证书）
  [2] 查看根CA证书信息
  [3] 返回主菜单

  通俗解释：
  根CA = 整个体系的"最高发证机关"
  这是信任的起点——所有证书的信任都追溯到根CA。
        """)

        choice = input("  请输入选项 [1-3]: ").strip()

        if choice == "1":
            create_root_ca()
        elif choice == "2":
            view_root_ca()
        elif choice == "3":
            break
        else:
            print("  [FAIL] 无效选项，请重新输入")
            wait_user()

def create_root_ca():
    """创建根CA"""
    clear_screen()
    print_header("创建根CA（初始化发证总局）")
    print("""
  [0x1f4d6] 通俗解释：
  这一步相当于成立"国家电子身份证管理局"，
  生成管理局的印章（私钥）和成立证书（自签证书）。
  这是整个PKI体系的信任基石。
    """)

    # 获取根CA信息
    name = get_input("请输入根CA名称", "演示根CA")
    org = get_input("请输入组织名称", "PKI演示系统")
    years = get_input("证书有效期（年）", "10")

    print("\n  [WAIT] 正在生成根CA，这可能需要几秒钟...")
    print("  （生成2048位RSA密钥对需要足够的随机数）")

    # 生成密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 保存私钥
    key_path = os.path.join(BASE_DIR, "keys", "root_ca_private.pem")
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"pki_demo_password")
    )
    with open(key_path, 'wb') as f:
        f.write(pem_data)

    # 生成自签证书
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365 * int(years)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True,
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # 保存证书
    cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"""
  [OK] 根CA创建成功！

  [0x1f4c4] 根CA信息：
     ├─ 名称：{name}
     ├─ 组织：{org}
     ├─ 序列号：{cert.serial_number}
     ├─ 有效期：{years}年
     └─ 签名算法：SHA-256 + RSA

  [0x1f4c1] 生成的文件：
     ├─ 私钥：keys/root_ca_private.pem（已加密）
     └─ 证书：certs/root_ca_cert.pem
    """)
    wait_user()

def view_root_ca():
    """查看根CA证书信息"""
    cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")
    if not os.path.exists(cert_path):
        print("\n  [WARN] 根CA尚未创建，请先执行选项[1]创建根CA。")
        wait_user()
        return

    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)

    print(f"""
  [0x1f4c4] 根CA证书信息：

  ├─ 持有人（Subject）：{cn[0].value if cn else 'N/A'}
  ├─ 颁发者（Issuer）：{issuer_cn[0].value if issuer_cn else 'N/A'}
  ├─ 序列号：{cert.serial_number}
  ├─ 生效日期：{cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M')}
  ├─ 到期日期：{cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M')}
  ├─ 签名算法：{cert.signature_algorithm_oid._name}
  └─ 类型：根CA自签名证书（信任锚点）
    """)
    wait_user()


# ============================================================
#  模块B：用户证书管理
# ============================================================
def module_b_user_cert():
    """用户证书管理——申请和签发证书"""
    while True:
        clear_screen()
        print_header("模块B：用户证书管理（办证中心）")
        print("""
  [1] 申请新证书（为用户生成密钥和证书请求）
  [2] CA签发证书（审核并颁发正式证书）
  [3] 查看已签发的证书
  [4] 返回主菜单

  通俗解释：
  用户证书管理就像"派出所的办证窗口"——
  用户提交申请，审核通过后颁发电子身份证。
        """)

        choice = input("  请输入选项 [1-4]: ").strip()

        if choice == "1":
            apply_new_cert()
        elif choice == "2":
            issue_certificates()
        elif choice == "3":
            view_user_certs()
        elif choice == "4":
            break
        else:
            print("  [FAIL] 无效选项，请重新输入")
            wait_user()

def apply_new_cert():
    """用户申请新证书（生成密钥+CSR）"""
    clear_screen()
    print_header("申请新证书（填写身份证申请表）")
    print("""
  [0x1f4d6] 通俗解释：
  就像去派出所办身份证——
  先自己配好锁和钥匙（密钥对），
  然后填写申请表（CSR），贴上锁的复印件（公钥），
  在申请表上签字（用自己的私钥签名）。
    """)

    name = get_input("请输入用户名", "张三")
    org = get_input("请输入所属部门", "研发部")

    print(f"\n  [WAIT] 正在为 '{name}' 生成密钥和CSR...")

    # 生成密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # 保存私钥
    key_path = os.path.join(BASE_DIR, "keys", f"user_{name}_private.pem")
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"user_password")
    )
    with open(key_path, 'wb') as f:
        f.write(pem_data)

    # 生成CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # 保存CSR
    csr_path = os.path.join(BASE_DIR, "csr", f"user_{name}_csr.pem")
    with open(csr_path, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"""
  [OK] 申请完成！

  [0x1f4c4] 申请人：{name}
  ├─ 组织：{org}
  └─ CSR签名：有效 [0x2713]（申请表是本人提交）

  [0x1f4c1] 生成的文件：
  ├─ 私钥：keys/user_{name}_private.pem（已加密）
  └─ CSR：csr/user_{name}_csr.pem（待CA审核）
    """)
    wait_user()

def issue_certificates():
    """CA签发所有待处理的CSR"""
    clear_screen()
    print_header("CA签发证书（审核并颁发电子身份证）")
    print("""
  [0x1f4d6] 通俗解释：
  CA（发证机关）审核用户提交的申请表（CSR），
  确认信息真实后，在申请表上盖上发证机关的钢印（CA签名），
  一份正式的电子身份证（数字证书）就制作完成了！
    """)

    # 检查根CA是否存在
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")
    ca_key_path = os.path.join(BASE_DIR, "keys", "root_ca_private.pem")
    if not os.path.exists(ca_cert_path):
        print("\n  [WARN] 根CA尚未创建！请先到[模块A]创建根CA。")
        wait_user()
        return

    # 加载CA
    with open(ca_key_path, 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(), password=b"pki_demo_password", backend=default_backend()
        )
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 查找所有待处理的CSR
    csr_files = [f for f in os.listdir(os.path.join(BASE_DIR, "csr"))
                 if f.endswith("_csr.pem")]

    if not csr_files:
        print("\n  [0x1f4ed] 没有待处理的CSR（没有待办申请）")
        print("  请先到[申请新证书]为用户生成CSR。")
        wait_user()
        return

    print(f"\n  发现 {len(csr_files)} 个待处理的证书申请：")
    issued_count = 0

    for csr_file in csr_files:
        # 提取用户名
        username = csr_file.replace("user_", "").replace("_csr.pem", "")

        # 检查是否已签发
        cert_file = os.path.join(BASE_DIR, "certs", f"user_{username}_cert.pem")
        if os.path.exists(cert_file):
            print(f"  [SKIP]  {username}：证书已签发，跳过")
            continue

        # 加载CSR
        csr_path = os.path.join(BASE_DIR, "csr", csr_file)
        with open(csr_path, 'rb') as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())

        # 签发证书
        now = datetime.now(timezone.utc)
        user_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )

        # 保存证书
        with open(cert_file, 'wb') as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))

        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        print(f"  [OK] {cn[0].value if cn else username}：证书已签发 [0x2713]")
        issued_count += 1

    print(f"\n  [OK] 签发完成！共处理 {issued_count} 个证书。")
    wait_user()

def view_user_certs():
    """查看已签发的用户证书"""
    cert_files = [f for f in os.listdir(os.path.join(BASE_DIR, "certs"))
                  if f.startswith("user_") and f.endswith("_cert.pem")]

    if not cert_files:
        print("\n  [0x1f4ed] 没有已签发的用户证书。")
        wait_user()
        return

    print("\n  [0x1f4c4] 已签发的用户证书：")
    print("-" * 50)

    for cert_file in cert_files:
        cert_path = os.path.join(BASE_DIR, "certs", cert_file)
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)

        # 检查是否被吊销
        revoked = is_cert_revoked(str(cert.serial_number))
        status = "[FAIL] 已吊销" if revoked else "[OK] 有效"

        print(f"  [0x1f4cc] {cert_file}")
        print(f"     持有人：{cn[0].value if cn else 'N/A'}")
        print(f"     颁发者：{issuer_cn[0].value if issuer_cn else 'N/A'}")
        print(f"     有效期至：{cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
        print(f"     状态：{status}")
        print("-" * 50)

    wait_user()


# ============================================================
#  模块C：证书吊销管理（CRL）
# ============================================================
def module_c_crl():
    """证书吊销管理"""
    while True:
        clear_screen()
        print_header("模块C：证书吊销管理（挂失中心）")
        print("""
  [1] 吊销证书（挂失电子身份证）
  [2] 生成CRL（发布"挂失名单"）
  [3] 查询证书状态（查"挂失名单"）
  [4] 查看已吊销证书列表
  [5] 导出PKCS#12个人证书
  [6] 返回主菜单

  通俗解释：
  就像公安局的"身份证挂失中心"——
  证件丢了可以挂失，然后系统发布挂失名单，
  别人一查就知道这张证已经失效了。
        """)

        choice = input("  请输入选项 [1-6]: ").strip()

        if choice == "1":
            revoke_cert()
        elif choice == "2":
            do_generate_crl()
        elif choice == "3":
            check_cert_status()
        elif choice == "4":
            show_revoked_list()
        elif choice == "5":
            export_p12()
        elif choice == "6":
            break
        else:
            print("  [FAIL] 无效选项，请重新输入")
            wait_user()

def revoke_cert():
    """吊销证书"""
    cert_files = [f for f in os.listdir(os.path.join(BASE_DIR, "certs"))
                  if f.startswith("user_") and f.endswith("_cert.pem")]

    if not cert_files:
        print("\n  [0x1f4ed] 没有可吊销的证书。")
        wait_user()
        return

    print("\n  可选证书：")
    for i, f in enumerate(cert_files, 1):
        username = f.replace("user_", "").replace("_cert.pem", "")
        print(f"  [{i}] {username}")

    try:
        idx = int(input("\n  选择要吊销的证书编号: ")) - 1
        if idx < 0 or idx >= len(cert_files):
            raise ValueError
    except:
        print("  [FAIL] 无效选择")
        wait_user()
        return

    cert_file = cert_files[idx]
    username = cert_file.replace("user_", "").replace("_cert.pem", "")

    print(f"""
  [0x1f4d6] 通俗解释：
  就像去派出所挂失身份证——
  证书丢失或用户离职，需要将证书作废。

  吊销原因：
  [1] 隶属关系变更（如离职）
  [2] 私钥泄露（钥匙被盗）
  [3] 已被替换（换了新证）
  [4] 停止运营
  [5] 未指定
    """)

    reason_map = {"1": "affiliationChanged", "2": "keyCompromise",
                  "3": "superseded", "4": "cessationOfOperation", "5": "unspecified"}
    reason_desc = {"1": "隶属关系变更（如离职）", "2": "私钥泄露（钥匙被盗）",
                   "3": "已被替换（换了新证）", "4": "停止运营", "5": "未指定原因"}

    r = input("  选择吊销原因 [1-5]: ").strip()

    if r not in reason_map:
        print("  [FAIL] 无效选择")
        wait_user()
        return

    # 加载证书获取序列号
    cert_path = os.path.join(BASE_DIR, "certs", cert_file)
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    revoked_list = _load_revoked()
    serial_str = str(cert.serial_number)

    if any(item['serial'] == serial_str for item in revoked_list):
        print("  [WARN] 该证书已被吊销，无需重复操作")
        wait_user()
        return

    revoked_list.append({
        "serial": serial_str,
        "name": username,
        "reason": reason_map[r],
        "reason_desc": reason_desc[r],
        "revoked_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })
    _save_revoked(revoked_list)

    print(f"\n  [OK] 证书 '{username}' 已成功吊销！")
    print(f"  原因：{reason_desc[r]}")
    print(f"  时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    wait_user()

def do_generate_crl():
    """生成CRL"""
    revoked_list = _load_revoked()
    if not revoked_list:
        print("\n  [0x1f4ed] 当前没有已吊销的证书，无需生成CRL。")
        wait_user()
        return

    # 加载CA
    ca_key_path = os.path.join(BASE_DIR, "keys", "root_ca_private.pem")
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")

    if not os.path.exists(ca_cert_path):
        print("\n  [WARN] 根CA尚未创建！")
        wait_user()
        return

    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=b"pki_demo_password", backend=default_backend()
        )
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 构建CRL
    now = datetime.now(timezone.utc)
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_cert.subject)
    crl_builder = crl_builder.last_update(now)
    crl_builder = crl_builder.next_update(now + timedelta(days=7))

    for item in revoked_list:
        try:
            revoked_cert = x509.RevokedCertificateBuilder() \
                .serial_number(int(item['serial'])) \
                .revocation_date(now) \
                .build(default_backend())
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        except Exception as e:
            print(f"  [WARN] 添加吊销证书失败: {e}")

    crl_builder = crl_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    crl = crl_builder.sign(ca_key, hashes.SHA256(), default_backend())

    crl_path = os.path.join(BASE_DIR, "crl", "ca_crl.pem")
    with open(crl_path, 'wb') as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print(f"""
  [OK] CRL生成成功！

  [0x1f4c4] CRL信息：
     ├─ 颁发者：{ca_cert.subject.rfc4514_string()}
     ├─ 本次更新：{now.strftime('%Y-%m-%d %H:%M')}
     ├─ 下次更新：{(now + timedelta(days=7)).strftime('%Y-%m-%d %H:%M')}
     ├─ 吊销证书数：{len(revoked_list)}
     └─ CA签名：有效 [0x2713]

  [0x1f4c1] 文件：crl/ca_crl.pem
    """)
    wait_user()

def check_cert_status():
    """查询证书状态"""
    cert_path = get_input("请输入证书文件路径", os.path.join(BASE_DIR, "certs", "user_张三_cert.pem"))

    if not os.path.exists(cert_path):
        print(f"\n  [WARN] 文件不存在: {cert_path}")
        wait_user()
        return

    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    serial = str(cert.serial_number)

    revoked = is_cert_revoked(serial)

    print(f"""
  [0x1f50d] 证书状态查询结果：

  持有人：{cn[0].value if cn else 'N/A'}
  序列号：{serial}
  有效期至：{cert.not_valid_after_utc.strftime('%Y-%m-%d')}

  吊销状态：{'[FAIL] 已吊销' if revoked else '[OK] 有效'}
    """)

    if revoked:
        revoked_list = _load_revoked()
        for item in revoked_list:
            if item['serial'] == serial:
                print(f"  吊销原因：{item['reason_desc']}")
                print(f"  吊销时间：{item['revoked_at']}")
                break

    wait_user()

def show_revoked_list():
    """显示已吊销证书列表"""
    revoked_list = _load_revoked()

    if not revoked_list:
        print("\n  [0x1f4ed] 当前没有已吊销的证书（挂失名单为空）")
        wait_user()
        return

    print(f"\n  [0x1f4cb] 已吊销证书列表（共 {len(revoked_list)} 张）")
    print("=" * 50)
    for i, item in enumerate(revoked_list, 1):
        print(f"  {i}. {item['name']}")
        print(f"     序列号：{item['serial']}")
        print(f"     原因：{item['reason_desc']}")
        print(f"     时间：{item['revoked_at']}")
        print("-" * 50)

    wait_user()

def export_p12():
    """导出PKCS#12个人证书"""
    cert_files = [f for f in os.listdir(os.path.join(BASE_DIR, "certs"))
                  if f.startswith("user_") and f.endswith("_cert.pem")]

    if not cert_files:
        print("\n  [0x1f4ed] 没有可导出的证书。")
        wait_user()
        return

    print("\n  可选证书：")
    for i, f in enumerate(cert_files, 1):
        username = f.replace("user_", "").replace("_cert.pem", "")
        print(f"  [{i}] {username}")

    try:
        idx = int(input("\n  选择要导出的证书编号: ")) - 1
        if idx < 0 or idx >= len(cert_files):
            raise ValueError
    except:
        print("  [FAIL] 无效选择")
        wait_user()
        return

    cert_file = cert_files[idx]
    username = cert_file.replace("user_", "").replace("_cert.pem", "")

    # 加载密钥和证书
    key_path = os.path.join(BASE_DIR, "keys", f"user_{username}_private.pem")
    cert_path = os.path.join(BASE_DIR, "certs", cert_file)
    ca_cert_path = os.path.join(BASE_DIR, "certs", "root_ca_cert.pem")

    if not os.path.exists(key_path) or not os.path.exists(ca_cert_path):
        print("  [WARN] 缺少必要的密钥或CA证书文件")
        wait_user()
        return

    pwd = get_input("设置PKCS#12导出密码", "p12_123")

    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=b"user_password", backend=default_backend()
        )
    with open(cert_path, 'rb') as f:
        user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates
    )

    p12_data = serialize_key_and_certificates(
        name=username.encode('utf-8'),
        key=private_key,
        cert=user_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode())
    )

    p12_path = os.path.join(BASE_DIR, "export", f"user_{username}.p12")
    with open(p12_path, 'wb') as f:
        f.write(p12_data)

    print(f"""
  [OK] PKCS#12导出成功！

  [0x1f4c1] 文件：export/user_{username}.p12
  [0x1f511] 密码：{pwd}

  [0x1f4d6] 通俗解释：
  PKCS#12文件就像"个人电子身份证保险箱"——
  里面包含私钥（钥匙）+ 证书（身份证）+ CA证书，
  用一个密码保护起来，方便导入浏览器或系统。
    """)
    wait_user()


# ============================================================
#  辅助函数
# ============================================================
def _load_revoked():
    """加载吊销列表"""
    if os.path.exists(CRL_DATA_FILE):
        with open(CRL_DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def _save_revoked(data):
    """保存吊销列表"""
    with open(CRL_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def is_cert_revoked(serial_str):
    """检查证书是否被吊销"""
    revoked_list = _load_revoked()
    return any(item['serial'] == serial_str for item in revoked_list)


# ============================================================
#  主菜单
# ============================================================
def main():
    while True:
        clear_screen()
        print("""
  ╔══════════════════════════════════════════════════════╗
  ║         PKI演示系统 - 电子身份证管理平台              ║
  ║         Mini PKI Demo System v1.0                    ║
  ╚══════════════════════════════════════════════════════╝

  ┌──────────────────────────────────────────────────────┐
  │  [A] 根CA管理      - 管理发证总局                    │
  │  [B] 用户证书管理   - 申请和签发电子身份证             │
  │  [C] 证书吊销管理   - 挂失、发布CRL、查状态            │
  │  [Q] 退出系统                                         │
  └──────────────────────────────────────────────────────┘

  生活类比：
  这套系统就像"电子身份证管理局"——
  A = 总局（发证机关的印章和授权）
  B = 办证窗口（申请人提交材料，审核发证）
  C = 挂失中心（证件挂失和状态查询）
        """)

        choice = input("  请输入选项 [A/B/C/Q]: ").strip().upper()

        if choice == "A":
            module_a_root_ca()
        elif choice == "B":
            module_b_user_cert()
        elif choice == "C":
            module_c_crl()
        elif choice == "Q":
            print("\n  [0x1f44b] 感谢使用PKI演示系统！再见！\n")
            sys.exit(0)
        else:
            print("  [FAIL] 无效选项，请重新输入")
            wait_user()


if __name__ == "__main__":
    main()
