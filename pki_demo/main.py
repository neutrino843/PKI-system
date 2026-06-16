"""
PKI演示系统 - 完整集成版 v2.0
功能：整合所有安全加固模块，提供全流程PKI操作
"""

import os
import sys
import json
import getpass
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# 安全模块导入
from config import CFG
from auth import (_session_manager as auth_sm, Permission, Role,
                  ROLE_PERMISSIONS, UserManager, require_permission,
                  AuthorizationError)
from audit import audit_logger
from ra import ra_manager
from security_crl import SecureRevokedList
from security_crypto import get_hash_algorithm, get_rsa_key_size, FileIntegrityChecker
from backup import BackupManager
from inter_ca import generate_intermediate_ca
from cert_expiry import CertExpiryChecker

BASE_DIR = Path(__file__).parent.resolve()


# ============================================================
# 初始化
# ============================================================
def initialize_system():
    """系统初始化：检查环境、创建目录、前置检查"""
    dirs = ["certs", "keys", "csr", "crl", "export", "data"]
    for d in dirs:
        (BASE_DIR / d).mkdir(exist_ok=True)

    # 检查环境变量
    missing = []
    for name in ["CA_KEY_PASSWORD", "USER_KEY_PASSWORD"]:
        if not CFG.get_password(name):
            missing.append(f"PKI_{name}")

    if missing:
        print(f"[WARN] 以下环境变量未设置: {', '.join(missing)}")
        print(" 建议运行 setup_env.bat 进行配置")
        if not os.environ.get("PKI_SKIP_CHECK"):
            input("  按回车键继续...")

    # 证书到期检查
    checker = CertExpiryChecker()
    results = checker.scan_certificates()
    expired = len(results.get("expired", []))
    if expired > 0:
        print(f"[WARN] 发现 {expired} 张已过期证书，建议及时处理")
    print("[INFO] 系统初始化完成")


# ============================================================
# 登录
# ============================================================
def login_screen():
    """登录界面"""
    print("=" * 60)
    print("  PKI演示系统 v2.0 - 电子身份证管理平台")
    print("=" * 60)
    print()
    print("  请登录系统")
    print("-" * 40)

    for attempt in range(3):
        username = input("  用户名: ").strip()
        password = getpass.getpass("  密  码: ").strip()

        success, msg = auth_sm.login(username, password)
        if success:
            user = auth_sm.get_current_user()
            audit_logger.log("LOGIN", username, "LOGIN", "system", "SUCCESS",
                             f"用户{user['name']}登录系统", user["role"])
            print(f"\n  [OK] {msg}")
            return True
        else:
            audit_logger.log("AUTH_FAIL", username, "LOGIN", "system", "FAILURE",
                             f"登录失败(第{attempt+1}次)", "")
            print(f"\n  [FAIL] {msg}")
            if attempt < 2:
                print("  请重试\n")

    print("\n[FAIL] 登录失败次数过多，系统退出")
    return False


# ============================================================
# 辅助UI函数
# ============================================================
def print_header(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def print_step(step_num, description):
    print(f"\n  [步骤{step_num}] {description}")
    print("-" * 50)

def wait_user():
    input("\n  按回车键继续...")

def get_input(prompt, default=None, max_len=100):
    val = input(f"  {prompt}(默认: {default}): ").strip()
    if len(val) > max_len:
        print(f"  [WARN] 输入超过{max_len}字符，已截断")
        val = val[:max_len]
    return val if val else default

def get_current_username():
    user = auth_sm.get_current_user()
    return user["username"] if user else "unknown"

def get_current_role():
    user = auth_sm.get_current_user()
    return user["role"] if user else "end_user"


# ============================================================
# 模块A：根CA管理
# ============================================================
def module_a_root_ca():
    while True:
        print_header("模块A：根CA管理(发证总局管理)")
        print("""
  [1] 创建根CA(首次初始化，生成发证总局的证书)
  [2] 创建中间CA(由根CA签发的二级发证机构)
  [3] 查看根CA证书信息
  [4] 查看中间CA证书信息
  [5] 返回主菜单
        """)
        choice = input("  请输入选项 [1-5]: ").strip()

        if choice == "1":
            _create_root_ca()
        elif choice == "2":
            _create_intermediate_ca()
        elif choice == "3":
            _view_cert_info("root_ca_cert.pem", "根CA")
        elif choice == "4":
            _view_cert_info("inter_ca_cert.pem", "中间CA")
        elif choice == "5":
            break
        else:
            print("  [FAIL] 无效选项")
            wait_user()

def _create_root_ca():
    print_header("创建根CA(初始化发证总局)")
    print("""
  说明：这一步生成发证总局的印章(私钥)和成立证书(自签证书)。
  根CA是整个PKI体系的信任基石。
    """)

    name = get_input("根CA名称", "演示根CA")
    org = get_input("组织名称", "PKI演示系统")
    years = get_input("证书有效期(年)", "10")

    print("\n  正在生成根CA(2048位RSA密钥对)...")

    # 生成密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=get_rsa_key_size(),
        backend=default_backend()
    )

    # 保存私钥
    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        raise RuntimeError("环境变量 PKI_CA_KEY_PASSWORD 未设置，无法加载CA私钥")
    key_path = BASE_DIR / "keys" / "root_ca_private.pem"
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(ca_pwd)
    )
    with open(key_path, "wb") as f:
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

    cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    audit_logger.log("CA_CREATE", get_current_username(), "CREATE",
                     "root_ca", "SUCCESS", f"创建根CA: {name}", get_current_role())

    print(f"""
  [OK] 根CA创建成功！
  名称: {name}  组织: {org}
  序列号: {cert.serial_number}  有效期: {years}年
  私钥: keys/root_ca_private.pem(已加密)
  证书: certs/root_ca_cert.pem
    """)
    wait_user()

def _create_intermediate_ca():
    """创建中间CA"""
    try:
        from inter_ca import generate_intermediate_ca
        success, msg = generate_intermediate_ca()
        print(f"\n  [OK] {msg}")
        audit_logger.log("CA_CREATE", get_current_username(), "CREATE",
                         "inter_ca", "SUCCESS", msg, get_current_role())
    except Exception as e:
        print(f"\n  [FAIL] 创建中间CA失败: {e}")

    wait_user()

def _view_cert_info(filename, label):
    cert_path = BASE_DIR / "certs" / filename
    if not cert_path.exists():
        print(f"\n  [WARN] {label}证书尚未创建")
        wait_user()
        return

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass

    print(f"""
  {label}证书信息:
  持有人: {cn[0].value if cn else 'N/A'}
  颁发者: {issuer_cn[0].value if issuer_cn else 'N/A'}
  序列号: {cert.serial_number}
  生效: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M')}
  到期: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M')}
  CA证书: {"是" if is_ca else "否"}
    """)
    wait_user()


# ============================================================
# 模块B：用户证书管理
# ============================================================
def module_b_user_cert():
    while True:
        print_header("模块B：用户证书管理(办证中心)")
        print("""
  [1] 申请新证书(为用户生成密钥和CSR)
  [2] RA审核证书申请(操作员审核待办申请)
  [3] CA签发证书(为已批准的申请签发证书)
  [4] 查看已签发的证书
  [5] 查看待审核的申请列表
  [6] 返回主菜单
        """)
        choice = input("  请输入选项 [1-6]: ").strip()

        if choice == "1":
            _apply_new_cert()
        elif choice == "2":
            _ra_approve_csr()
        elif choice == "3":
            _issue_approved_certs()
        elif choice == "4":
            _view_user_certs()
        elif choice == "5":
            _view_pending_csr()
        elif choice == "6":
            break
        else:
            print("  [FAIL] 无效选项")
            wait_user()

def _apply_new_cert():
    print_header("申请新证书(填写身份证申请表)")

    name = get_input("用户名", "张三")
    org = get_input("所属部门", "研发部")

    print(f"\n  正在为 '{name}' 生成密钥和CSR...")

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=get_rsa_key_size(), backend=default_backend()
    )

    user_pwd = CFG.get_password("USER_KEY_PASSWORD")
    if not user_pwd:
        raise RuntimeError("环境变量 PKI_USER_KEY_PASSWORD 未设置，无法加载用户私钥")
    key_path = BASE_DIR / "keys" / f"user_{name}_private.pem"
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(user_pwd)
    )
    with open(key_path, "wb") as f:
        f.write(pem_data)

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

    csr_path = BASE_DIR / "csr" / f"user_{name}_csr.pem"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # 通过RA提交申请
    csr_id = f"CSR-{name}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    success, msg = ra_manager.submit_csr(
        csr_id, name, org, str(csr_path), get_current_username()
    )

    audit_logger.log("CSR_CREATE", get_current_username(), "CREATE",
                     csr_id, "SUCCESS", f"用户{name}提交证书申请", get_current_role())

    print(f"""
  [OK] 申请完成！申请人: {name}  组织: {org}
  申请编号: {csr_id}
  状态: 待RA审核
  私钥: keys/user_{name}_private.pem(已加密)
  CSR: csr/user_{name}_csr.pem
    """)
    wait_user()

def _ra_approve_csr():
    """RA审核证书申请（含四眼原则）"""
    try:
        require_permission(Permission.APPROVE_CSR)(lambda: None)()
    except AuthorizationError as e:
        print(f"\n  [FAIL] {e}")
        wait_user()
        return

    pending = ra_manager.get_pending_list()
    if not pending:
        print("\n  [INFO] 当前没有待审核的申请")
        wait_user()
        return

    print(f"\n  待审核申请(共{len(pending)}条):")
    print("-" * 50)
    for i, item in enumerate(pending, 1):
        status_tag = "待初审" if item["status"] == "pending" else "待二审"
        reviewer = ""
        if item["status"] == "first_approved":
            reviewer = f" (已由{item.get('reviewer_1','?')}初审)"
        print(f"  [{i}] {item['csr_id']} - {item['username']}({item['org']}) [{status_tag}]{reviewer}")
        print(f"      提交时间: {item['submitted_at'][:19]}")

    try:
        idx = int(input("\n  选择要处理的编号(0=返回): ")) - 1
        if idx < 0 or idx >= len(pending):
            return
    except:
        return

    item = pending[idx]
    current_user = get_current_username()

    if item["status"] == "first_approved":
        # 二审路径
        action = input("  [1]二审通过 [2]拒绝: ").strip()
        note = input("  审核意见: ").strip()
        if action == "1":
            success, msg = ra_manager.second_approve_csr(
                item["csr_id"], current_user, note
            )
            audit_logger.log("CSR_SECOND_APPROVE", current_user, "UPDATE",
                             item["csr_id"], "SUCCESS", msg, get_current_role())
            print(f"\n  [OK] {msg}")
        elif action == "2":
            success, msg = ra_manager.reject_csr(
                item["csr_id"], current_user, note
            )
            print(f"\n  [OK] {msg}")
        else:
            print("  [FAIL] 无效操作")
    else:
        # 初审路径
        action = input("  [1]初审通过 [2]拒绝: ").strip()
        note = input("  审核意见: ").strip()
        if action == "1":
            success, msg = ra_manager.approve_csr(
                item["csr_id"], current_user, note
            )
            audit_logger.log("CSR_FIRST_APPROVE", current_user, "UPDATE",
                             item["csr_id"], "SUCCESS", msg, get_current_role())
            print(f"\n  [OK] {msg}")
        elif action == "2":
            success, msg = ra_manager.reject_csr(
                item["csr_id"], current_user, note
            )
            print(f"\n  [OK] {msg}")
        else:
            print("  [FAIL] 无效操作")

    wait_user()

def _issue_approved_certs():
    """签发已批准的证书"""
    try:
        require_permission(Permission.ISSUE_CERT)(lambda: None)()
    except AuthorizationError as e:
        print(f"\n  [FAIL] {e}")
        wait_user()
        return

    approved = ra_manager.get_approved_list()
    if not approved:
        print("\n  [INFO] 没有待签发的申请(请先执行RA审核)")
        wait_user()
        return

    # 先尝试加载中间CA，如果没有则用根CA
    ca_cert_path = BASE_DIR / "certs" / "inter_ca_cert.pem"
    ca_key_path = BASE_DIR / "keys" / "inter_ca_private.pem"

    if not ca_cert_path.exists():
        ca_cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"
        ca_key_path = BASE_DIR / "keys" / "root_ca_private.pem"

    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        raise RuntimeError("环境变量 PKI_CA_KEY_PASSWORD 未设置，无法加载CA私钥")
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=ca_pwd, backend=default_backend()
        )
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    issued_count = 0
    for item in approved:
        csr_path = item["csr_filepath"]
        if not os.path.exists(csr_path):
            print(f"  [WARN] CSR文件不存在: {csr_path}")
            continue

        with open(csr_path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())

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
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        cert_path = BASE_DIR / "certs" / f"user_{item['username']}_cert.pem"
        with open(cert_path, "wb") as f:
            f.write(user_cert.public_bytes(serialization.Encoding.PEM))

        ra_manager.mark_issued(item["csr_id"])
        audit_logger.log("CERT_ISSUE", get_current_username(), "CREATE",
                         f"user_{item['username']}_cert.pem", "SUCCESS",
                         f"为用户{item['username']}签发证书", get_current_role())
        issued_count += 1
        print(f"  [OK] {item['username']}: 证书已签发")

    print(f"\n  [OK] 签发完成！共签发 {issued_count} 张证书")
    wait_user()

def _view_user_certs():
    cert_files = sorted(BASE_DIR.glob("certs/user_*_cert.pem"))
    if not cert_files:
        print("\n  [INFO] 没有已签发的用户证书")
        wait_user()
        return

    print("\n  已签发的用户证书:")
    print("-" * 50)
    for cert_file in cert_files:
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)

        # 检查吊销状态
        revoked_list = SecureRevokedList().get_revoked_list()
        revoked = any(item["serial"] == str(cert.serial_number) for item in revoked_list)
        status = "[已吊销]" if revoked else "[有效]"

        print(f"  {cert_file.name}:")
        print(f"    持有人: {cn[0].value if cn else 'N/A'}  {status}")
        print(f"    颁发者: {issuer_cn[0].value if issuer_cn else 'N/A'}")
        print(f"    有效期至: {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
        print("-" * 40)

    wait_user()

def _view_pending_csr():
    pending = ra_manager.get_pending_list()
    if not pending:
        print("\n  [INFO] 没有待审核的申请")
        wait_user()
        return

    print(f"\n  待审核申请(共{len(pending)}条):")
    for item in pending:
        print(f"  {item['csr_id']}: {item['username']}({item['org']}) - {item['submitted_at'][:19]}")
    wait_user()


# ============================================================
# 模块C：证书吊销与CRL
# ============================================================
def module_c_crl():
    while True:
        print_header("模块C：证书吊销管理(挂失中心)")
        print("""
  [1] 吊销证书(挂失电子身份证)
  [2] 生成CRL(发布挂失名单)
  [3] 查询证书状态
  [4] 查看已吊销证书列表
  [5] 导出PKCS#12个人证书
  [6] CRL完整性校验
  [7] 返回主菜单
        """)
        choice = input("  请输入选项 [1-7]: ").strip()

        if choice == "1":
            _revoke_cert()
        elif choice == "2":
            _generate_crl()
        elif choice == "3":
            _check_cert_status()
        elif choice == "4":
            _show_revoked_list()
        elif choice == "5":
            _export_p12()
        elif choice == "6":
            _verify_crl_integrity()
        elif choice == "7":
            break
        else:
            print("  [FAIL] 无效选项")
            wait_user()

def _revoke_cert():
    try:
        require_permission(Permission.REVOKE_CERT)(lambda: None)()
    except AuthorizationError as e:
        print(f"\n  [FAIL] {e}")
        wait_user()
        return

    cert_files = sorted(BASE_DIR.glob("certs/user_*_cert.pem"))
    if not cert_files:
        print("\n  [INFO] 没有可吊销的证书")
        wait_user()
        return

    print("\n  可选证书:")
    for i, f in enumerate(cert_files, 1):
        username = f.stem.replace("user_", "").replace("_cert", "")
        print(f"  [{i}] {username}")

    try:
        idx = int(input("\n  选择要吊销的证书编号: ")) - 1
        if idx < 0 or idx >= len(cert_files):
            return
    except:
        return

    cert_file = cert_files[idx]
    username = cert_file.stem.replace("user_", "").replace("_cert", "")

    print("""
  吊销原因:
  [1] 隶属关系变更(如离职)
  [2] 私钥泄露(钥匙被盗)
  [3] 已被替换(换了新证)
  [4] 停止运营
  [5] 未指定
    """)

    reason_map = {"1": "affiliationChanged", "2": "keyCompromise",
                  "3": "superseded", "4": "cessationOfOperation", "5": "unspecified"}
    reason_desc = {"1": "隶属关系变更(如离职)", "2": "私钥泄露(钥匙被盗)",
                   "3": "已被替换(换了新证)", "4": "停止运营", "5": "未指定原因"}

    r = input("  选择吊销原因 [1-5]: ").strip()
    if r not in reason_map:
        print("  [FAIL] 无效选择")
        wait_user()
        return

    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 使用安全CRL管理器
    s = SecureRevokedList()
    result = s.revoke(cert.serial_number, username, reason_map[r], reason_desc[r])
    if result:
        audit_logger.log("CERT_REVOKE", get_current_username(), "DELETE",
                         str(cert.serial_number), "SUCCESS",
                         f"吊销用户{username}证书,原因:{reason_desc[r]}", get_current_role())
    wait_user()

def _generate_crl():
    try:
        require_permission(Permission.GENERATE_CRL)(lambda: None)()
    except AuthorizationError as e:
        print(f"\n  [FAIL] {e}")
        wait_user()
        return

    s = SecureRevokedList()
    revoked_list = s.get_revoked_list()
    if not revoked_list:
        print("\n  [INFO] 没有已吊销的证书，无需生成CRL")
        wait_user()
        return

    # 加载CA
    ca_cert_path = BASE_DIR / "certs" / "inter_ca_cert.pem"
    ca_key_path = BASE_DIR / "keys" / "inter_ca_private.pem"
    if not ca_cert_path.exists():
        ca_cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"
        ca_key_path = BASE_DIR / "keys" / "root_ca_private.pem"

    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        raise RuntimeError("环境变量 PKI_CA_KEY_PASSWORD 未设置，无法加载CA私钥")
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=ca_pwd, backend=default_backend()
        )
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 构建CRL - 使用真实吊销时间
    now = datetime.now(timezone.utc)
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_cert.subject)
    crl_builder = crl_builder.last_update(now)
    crl_builder = crl_builder.next_update(now + timedelta(days=7))

    for item in revoked_list:
        try:
            # 使用保存的真实吊销时间
            revoked_at_str = item.get("revoked_at", now.isoformat())
            try:
                revoked_at = datetime.fromisoformat(revoked_at_str)
            except:
                revoked_at = now

            revoked_cert = x509.RevokedCertificateBuilder() \
                .serial_number(int(item["serial"])) \
                .revocation_date(revoked_at.replace(tzinfo=timezone.utc)) \
                .build(default_backend())
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
            print(f"  [OK] 已添加: {item['name']}(吊销于{revoked_at_str[:19]})")
        except Exception as e:
            print(f"  [WARN] 添加吊销证书失败: {e}")

    crl_builder = crl_builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    crl = crl_builder.sign(ca_key, get_hash_algorithm(), default_backend())

    crl_path = BASE_DIR / "crl" / "ca_crl.pem"
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    audit_logger.log("CRL_GEN", get_current_username(), "CREATE",
                     "ca_crl.pem", "SUCCESS",
                     f"生成CRL，包含{len(revoked_list)}条吊销记录", get_current_role())

    print(f"""
  [OK] CRL生成成功！
  颁发者: {ca_cert.subject.rfc4514_string()}
  吊销证书数: {len(revoked_list)}
  下次更新: {(now + timedelta(days=7)).strftime('%Y-%m-%d')}
  文件: crl/ca_crl.pem
    """)
    wait_user()

def _check_cert_status():
    s = SecureRevokedList()
    serial = input("  输入证书序列号(直接回车查看默认证书): ").strip()

    if not serial:
        # 选择用户证书
        cert_files = sorted(BASE_DIR.glob("certs/user_*_cert.pem"))
        if not cert_files:
            print("\n  [INFO] 没有用户证书")
            wait_user()
            return
        print("\n  可选证书:")
        for i, f in enumerate(cert_files, 1):
            username = f.stem.replace("user_", "").replace("_cert", "")
            print(f"  [{i}] {username}")
        try:
            idx = int(input("  选择: ")) - 1
            cert_path = cert_files[idx]
        except:
            return
    else:
        # 通过序列号查找
        cert_path = None
        for f in BASE_DIR.glob("certs/user_*_cert.pem"):
            with open(f, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
                if str(cert.serial_number) == serial:
                    cert_path = f
                    break
        if not cert_path:
            print(f"\n  [FAIL] 未找到序列号为 {serial} 的证书")
            wait_user()
            return

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    revoked = s.is_revoked(cert.serial_number)

    print(f"""
  证书状态查询结果:
  持有人: {cn[0].value if cn else 'N/A'}
  序列号: {cert.serial_number}
  有效期至: {cert.not_valid_after_utc.strftime('%Y-%m-%d')}
  吊销状态: {"[已吊销]" if revoked else "[有效]"}
    """)

    if revoked:
        for item in s.get_revoked_list():
            if item["serial"] == str(cert.serial_number):
                print(f"  吊销原因: {item.get('reason_desc', '未知')}")
                print(f"  吊销时间: {item.get('revoked_at', '未知')[:19]}")
                break

    wait_user()

def _show_revoked_list():
    s = SecureRevokedList()
    revoked_list = s.get_revoked_list()
    if not revoked_list:
        print("\n  [INFO] 当前没有已吊销的证书")
        wait_user()
        return

    print(f"\n  已吊销证书列表(共{len(revoked_list)}张):")
    print("=" * 50)
    for i, item in enumerate(revoked_list, 1):
        print(f"  {i}. {item['name']}")
        print(f"     序列号: {item['serial']}")
        print(f"     原因: {item.get('reason_desc', '未知')}")
        print(f"     时间: {item.get('revoked_at', '未知')[:19]}")
        print("-" * 40)
    wait_user()

def _export_p12():
    cert_files = sorted(BASE_DIR.glob("certs/user_*_cert.pem"))
    if not cert_files:
        print("\n  [INFO] 没有可导出的证书")
        wait_user()
        return

    print("\n  可选证书:")
    for i, f in enumerate(cert_files, 1):
        username = f.stem.replace("user_", "").replace("_cert", "")
        print(f"  [{i}] {username}")

    try:
        idx = int(input("\n  选择要导出的证书编号: ")) - 1
    except:
        return

    cert_file = cert_files[idx]
    username = cert_file.stem.replace("user_", "").replace("_cert", "")

    key_path = BASE_DIR / "keys" / f"user_{username}_private.pem"
    ca_cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"

    if not key_path.exists() or not ca_cert_path.exists():
        print("  [FAIL] 缺少必要的密钥或CA证书文件")
        wait_user()
        return

    pwd = get_input("设置PKCS#12导出密码", "p12_123")
    user_pwd = CFG.get_password("USER_KEY_PASSWORD")
    if not user_pwd:
        raise RuntimeError("环境变量 PKI_USER_KEY_PASSWORD 未设置，无法加载用户私钥")

    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=user_pwd, backend=default_backend()
        )
    with open(cert_file, "rb") as f:
        user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates
    )

    p12_data = serialize_key_and_certificates(
        name=username.encode("utf-8"),
        key=private_key,
        cert=user_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode())
    )

    p12_path = BASE_DIR / "export" / f"user_{username}.p12"
    with open(p12_path, "wb") as f:
        f.write(p12_data)

    audit_logger.log("P12_EXPORT", get_current_username(), "CREATE",
                     f"user_{username}.p12", "SUCCESS",
                     f"导出用户{username}的PKCS#12证书", get_current_role())

    print(f"""
  [OK] PKCS#12导出成功！
  文件: export/user_{username}.p12
  密码: {pwd}
  说明: PKCS#12文件包含私钥(钥匙)+证书(身份证)+CA证书,
  用密码保护，可用于导入浏览器或系统。
    """)
    wait_user()

def _verify_crl_integrity():
    s = SecureRevokedList()
    is_valid, msg = s.verify_integrity()
    print(f"\n  CRL完整性校验: {'[OK]' if is_valid else '[FAIL]'}")
    print(f"  {msg}")
    wait_user()


# ============================================================
# 模块D：系统管理
# ============================================================
def module_d_system():
    while True:
        print_header("模块D：系统管理")
        print("""
  [1] 创建数据备份
  [2] 查看备份列表
  [3] 证书到期检查
  [4] 配置状态检查
  [5] 查看审计日志
  [6] 审计日志完整性校验
  [7] 管理用户
  [8] 返回主菜单
        """)
        choice = input("  请输入选项 [1-8]: ").strip()

        if choice == "1":
            _do_backup()
        elif choice == "2":
            _list_backups()
        elif choice == "3":
            _do_expiry_check()
        elif choice == "4":
            CFG.show_config_status()
            wait_user()
        elif choice == "5":
            _view_audit_log()
        elif choice == "6":
            _verify_audit_integrity()
        elif choice == "7":
            _manage_users()
        elif choice == "8":
            break
        else:
            print("  [FAIL] 无效选项")
            wait_user()

def _do_backup():
    bm = BackupManager()
    label = get_input("备份标签(可选)", "")
    backup_name = bm.create_backup(label)
    print(f"\n  [OK] 备份创建成功: {backup_name}")
    audit_logger.log("BACKUP", get_current_username(), "CREATE",
                     backup_name, "SUCCESS", "创建系统备份", get_current_role())
    wait_user()

def _list_backups():
    bm = BackupManager()
    backups = bm.list_backups()
    if not backups:
        print("\n  [INFO] 没有备份记录")
        wait_user()
        return

    print(f"\n  备份列表(共{len(backups)}个):")
    for b in backups:
        size_kb = b["size"] / 1024
        print(f"  {b['file']} - {size_kb:.1f}KB - {b['modified'][:19]}")
    wait_user()

def _do_expiry_check():
    checker = CertExpiryChecker()
    scanner = checker.scan_certificates()
    if "error" in scanner:
        print(f"\n  [FAIL] {scanner['error']}")
        wait_user()
        return

    expired = scanner.get("expired", [])
    critical = scanner.get("critical", [])
    warning = scanner.get("warning", [])
    valid = scanner.get("valid", [])

    total = len(expired) + len(critical) + len(warning) + len(valid)
    print(f"\n  证书到期检查报告(共{total}张证书):")
    print(f"  已过期: {len(expired)} 张")
    print(f"  7天内到期: {len(critical)} 张")
    print(f"  30天内到期: {len(warning)} 张")
    print(f"  有效: {len(valid)} 张")

    if expired:
        print("\n  已过期证书:")
        for cert in expired:
            print(f"    {cert['name']} - 已过期{cert['overdue_days']}天")
    if critical:
        print("\n  7天内到期:")
        for cert in critical:
            print(f"    {cert['name']} - 剩余{cert['remaining_days']}天")
    wait_user()

def _view_audit_log():
    limit_str = input("  查询最近多少条记录(默认50): ").strip()
    limit = int(limit_str) if limit_str.isdigit() else 50

    event_type = input("  按事件类型过滤(留空不过滤): ").strip()
    username = input("  按用户过滤(留空不过滤): ").strip()

    results = audit_logger.query(
        event_type=event_type if event_type else None,
        username=username if username else None,
        limit=limit
    )

    if not results:
        print("\n  [INFO] 没有匹配的审计日志")
        wait_user()
        return

    print(f"\n  审计日志(最近{len(results)}条):")
    print("=" * 60)
    for entry in results:
        ts = entry.get("timestamp", "")[:19]
        et = entry.get("event_type", "")
        user = entry.get("username", "")
        detail = entry.get("detail", "")
        result = entry.get("result", "")
        r_mark = "[OK]" if result == "SUCCESS" else "[FAIL]"
        print(f"  {ts} {r_mark} {et} - {user}: {detail}")
    wait_user()

def _verify_audit_integrity():
    from audit import AuditLogger
    al = AuditLogger()
    is_valid, count, errors = al.verify_integrity()

    print(f"\n  审计日志完整性校验:")
    print(f"  检查条目: {count} 条")
    if is_valid:
        print(f"  [OK] 日志完整，未被篡改")
    else:
        print(f"  [FAIL] 发现 {len(errors)} 个问题:")
        for e in errors:
            print(f"    [FAIL] {e}")
    wait_user()

def _manage_users():
    try:
        require_permission(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        print(f"\n  [FAIL] {e}")
        wait_user()
        return

    um = UserManager()
    users = um.list_users()

    print(f"\n  用户列表(共{len(users)}人):")
    print("-" * 50)
    for u in users:
        role_cn = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                    "auditor": "审计员", "end_user": "终端用户"}
        print(f"  {u['username']} - {u['name']}({role_cn.get(u['role'], u['role'])}) "
              f"{'[已启用]' if u['is_active'] else '[已停用]'}")
    print("-" * 50)
    wait_user()


# ============================================================
# 主菜单
# ============================================================
def main():
    initialize_system()

    if not login_screen():
        sys.exit(1)

    current_user = auth_sm.get_current_user()
    print(f"\n  欢迎回来, {current_user['name']}!")

    while True:
        print_header("PKI演示系统 v2.0 - 主菜单")
        print(f"  当前用户: {current_user['name']}({current_user['role']})")
        print()

        # 根据角色显示可用菜单项
        all_menus = {
            "A": ("根CA管理", Permission.MANAGE_ROOT_CA),
            "B": ("用户证书管理", Permission.APPLY_CERT),
            "C": ("证书吊销管理", Permission.REVOKE_CERT),
            "D": ("系统管理", Permission.MANAGE_USERS),
            "Q": ("退出系统", None),
        }

        for key, (label, perm) in all_menus.items():
            if perm is None or auth_sm.check_permission(perm):
                print(f"  [{key}] {label}")

        choice = input("\n  请输入选项: ").strip().upper()

        if choice == "A" and auth_sm.check_permission(Permission.MANAGE_ROOT_CA):
            module_a_root_ca()
        elif choice == "B" and auth_sm.check_permission(Permission.APPLY_CERT):
            module_b_user_cert()
        elif choice == "C" and auth_sm.check_permission(Permission.REVOKE_CERT):
            module_c_crl()
        elif choice == "D":
            module_d_system()
        elif choice == "Q":
            audit_logger.log("LOGOUT", get_current_username(), "LOGOUT",
                             "system", "SUCCESS", "用户退出系统", get_current_role())
            print("\n  感谢使用PKI演示系统！再见！\n")
            sys.exit(0)
        else:
            print("  [FAIL] 无效选项或无权限")
            wait_user()


if __name__ == "__main__":
    main()
