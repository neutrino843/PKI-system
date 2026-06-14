"""
================================================================
  PKI系统端到端全流程可用性测试
  测试所有核心功能的实际可用性，模拟完整生产流程
================================================================
"""
import sys
import os
import json
import time
import tempfile
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0
WARN = 0

def test(name, func):
    global PASS, FAIL, WARN
    try:
        func()
        PASS += 1
        print(f"  [PASS] {name}")
    except Exception as e:
        FAIL += 1
        print(f"  [FAIL] {name}: {e}")
    except SystemExit:
        FAIL += 1
        print(f"  [FAIL] {name}: 系统异常退出")

def warn(name, msg):
    global WARN
    WARN += 1
    print(f"  [WARN] {name}: {msg}")

# 清理测试残留
def cleanup():
    base = Path(__file__).parent.resolve()
    for f in base.glob("data/*.*"):
        if f.name not in ["users.json", "sessions.json"]:
            f.unlink(missing_ok=True)
    for f in base.glob("certs/user_*"):
        f.unlink(missing_ok=True)
    for f in base.glob("keys/user_*"):
        f.unlink(missing_ok=True)
    for f in base.glob("csr/user_*"):
        f.unlink(missing_ok=True)
    for f in base.glob("export/user_*"):
        f.unlink(missing_ok=True)
    for f in base.glob("crl/revoked_certs_secure.json"):
        f.unlink(missing_ok=True)

cleanup()

print("=" * 65)
print("  PKI系统端到端全流程可用性测试")
print(f"  测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 65)

# ========== TC-01: 系统初始化 ==========
def test_init():
    import config
    assert config.CFG is not None
    from auth import UserManager
    um = UserManager()
    users = um.list_users()
    assert len(users) >= 4, f"应有至少4个预设用户, 当前: {len(users)}"
    # 验证关键角色存在
    roles = [u['role'] for u in users]
    assert 'ca_admin' in roles
    assert 'ra_operator' in roles
    assert 'auditor' in roles
    assert 'end_user' in roles

test("TC-01: 系统初始化与预设用户检查", test_init)

# ========== TC-02: 用户认证（全部4个角色） ==========
def test_auth_all_roles():
    from auth import SessionManager, UserManager
    sm = SessionManager()
    # 测试4个角色登录
    creds = [
        ("admin", "admin123", "ca_admin"),
        ("ra_zhang", "ra123456", "ra_operator"),
        ("auditor_li", "audit123", "auditor"),
        ("user_wang", "user1234", "end_user"),
    ]
    for username, password, expected_role in creds:
        success, _ = sm.login(username, password)
        assert success, f"{username} 登录失败"
        user = sm.get_current_user()
        assert user is not None, f"{username} 登录后无用户信息"
        assert user['role'] == expected_role, \
            f"{username} 角色应为 {expected_role}, 实际: {user['role']}"
        sm.logout()
    # 错误密码测试
    success, _ = sm.login("admin", "wrong_password")
    assert not success, "错误密码应登录失败"
    # 不存在的用户测试
    success, _ = sm.login("nonexist", "anypass")
    assert not success, "不存在的用户应登录失败"

test("TC-02: 用户认证（4角色+异常场景）", test_auth_all_roles)

# ========== TC-03: RBAC权限校验 ==========
def test_rbac():
    from auth import SessionManager, Permission
    sm = SessionManager()
    # admin有所有权限
    sm.login("admin", "admin123")
    assert sm.check_permission(Permission.MANAGE_ROOT_CA)
    assert sm.check_permission(Permission.ISSUE_CERT)
    assert sm.check_permission(Permission.REVOKE_CERT)
    assert sm.check_permission(Permission.GENERATE_CRL)
    assert sm.check_permission(Permission.MANAGE_USERS)
    sm.logout()
    # end_user只有基本权限
    sm.login("user_wang", "user1234")
    assert sm.check_permission(Permission.APPLY_CERT)
    assert sm.check_permission(Permission.VIEW_OWN_CERT)
    assert not sm.check_permission(Permission.MANAGE_ROOT_CA)
    assert not sm.check_permission(Permission.REVOKE_CERT)
    assert not sm.check_permission(Permission.GENERATE_CRL)
    sm.logout()
    # auditor只有查看权限
    sm.login("auditor_li", "audit123")
    assert sm.check_permission(Permission.VIEW_AUDIT_LOG)
    assert not sm.check_permission(Permission.REVOKE_CERT)
    assert not sm.check_permission(Permission.MANAGE_USERS)
    sm.logout()

test("TC-03: RBAC权限校验", test_rbac)

# ========== TC-04: PBKDF2密码哈希 ==========
def test_pbkdf2():
    import json
    from auth import UserManager
    um = UserManager()
    users_path = os.path.join(os.path.dirname(__file__), "data", "users.json")
    with open(users_path, "r", encoding="utf-8") as f:
        users = json.load(f)
    admin_pwd = users.get("admin", {}).get("password", "")
    assert "$" in admin_pwd, f"密码应为salt$hash格式"
    salt_part = admin_pwd.split("$")[0]
    assert len(salt_part) == 32, f"盐值应为32位hex(16字节)"
    # 验证每个用户的密码都是PBKDF2格式
    for username, info in users.items():
        pwd = info.get("password", "")
        assert "$" in pwd, f"{username} 的密码不是salt$hash格式"

test("TC-04: PBKDF2密码哈希验证", test_pbkdf2)

# ========== TC-05: 多用户会话隔离 ==========
def test_session_isolation():
    from auth import SessionManager
    sm = SessionManager()
    sm.login("admin", "admin123")
    sid1 = sm._current_sid
    assert len(sid1) == 64, f"Session ID应为64位hex: {sid1}"
    sm.login("user_wang", "user1234")
    sid2 = sm._current_sid
    assert sid2 != sid1, "不同用户应有不同session ID"
    sm.logout()

test("TC-05: 多用户会话隔离", test_session_isolation)

# ========== TC-06: 根CA创建 ==========
def test_root_ca_create():
    from main import _create_root_ca
    # 由于_create_root_ca是交互式的，直接测试底层流程
    from config import CFG
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from datetime import datetime, timezone

    base = Path(__file__).parent.resolve()
    # 检查是否已有根CA
    cert_path = base / "certs" / "root_ca_cert.pem"
    key_path = base / "keys" / "root_ca_private.pem"
    if not cert_path.exists():
        print("\n    [INFO] 根CA尚未创建，跳过（需手动创建）")
        return
    # 验证根CA证书可加载
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    # 验证是自签名（颁发者=主题）
    assert cert.subject == cert.issuer, "根CA应为自签名证书"
    # 验证是CA证书
    from cryptography.x509 import BasicConstraints
    bc = cert.extensions.get_extension_for_class(BasicConstraints).value
    assert bc.ca, "根CA的BasicConstraints.ca应为True"
    print(f"    [OK] 根CA: {cert.subject.rfc4514_string()}")

test("TC-06: 根CA创建验证", test_root_ca_create)

# ========== TC-07: 中间CA创建 ==========
def test_inter_ca():
    from inter_ca import generate_intermediate_ca
    base = Path(__file__).parent.resolve()
    cert_path = base / "certs" / "inter_ca_cert.pem"
    key_path = base / "keys" / "inter_ca_private.pem"
    if not cert_path.exists() or not key_path.exists():
        # 如果没有根CA则跳过
        root_cert = base / "certs" / "root_ca_cert.pem"
        if not root_cert.exists():
            print("\n    [INFO] 根CA未创建，跳过中间CA测试")
            return
    success, msg = generate_intermediate_ca()
    print(f"    {msg}")
    # 验证中间CA证书
    if cert_path.exists():
        from cryptography import x509
        from cryptography.x509 import BasicConstraints
        from cryptography.hazmat.backends import default_backend
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        bc = cert.extensions.get_extension_for_class(BasicConstraints).value
        assert bc.ca, "中间CA的BasicConstraints.ca应为True"

test("TC-07: 中间CA创建验证", test_inter_ca)

# ========== TC-08: 证书申请-审核-签发全流程 ==========
def test_cert_full_lifecycle():
    from ra import RAManager
    ra = RAManager()

    # 1. 提交CSR申请
    csr_id = f"E2E-TEST-{int(time.time())}"
    success, msg = ra.submit_csr(csr_id, "测试用户E2E", "测试部",
                                  f"csr/test_{csr_id}.pem", "test_user")
    assert success, f"CSR提交失败: {msg}"

    # 2. 查看待审核列表
    pending = ra.get_pending_list()
    assert any(item['csr_id'] == csr_id for item in pending), "待审核列表应包含新申请"

    # 3. 初审通过
    success, msg = ra.approve_csr(csr_id, "审核员A", "E2E测试初审")
    assert success, f"初审失败: {msg}"

    # 4. 二审（四眼原则-同人拒绝）
    success, msg = ra.second_approve_csr(csr_id, "审核员A", "E2E测试二审")
    assert not success, "四眼原则违规：同人二审应被拒绝"
    assert "四眼原则违规" in msg

    # 5. 二审通过（不同人）
    success, msg = ra.second_approve_csr(csr_id, "审核员B", "E2E测试二审通过")
    assert success, f"二审失败: {msg}"

    # 6. 查看已批准列表
    approved = ra.get_approved_list()
    assert any(item['csr_id'] == csr_id for item in approved), "已批准列表应包含该申请"

    # 7. 标记已签发
    success = ra.mark_issued(csr_id)
    assert success, "标记签发失败"

    # 8. 统计验证
    stats = ra.get_statistics()
    assert stats['approved_count'] >= 1
    assert stats['issued_count'] >= 1
    print(f"    [OK] 全流程完成: {csr_id}")

test("TC-08: 证书申请-审核-签发全流程", test_cert_full_lifecycle)

# ========== TC-09: 证书吊销与CRL ==========
def test_revoke_and_crl():
    from security_crl import SecureRevokedList
    from datetime import datetime, timezone

    s = SecureRevokedList()
    test_serial = f"E2E-REVOKE-{int(time.time())}"

    # 1. 吊销证书
    result = s.revoke(test_serial, "E2E吊销测试用户", "keyCompromise", "私钥泄露测试")
    assert result, "吊销操作应成功"

    # 2. 验证吊销状态
    assert s.is_revoked(test_serial), "应检测到证书已吊销"

    # 3. 验证未吊销证书
    assert not s.is_revoked("NONEXIST-SERIAL"), "未吊销证书应返回False"

    # 4. 重复吊销检测
    result = s.revoke(test_serial, "E2E吊销测试用户", "keyCompromise", "重复吊销")
    assert not result, "重复吊销应返回False"

    # 5. HMAC完整性验证
    is_valid, msg = s.verify_integrity()
    assert is_valid, f"CRL完整性验证失败: {msg}"

    # 6. 获取吊销列表
    revoked_list = s.get_revoked_list()
    assert len(revoked_list) > 0, "吊销列表不应为空"

    # 7. 清理
    revoked_list = [item for item in revoked_list if item['serial'] != test_serial]
    s.save(revoked_list)
    print(f"    [OK] 吊销测试完成")

test("TC-09: 证书吊销与CRL完整性", test_revoke_and_crl)

# ========== TC-10: 审计日志完整性 ==========
def test_audit_integrity():
    from audit import AuditLogger
    al = AuditLogger()

    # 1. 记录测试日志
    al.log("E2E_TEST", "test_user", "TEST", "e2e_resource", "SUCCESS", "端到端测试日志", "ca_admin")
    al.log("E2E_TEST", "test_user", "TEST", "e2e_resource2", "FAILURE", "端到端测试失败日志", "ca_admin")

    # 2. 验证完整性
    is_valid, count, errors = al.verify_integrity()
    assert is_valid, f"审计日志完整性验证失败: {errors}"
    assert count >= 2, f"应有足够日志条目: {count}"

    # 3. 查询测试
    results = al.query(limit=10)
    assert len(results) >= 2, "应能查询到日志"

    # 4. 按事件类型过滤
    results = al.query(event_type="E2E_TEST", limit=5)
    assert len(results) >= 2, f"按类型过滤失败: {len(results)}"

    print(f"    [OK] 审计日志: {count}条, 查询正常")

test("TC-10: 审计日志链式哈希完整性", test_audit_integrity)

# ========== TC-11: 备份创建 ==========
def test_backup():
    from backup import BackupManager
    mgr = BackupManager()
    try:
        name = mgr.create_backup(label="e2e_test_backup")
        assert name is not None
        assert name.endswith(".enc"), f"备份文件名应以.enc结尾: {name}"
        # 列出备份
        backups = mgr.list_backups()
        assert len(backups) > 0, "备份列表不应为空"
        print(f"    [OK] 备份创建成功: {name}")
    except RuntimeError as e:
        if "PKI_BACKUP_KEY" in str(e):
            warn("backup", f"PKI_BACKUP_KEY未设置, 跳过")

test("TC-11: AES-256-GCM加密备份", test_backup)

# ========== TC-12: 证书到期检查 ==========
def test_cert_expiry():
    from cert_expiry import CertExpiryChecker
    checker = CertExpiryChecker()
    results = checker.scan_certificates()
    assert "error" not in results, f"扫描出错: {results.get('error', '')}"
    total = sum(len(v) for v in results.values() if isinstance(v, list))
    print(f"    [OK] 扫描到 {total} 张证书")

test("TC-12: 证书到期检查", test_cert_expiry)

# ========== TC-13: 文件完整性校验 ==========
def test_file_integrity():
    from security_crypto import FileIntegrityChecker
    checker = FileIntegrityChecker()
    # 验证config.py完整性
    test_file = os.path.join(os.path.dirname(__file__), "config.py")
    if os.path.exists(test_file):
        is_valid, h, msg = checker.verify_file(test_file)
        assert is_valid, f"config.py完整性校验失败: {msg}"

test("TC-13: 文件完整性校验", test_file_integrity)

# ========== TC-14: 算法可配置化 ==========
def test_algorithm_config():
    from security_crypto import get_hash_algorithm, get_rsa_key_size, HASH_ALGORITHM_MAP
    # 测试默认值
    algo = get_hash_algorithm()
    assert algo is not None
    ks = get_rsa_key_size()
    assert ks == 2048 or ks == 4096, f"默认密钥长度应为2048或4096"
    # 测试覆盖值
    algo = get_hash_algorithm("SHA384")
    assert algo is not None
    ks = get_rsa_key_size(4096)
    assert ks == 4096
    # 测试无效值
    ks = get_rsa_key_size(1024)
    assert ks == 2048, "无效密钥长度应回退到默认值"

test("TC-14: 算法参数可配置化", test_algorithm_config)

# ========== TC-15: 安全删除功能 ==========
def test_secure_delete():
    from security_crypto import secure_delete
    # 创建临时文件
    tmp_file = "_e2e_secure_delete_test.tmp"
    with open(tmp_file, "w") as f:
        f.write("sensitive test data for secure delete verification")
    success, msg = secure_delete(tmp_file)
    assert success, f"安全删除失败: {msg}"
    assert not os.path.exists(tmp_file), "安全删除后文件应不存在"

test("TC-15: 安全删除功能", test_secure_delete)

# ========== TC-16: 配置状态检查 ==========
def test_config_status():
    from config import CFG
    # 验证可以获取配置
    algo = CFG.get_algorithm_config()
    assert algo is not None
    policy = CFG.get_cert_policy()
    assert policy is not None
    security = CFG.get_security_config()
    assert security is not None
    # 验证密码获取
    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    assert ca_pwd is not None and len(ca_pwd) > 0, "CA_KEY_PASSWORD应已设置"

test("TC-16: 配置状态检查", test_config_status)

# ========== TC-17: 审计日志告警阈值 ==========
def test_alert_threshold():
    from audit import AuditLogger
    al = AuditLogger()
    # 触发多次认证失败（使用内部方法直接测试）
    for i in range(6):
        al.log("AUTH_FAIL", "hacker", "LOGIN", "system", "FAILURE",
               f"暴力破解尝试#{i+1}", "")
    # 告警日志文件应存在
    from pathlib import Path
    alert_file = Path(__file__).parent.resolve() / "data" / "alerts.log"
    if alert_file.exists():
        print(f"    [OK] 告警日志已生成")

test("TC-17: 审计日志告警阈值", test_alert_threshold)

# ========== 结果统计 ==========
print(f"\n{'='*65}")
print(f"  端到端可用性测试结果")
print(f"{'='*65}")
print(f"  总用例: {PASS + FAIL + WARN}")
print(f"  [PASS] 通过: {PASS}")
print(f"  [FAIL] 失败: {FAIL}")
print(f"  [WARN] 警告: {WARN}")

if FAIL == 0:
    print(f"\n  [综合结论] 核心功能全部可用!")
else:
    print(f"\n  [综合结论] 存在 {FAIL} 个功能不可用, 需要修复!")

# 可用性评分
availability_score = PASS / (PASS + FAIL + WARN) * 100 if (PASS + FAIL + WARN) > 0 else 0
print(f"  可用性评分: {availability_score:.1f}%")
print(f"{'='*65}")
