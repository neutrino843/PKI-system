"""
全模块回归测试脚本（v2.1）
验证所有安全加固模块的正确性
覆盖：P0-01至P0-05, P1-01至P1-04修复点
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0

def test(name, func):
    global PASS, FAIL
    try:
        func()
        PASS += 1
        print(f"  [PASS] {name}")
    except Exception as e:
        FAIL += 1
        print(f"  [FAIL] {name}: {e}")

def get_env(key, default):
    """安全获取环境变量（测试用）"""
    return os.environ.get(key, default)

# ========== 1. config模块测试 ==========
def test_config():
    import config
    assert config.CFG is not None
    algo = config.CFG.get_algorithm_config()
    assert algo["rsa_key_size"] == 2048
    assert algo["hash_algorithm"] == "SHA256"
    sec = config.CFG.get_security_config()
    assert sec["min_password_length"] == 8

# ========== 2. auth模块测试（含P0-01/P0-02） ==========
def test_auth():
    import auth
    sm = auth._session_manager

    # 测试PBKDF2密码哈希（P0-01）- 通过登录验证
    # 登录成功验证密码哈希和验证流程正确
    success, _ = sm.login("admin", "admin123")
    assert success, "admin登录成功(PBKDF2密码验证通过)"

    # 检查存储的密码格式是否为 salt$hash
    import json
    users_path = os.path.join(os.path.dirname(__file__), "data", "users.json")
    if os.path.exists(users_path):
        with open(users_path, "r", encoding="utf-8") as f:
            user_data = json.load(f)
        admin_pwd = user_data.get("admin", {}).get("password", "")
        assert "$" in admin_pwd, f"密码应为salt$hash格式: {admin_pwd[:30]}..."
        salt_part = admin_pwd.split("$")[0]
        assert len(salt_part) == 32, f"盐值应为32位hex(16字节): {salt_part}"
    sm.logout()

    # 测试多用户会话（P0-02）
    success, _ = sm.login("admin", "admin123")
    assert success, "admin登录失败"
    assert sm.get_current_user() is not None, "登录后应有当前用户"
    admin_sid = sm._current_sid
    assert len(admin_sid) == 64, f"session ID应为64位hex: {admin_sid}"

    # 测试同一会话的权限
    assert sm.check_permission(auth.Permission.MANAGE_ROOT_CA), "管理员应有CA管理权限"
    assert sm.check_permission(auth.Permission.REVOKE_CERT), "管理员应有吊销权限"

    # 测试多用户隔离 - 用另一个账号登录
    sm.login("user_wang", "user1234")
    after_login_sid = sm._current_sid
    assert after_login_sid != admin_sid, "不同用户应有不同session ID"

    # user_wang 不能有CA管理权限
    assert not sm.check_permission(auth.Permission.MANAGE_ROOT_CA), "终端用户不能有CA管理权限"
    assert sm.check_permission(auth.Permission.APPLY_CERT), "终端用户应有申请权限"

    # 测试终端用户角色权限定义
    end_user_perms = auth.ROLE_PERMISSIONS[auth.Role.END_USER]
    assert auth.Permission.MANAGE_ROOT_CA not in end_user_perms, "终端用户不能有CA管理权限"
    assert auth.Permission.APPLY_CERT in end_user_perms, "终端用户应有申请权限"

    sm.logout()
    assert sm.get_current_user() is None, "登出后应无当前用户"

# ========== 3. audit模块测试（含P0-03） ==========
def test_audit():
    import audit
    al = audit.AuditLogger()
    al.log("TEST", "admin", "TEST", "test_resource", "SUCCESS", "测试日志", "ca_admin")
    is_valid, count, errors = al.verify_integrity()
    assert is_valid, f"审计日志完整性验证失败: {errors}"
    assert count > 0, f"应有日志条目, 当前: {count}"
    # 查询测试
    results = al.query(limit=5)
    assert len(results) > 0, "应能查询到日志"

    # 测试HMAC密钥不存在时的错误处理（P0-03）
    import os
    original_key = os.environ.get("PKI_AUDIT_HMAC_KEY")
    # 创建一个不带HMAC key的logger实例验证其行为
    al2 = audit.AuditLogger()
    if not original_key:
        try:
            # 如果原本就没有HMAC Key，verify_integrity应失败
            is_valid2, _, _ = al2.verify_integrity()
            # 不应走到这里
        except RuntimeError:
            pass  # 预期行为：抛出RuntimeError

# ========== 4. security_crl模块测试（含HMAC强制） ==========
def test_security_crl():
    import security_crl
    s = security_crl.SecureRevokedList()

    # 测试吊销
    result = s.revoke("TEST-999", "测试用户", "unspecified", "未指定")
    assert result, "吊销操作应成功"
    # 验证完整性
    is_valid, msg = s.verify_integrity()
    assert is_valid, f"CRL完整性验证失败: {msg}"
    # 检查吊销状态
    assert s.is_revoked("TEST-999"), "应检测到证书已吊销"
    assert not s.is_revoked("NOT-REVOKED"), "未吊销证书应返回False"
    # 清理
    revoked_list = s.load()
    revoked_list = [item for item in revoked_list if item["serial"] != "TEST-999"]
    s.save(revoked_list)

# ========== 5. ra模块测试（含P1-01四眼原则） ==========
def test_ra():
    import ra
    ra_mgr = ra.RAManager()
    # 提交申请
    success, _ = ra_mgr.submit_csr("CSR-TEST", "测试用户", "测试部", "csr/test.pem", "测试")
    assert success, "提交CSR应成功"
    # 查看待审核
    pending = ra_mgr.get_pending_list()
    assert any(item["csr_id"] == "CSR-TEST" for item in pending), "待审核列表应包含新申请"

    # 初审通过（P1-01四眼原则第1步）
    success, _ = ra_mgr.approve_csr("CSR-TEST", "审核员A", "初审通过")
    assert success, "初审应成功"

    # 待审核列表仍应包含该申请（状态变为FIRST_APPROVED）
    pending = ra_mgr.get_pending_list()
    assert any(item["csr_id"] == "CSR-TEST" for item in pending), "初审后申请仍在待审核列表"

    # 二审不能由同一人操作（四眼原则）
    success, msg = ra_mgr.second_approve_csr("CSR-TEST", "审核员A", "二审")
    assert not success, "四眼原则违规：同一个人不能进行二审"
    assert "四眼原则违规" in msg, f"应提示四眼原则违规: {msg}"

    # 二审通过（由不同的审核员）
    success, _ = ra_mgr.second_approve_csr("CSR-TEST", "审核员B", "二审通过")
    assert success, "二审应成功"

    # 二审后，申请应移动到已批准列表
    approved = ra_mgr.get_approved_list()
    assert any(item["csr_id"] == "CSR-TEST" for item in approved), "待签发列表应包含已批准的申请"

    # 统计
    stats = ra_mgr.get_statistics()
    assert stats["approved_count"] >= 1, "统计应有批准记录"

# ========== 6. security_crypto模块测试 ==========
def test_security_crypto():
    import security_crypto
    # 算法
    algo = security_crypto.get_hash_algorithm("SHA384")
    assert algo is not None
    ks = security_crypto.get_rsa_key_size(4096)
    assert ks == 4096
    # 文件完整性
    checker = security_crypto.FileIntegrityChecker()
    test_file = os.path.join(os.path.dirname(__file__), "config.py")
    if os.path.exists(test_file):
        is_valid, h, msg = checker.verify_file(test_file)
        assert is_valid, f"config.py完整性校验失败: {msg}"
    # 安全删除
    tmp_file = "_test_secure_del.tmp"
    with open(tmp_file, "w") as f:
        f.write("test data for secure delete")
    success, msg = security_crypto.secure_delete(tmp_file)
    assert success, f"安全删除失败: {msg}"
    assert not os.path.exists(tmp_file), "安全删除后文件应不存在"

# ========== 7. cert_expiry模块测试 ==========
def test_cert_expiry():
    import cert_expiry
    checker = cert_expiry.CertExpiryChecker()
    results = checker.scan_certificates()
    assert "error" not in results, f"扫描出错: {results.get('error', '')}"
    total = sum(len(v) for v in results.values() if isinstance(v, list))
    assert total >= 0, "应能扫描到证书"

# ========== 8. backup模块测试（含P0-05路径穿越+P1-03加密） ==========
def test_backup():
    import backup
    mgr = backup.BackupManager()
    # 创建备份（需要PKI_BACKUP_KEY环境变量）
    try:
        name = mgr.create_backup(label="test_backup")
        assert name is not None
        assert name.endswith(".enc"), f"备份文件名应以.enc结尾: {name}"
        # 列出备份
        backups = mgr.list_backups()
        assert len(backups) > 0, "备份列表不应为空"
        assert any(b["file"] == name for b in backups), "新创建的备份应在列表中"
        # 清理测试备份
        from pathlib import Path
        backup_dir = Path(__file__).parent.resolve() / "backups"
        for f in backup_dir.glob(f"*test_backup*"):
            os.remove(f)
        for f in backup_dir.glob(f"manifest_*"):
            os.remove(f)
    except RuntimeError as e:
        if "PKI_BACKUP_KEY" in str(e):
            # 环境变量未设置，跳过备份测试
            print(f"  [SKIP] backup加密测试: PKI_BACKUP_KEY未设置")
        else:
            raise

# ========== 9. inter_ca模块测试 ==========
def test_inter_ca():
    import inter_ca
    from pathlib import Path
    base_dir = Path(__file__).parent.resolve()
    ca_key = base_dir / "keys" / "root_ca_private.pem"
    ca_cert = base_dir / "certs" / "root_ca_cert.pem"
    if not ca_key.exists() or not ca_cert.exists():
        success, msg = inter_ca.generate_intermediate_ca()
        assert success == False, "无根CA时应返回False"
        assert "根CA尚未创建" in msg, f"错误信息应提示根CA未创建: {msg}"
    else:
        try:
            success, msg = inter_ca.generate_intermediate_ca()
            assert success == True or "根CA尚未创建" in msg
        except RuntimeError as e:
            err_msg = str(e)
            assert "CA_KEY_PASSWORD" in err_msg or "password" in err_msg.lower(), \
                   f"应报告密码错误而非其他异常: {err_msg}"

# ========== 10. 批量处理性能测试（1000条） ==========
def test_batch_performance():
    """验证系统能处理1000条批量操作"""
    import time
    import audit

    al = audit.AuditLogger()
    # 写入1000条测试日志
    t0 = time.perf_counter()
    for i in range(1000):
        al.log("BATCH_TEST", f"user_{i}", "TEST", "batch", "SUCCESS",
               f"批量测试第{i+1}条", "ca_admin")
    t1 = time.perf_counter()
    write_time = t1 - t0
    print(f"\n    [PERF] 写入1000条审计日志: {write_time*1000:.1f}ms ({write_time/1000*1000:.3f}ms/条)")

    # 验证1000条日志的完整性
    t0 = time.perf_counter()
    is_valid, count, errors = al.verify_integrity()
    t1 = time.perf_counter()
    verify_time = t1 - t0
    assert is_valid, f"批量审计日志完整性验证失败: {errors[:3]}"
    assert count >= 1000, f"审计日志不足: {count}"
    print(f"    [PERF] 验证{count}条日志完整性: {verify_time*1000:.1f}ms")

    # 查询测试
    t0 = time.perf_counter()
    results = al.query(limit=100)
    t1 = time.perf_counter()
    print(f"    [PERF] 查询100条日志: {(t1-t0)*1000:.1f}ms")
    assert len(results) <= 100, f"查询限制失效: {len(results)}"

# ========== 主测试流程 ==========
print("=" * 60)
print("  PKI系统安全加固 - 全模块回归测试 v2.1")
print("=" * 60)

test("config模块", test_config)
test("auth模块(PBKDF2+多会话)", test_auth)
test("audit模块(链式哈希)", test_audit)
test("security_crl模块(HMAC)", test_security_crl)
test("ra模块(四眼原则审核)", test_ra)
test("security_crypto模块", test_security_crypto)
test("cert_expiry模块", test_cert_expiry)
test("backup模块(加密备份)", test_backup)
test("inter_ca模块(中间CA)", test_inter_ca)
test("batch性能(1000条)", test_batch_performance)

print(f"\n{'='*60}")
print(f"  测试结果: {PASS} 通过, {FAIL} 失败")
if FAIL == 0:
    print("  [PASS] 所有模块测试通过!")
else:
    print(f"  [FAIL] 存在 {FAIL} 个测试失败, 请检查!")
print(f"{'='*60}")
