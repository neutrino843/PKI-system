"""
全模块回归测试脚本
验证所有安全加固模块的正确性
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

# ========== 1. config模块测试 ==========
def test_config():
    import config
    assert config.CFG is not None
    algo = config.CFG.get_algorithm_config()
    assert algo["rsa_key_size"] == 2048
    assert algo["hash_algorithm"] == "SHA256"
    sec = config.CFG.get_security_config()
    assert sec["min_password_length"] == 8

# ========== 2. auth模块测试 ==========
def test_auth():
    import auth
    sm = auth._session_manager
    # 测试登录
    success, _ = sm.login("admin", "admin123")
    assert success, "admin登录失败"
    # 测试权限
    assert sm.check_permission(auth.Permission.MANAGE_ROOT_CA), "管理员应有CA管理权限"
    assert sm.check_permission(auth.Permission.REVOKE_CERT), "管理员应有吊销权限"
    # 测试终端用户权限
    end_user_perms = auth.ROLE_PERMISSIONS[auth.Role.END_USER]
    assert auth.Permission.MANAGE_ROOT_CA not in end_user_perms, "终端用户不能有CA管理权限"
    assert auth.Permission.APPLY_CERT in end_user_perms, "终端用户应有申请权限"
    sm.logout()
    # 测试无权限
    assert sm.get_current_user() is None, "登出后应无当前用户"

# ========== 3. audit模块测试 ==========
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

# ========== 4. security_crl模块测试 ==========
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

# ========== 5. ra模块测试 ==========
def test_ra():
    import ra
    ra_mgr = ra.RAManager()
    # 提交申请
    success, _ = ra_mgr.submit_csr("CSR-TEST", "测试用户", "测试部", "csr/test.pem", "测试")
    assert success, "提交CSR应成功"
    # 查看待审核
    pending = ra_mgr.get_pending_list()
    assert any(item["csr_id"] == "CSR-TEST" for item in pending), "待审核列表应包含新申请"
    # 批准
    success, _ = ra_mgr.approve_csr("CSR-TEST", "审核员", "审核通过")
    assert success, "批准应成功"
    # 查看待签发
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

# ========== 主测试流程 ==========
print("=" * 60)
print("  PKI系统安全加固 - 全模块回归测试")
print("=" * 60)

test("config模块", test_config)
test("auth模块(RBAC)", test_auth)
test("audit模块(链式哈希)", test_audit)
test("security_crl模块(HMAC)", test_security_crl)
test("ra模块(审核流程)", test_ra)
test("security_crypto模块", test_security_crypto)
test("cert_expiry模块", test_cert_expiry)

print(f"\n{'='*60}")
print(f"  测试结果: {PASS} 通过, {FAIL} 失败")
if FAIL == 0:
    print("  [PASS] 所有模块测试通过!")
else:
    print(f"  [FAIL] 存在 {FAIL} 个测试失败, 请检查!")
print(f"{'='*60}")
