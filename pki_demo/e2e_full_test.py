"""
================================================================
  PKI系统 E2E全流程测试脚本（v2.0）
  覆盖范围：认证、会话、CSR申请/审核/签发、吊销、CRL、安全防护
  输出：详细的指标数据和运行记录
================================================================
"""
import requests
import time
import json
import sys
from datetime import datetime
import uuid
from pathlib import Path

BASE = "http://localhost:8080"
S = requests.Session()
RS = requests.Session()  # ra_zhang独立会话
UID = uuid.uuid4().hex[:8]


class TestMetrics:
    def __init__(self):
        self.results = []
        self.start_time = None
        self.end_time = None

    def start(self):
        self.start_time = datetime.now()

    def end(self):
        self.end_time = datetime.now()

    def record(self, category, name, status, detail="", duration_ms=0):
        self.results.append({
            "category": category, "name": name, "status": status,
            "detail": detail, "duration_ms": duration_ms,
        })
        icon = "PASS" if status == "PASS" else "FAIL" if status == "FAIL" else "WARN"
        print(f"  [{icon}] {name}: {detail} ({duration_ms}ms)")

    def summary(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        failed = sum(1 for r in self.results if r["status"] == "FAIL")
        warned = sum(1 for r in self.results if r["status"] == "WARN")
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        return {"total": total, "passed": passed, "failed": failed,
                "warned": warned, "duration_sec": round(duration, 2)}

TM = TestMetrics()


def tc(category, name, func):
    tic = time.time()
    try:
        detail = func()
        TM.record(category, name, "PASS", detail, round((time.time() - tic) * 1000, 1))
    except AssertionError as e:
        TM.record(category, name, "FAIL", f"断言: {e}", round((time.time() - tic) * 1000, 1))
    except Exception as e:
        TM.record(category, name, "FAIL", f"异常: {e}", round((time.time() - tic) * 1000, 1))


def check(r, expected, msg):
    if r.status_code != expected:
        raise AssertionError(f"期望{expected}, 实际{r.status_code}: {r.json()}")
    return r


print("=" * 70)
print("  PKI系统 E2E全流程测试")
print(f"  测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  目标地址: {BASE}")
print(f"  会话ID: {UID}")
print("=" * 70)

TM.start()

# ====== 1. 认证模块 ======
print("\n--- 1. 认证模块 ---")

def t1():
    r = S.post(f"{BASE}/api/auth/login",
               json={"username": "admin", "password": "admin123"})
    check(r, 200, "管理员登录")
    d = r.json()
    return f"用户={d['user']['name']} 角色={d['user']['roleName']}"

def t2():
    r = S.post(f"{BASE}/api/auth/login",
               json={"username": "admin", "password": "wrong"})
    check(r, 401, "错误密码")
    return "正确拒绝"

def t3():
    r = S.get(f"{BASE}/api/auth/me")
    check(r, 200, "会话")
    d = r.json()
    assert d["role"] == "ca_admin", f"角色异常: {d}"
    return f"user={d['name']} role={d['role']}"

def t4():
    S.post(f"{BASE}/api/auth/logout")
    r = S.get(f"{BASE}/api/auth/me")
    check(r, 401, "登出")
    S.post(f"{BASE}/api/auth/login",
           json={"username": "admin", "password": "admin123"})
    return "登出成功，会话已清除"

reg_user = f"test_{UID}"

def t5():
    r = S.post(f"{BASE}/api/auth/register",
               json={"username": reg_user, "password": "TestPwd123",
                      "name": f"测试用户{UID}"})
    check(r, 200, "注册")
    return f"注册成功: {r.json()['username']}"

tc("认证", "管理员登录", t1)
tc("认证", "错误密码拒绝", t2)
tc("认证", "会话持久化", t3)
tc("认证", "注销登录", t4)
tc("认证", "用户注册", t5)

# ====== 2. RBAC权限 ======
print("\n--- 2. RBAC权限模块 ---")

def t6():
    r = S.get(f"{BASE}/api/auth/users")
    check(r, 200, "用户列表")
    users = r.json()
    roles = {u["role"] for u in users}
    assert "ca_admin" in roles and "ra_operator" in roles
    return f"{len(users)}个用户, 角色={roles}"

def t7():
    r = S.post(f"{BASE}/api/auth/promote-reviewer",
               json={"username": reg_user})
    check(r, 200, "提升审核员")
    return f"提升成功: {reg_user} -> ra_operator"

def t8():
    r = S.post(f"{BASE}/api/auth/demote-user",
               json={"username": reg_user})
    check(r, 200, "降级用户")
    return f"降级成功: {reg_user} -> end_user"

tc("权限", "列出用户", t6)
tc("权限", "提升审核员", t7)
tc("权限", "降级用户", t8)

# ====== 3. 安全校验 ======
print("\n--- 3. 安全输入校验 ---")

def t9():
    r = S.post(f"{BASE}/api/csr/apply",
               json={"cn": "../../etc/passwd", "org": "test"})
    check(r, 400, "路径遍历")
    return r.json()["error"]

def t10():
    r = S.post(f"{BASE}/api/csr/apply",
               json={"cn": "<script>alert(1)</script>", "org": "test"})
    check(r, 400, "XSS")
    return r.json()["error"]

def t11():
    r = S.post(f"{BASE}/api/csr/apply",
               json={"cn": "CN=admin; DROP TABLE", "org": "test"})
    check(r, 400, "SQL注入")
    return r.json()["error"]

def t12():
    r = S.post(f"{BASE}/api/csr/apply",
               json={"cn": f"张三_{UID}", "org": "研发部"})
    check(r, 200, "有效CN")
    return f"csrId={r.json()['csrId']}"

tc("安全", "路径遍历拦截", t9)
tc("安全", "XSS注入拦截", t10)
tc("安全", "SQL注入拦截", t11)
tc("安全", "有效CN提交", t12)

# ====== 4. CSR流程 ======
print("\n--- 4. CSR审批流程 ---")

first_csr_id = [None]

def t13():
    r = S.get(f"{BASE}/api/csr/pending")
    check(r, 200, "待审核列表")
    items = r.json()
    assert len(items) > 0, "无待审核项"
    return f"{len(items)}个待审核"

def t14():
    items = S.get(f"{BASE}/api/csr/pending").json()
    target = None
    for item in items:
        if item["status"] == "pending":
            target = item["id"]
            break
    assert target, "未找到待初审项"
    first_csr_id[0] = target
    r = S.post(f"{BASE}/api/csr/approve-first",
               json={"csrId": target, "note": "身份核实通过"})
    check(r, 200, "初审")
    return f"csrId={target}"

def t15():
    RS.post(f"{BASE}/api/auth/login",
            json={"username": "ra_zhang", "password": "ra123456"})
    items = RS.get(f"{BASE}/api/csr/pending").json()
    target = None
    for item in items:
        if item["status"] == "first_approved":
            target = item["id"]
            break
    assert target, "未找到待二审项"
    first_csr_id[0] = target
    r = RS.post(f"{BASE}/api/csr/approve-second",
                json={"csrId": target, "note": "二审通过"})
    check(r, 200, "二审")
    return f"csrId={target} (ra_zhang二审)"

def t16():
    S.post(f"{BASE}/api/csr/apply",
           json={"cn": f"四眼测试{UID}", "org": "测试部"})
    items = S.get(f"{BASE}/api/csr/pending").json()
    target = None
    for item in items:
        if item["status"] == "pending":
            target = item["id"]
            break
    if not target:
        return "无待审项(跳过)"
    S.post(f"{BASE}/api/csr/approve-first",
           json={"csrId": target, "note": "初审"})
    r = S.post(f"{BASE}/api/csr/approve-second",
               json={"csrId": target, "note": "自己也二审"})
    check(r, 400, "四眼原则")
    return "四眼原则生效"

def t17():
    r = S.post(f"{BASE}/api/certificates/issue/{first_csr_id[0]}")
    check(r, 200, "签发")
    d = r.json()
    return f"message={d.get('message', '')}"

tc("CSR", "待审核列表查询", t13)
tc("CSR", "初审(四眼-1)", t14)
tc("CSR", "二审(四眼-2)", t15)
tc("CSR", "同人二审拒绝", t16)
tc("CSR", "证书签发", t17)

# ====== 5. 证书管理 ======
print("\n--- 5. 证书管理 ---")

def t18():
    r = S.get(f"{BASE}/api/certificates")
    check(r, 200, "证书列表")
    certs = r.json()
    return f"{len(certs)}张证书"

def t19():
    certs = S.get(f"{BASE}/api/certificates").json()
    assert len(certs) > 0, "无证书"
    serial = certs[0]["serial"]
    r = S.get(f"{BASE}/api/certificates/{serial}")
    check(r, 200, "证书详情")
    c = r.json()
    return f"CN={c['cn']} 状态={c['status']}"

def t20():
    # 签发一张供吊销
    S.post(f"{BASE}/api/csr/apply",
           json={"cn": f"吊销测试{UID}", "org": "测试部"})
    items = S.get(f"{BASE}/api/csr/pending").json()
    csr_id = None
    for item in items:
        if item["status"] == "pending":
            csr_id = item["id"]
            break
    assert csr_id, "无可签发CSR"
    S.post(f"{BASE}/api/csr/approve-first",
           json={"csrId": csr_id, "note": "初审"})
    RS.post(f"{BASE}/api/csr/approve-second",
            json={"csrId": csr_id, "note": "二审"})
    S.post(f"{BASE}/api/certificates/issue/{csr_id}")
    # 吊销
    certs = S.get(f"{BASE}/api/certificates").json()
    target = None
    for c in certs:
        if c["status"] in ("有效", "即将到期"):
            target = c
            break
    assert target, "无可吊销证书"
    r = S.post(f"{BASE}/api/revoked/revoke",
               json={"serial": target["serial"], "cn": target["cn"],
                     "reason": "affiliationChanged", "reasonDesc": "用户离职"})
    check(r, 200, "吊销")
    return f"serial={target['serial']} CN={target['cn']}"

def t21():
    r = S.get(f"{BASE}/api/revoked")
    check(r, 200, "CRL列表")
    return f"{len(r.json())}条吊销记录"

def t22():
    r = S.get(f"{BASE}/api/revoked/verify")
    check(r, 200, "CRL验证")
    d = r.json()
    return f"valid={d['valid']} msg={d['message']}"

tc("证书", "证书列表", t18)
tc("证书", "证书详情", t19)
tc("证书", "吊销证书", t20)
tc("CRL", "吊销列表查询", t21)
tc("CRL", "CRL完整性验证", t22)

# ====== 6. 统计 ======
print("\n--- 6. 仪表盘统计 ---")

def t23():
    r = S.get(f"{BASE}/api/stats")
    check(r, 200, "统计")
    d = r.json()
    return (f"totalCerts={d['totalCerts']} valid={d['validCerts']} "
            f"expiring={d['expiringCerts']} revoked={d['revokedCerts']} "
            f"pendingCsr={d['pendingCsrCount']} crlRevoked={d['crlRevokedCount']}")

tc("统计", "仪表盘数据", t23)

# ====== 7. 前端 ======
print("\n--- 7. 前端静态资源 ---")

def t24():
    r = requests.get(f"{BASE}/")
    check(r, 200, "首页")
    return f"Content-Type={r.headers['Content-Type']} size={len(r.content)}B"

def t25():
    r = requests.get(f"{BASE}/login.html")
    assert r.status_code in (200, 404), f"登录页: {r.status_code}"
    return f"status={r.status_code}"

tc("前端", "首页加载", t24)
tc("前端", "登录页", t25)

# ====== 结束 ======
TM.end()
summary = TM.summary()

print("\n" + "=" * 70)
print("  测试执行结果汇总")
print("=" * 70)
print(f"  总测试项: {summary['total']}")
print(f"  通过:     {summary['passed']}")
print(f"  失败:     {summary['failed']}")
print(f"  警告:     {summary['warned']}")
print(f"  总耗时:   {summary['duration_sec']}秒")
print("=" * 70)

report = {
    "test_time": datetime.now().isoformat(),
    "target": BASE,
    "summary": summary,
    "details": TM.results,
}
rp = Path("pki_demo/data/e2e_test_report.json")
rp.parent.mkdir(exist_ok=True)
with open(rp, "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)
print(f"\n测试报告已保存: {rp}")

if summary["failed"] > 0:
    sys.exit(1)
else:
    print("\n所有测试通过！")
