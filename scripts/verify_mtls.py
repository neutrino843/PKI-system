"""
mTLS 验证脚本
测试场景：
  1. 无客户端证书访问 cert-login → 预期 401
  2. 有有效客户端证书访问 cert-login → 预期 200 + user info + session
  3. 用 session cookie 访问 /api/auth/me → 预期 200
  4. 无证书访问常规 login → 预期 200（传统登录不受影响）
"""
import urllib.request
import json
import ssl
import sys
from pathlib import Path

BASE = "https://localhost"
BASE_DIR = Path(__file__).parent.parent
EXPORT_DIR = BASE_DIR / "export"

passed = 0
failed = 0


def log_test(num, desc, result, detail=""):
    global passed, failed
    status = "[PASS]" if result else "[FAIL]"
    if result:
        passed += 1
    else:
        failed += 1
    print(f"  {status} 测试{num}: {desc}")
    if detail:
        print(f"       {detail}")


def make_request(method, path, data=None, cookies=None, client_cert=None):
    """HTTP 请求辅助函数"""
    url = f"{BASE}{path}"
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.data = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    if cookies:
        for c in cookies:
            req.add_header("Cookie", c.split(';')[0])

    # SSL 上下文配置
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 信任自签名服务器证书

    # 加载客户端证书（如果提供）
    if client_cert:
        # client_cert = (cert_chain_pem_path, key_pem_path)
        ctx.load_cert_chain(client_cert[0], keyfile=client_cert[1])

    try:
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        body = json.loads(resp.read())
        new_cookies = resp.headers.get_all('Set-Cookie') or []
        return body, new_cookies, resp.status
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            body_json = json.loads(body)
        except:
            body_json = {"error": body.decode()}
        return body_json, [], e.code
    except Exception as e:
        return {"error": str(e)}, [], 0


def check_p12_export():
    """检查 P12 文件是否存在"""
    p12_path = EXPORT_DIR / "admin_client.p12"
    key_path = EXPORT_DIR / "admin_client_key.pem"
    chain_path = EXPORT_DIR / "admin_client_chain.pem"
    return p12_path.exists(), key_path.exists(), chain_path.exists()


print("=" * 60)
print("  mTLS 验证脚本")
print("=" * 60)

# 预备检查：确认证书文件存在
print("\n[预备] 检查客户端证书文件...")
p12_ok, key_ok, chain_ok = check_p12_export()
print(f"  admin_client.p12:       {'[OK]' if p12_ok else '[缺失]'}")
print(f"  admin_client_key.pem:   {'[OK]' if key_ok else '[缺失]'}")
print(f"  admin_client_chain.pem: {'[OK]' if chain_ok else '[缺失]'}")
if not (key_ok and chain_ok):
    print("\n  [FAIL] 客户端证书文件缺失，请先运行 setup_mtls_full.py")
    sys.exit(1)

# 测试1: 无客户端证书访问 cert-login
print("\n[测试1] 无客户端证书 → POST /api/auth/cert-login")
body, cookies, status = make_request("POST", "/api/auth/cert-login",
                                     {"no": "data"})
expected = status in (400, 401, 403)
log_test(1, "预期返回 400/401/403",
         expected,
         f"实际状态码 {status}: {body.get('error', 'unknown')}")

# 测试2: 有客户端证书访问 cert-login
print("\n[测试2] 有客户端证书 → POST /api/auth/cert-login")
client_cert_path = EXPORT_DIR / "admin_client_chain.pem"
client_key_path = EXPORT_DIR / "admin_client_key.pem"
body, cookies, status = make_request(
    "POST", "/api/auth/cert-login",
    {},  # 无请求体
    client_cert=(str(client_cert_path), str(client_key_path))
)
success = status == 200 and "user" in body
log_test(2, f"预期返回 200 + user 信息",
         success,
         f"状态码 {status}, user={body.get('user', {}).get('name', 'N/A')}")
if success:
    print(f"       用户: {body['user']['name']} ({body['user']['roleName']})")

# 测试3: 用 cert-login 的 session cookie 访问 /api/auth/me
print("\n[测试3] cert-login cookie → GET /api/auth/me")
if cookies:
    body, _, status = make_request("GET", "/api/auth/me",
                                   cookies=cookies)
    success = status == 200 and body.get("name") == "系统管理员"
    log_test(3, f"预期返回 200 + 用户信息(系统管理员)",
             success,
             f"状态码 {status}, name={body.get('name', 'N/A')}")
else:
    log_test(3, "无 cookie 可用，跳过", False, "上一个测试未返回 set-cookie")

# 测试4: 无证书访问常规 login（传统密码登录）
print("\n[测试4] 无证书 → POST /api/auth/login (传统密码登录)")
body, cookies, status = make_request(
    "POST", "/api/auth/login",
    {"username": "admin", "password": "admin123"}
)
success = status == 200 and "user" in body
log_test(4, "预期返回 200 + 用户信息（传统登录不受影响）",
         success,
         f"状态码 {status}, user={body.get('user', {}).get('name', 'N/A')}")

# 汇总
print(f"\n{'=' * 60}")
total = passed + failed
if failed == 0:
    print(f"  全部通过! ({passed}/{total})")
else:
    print(f"  通过 {passed}/{total}, 失败 {failed}/{total}")
print(f"{'=' * 60}")
print(f"""
浏览器导入说明:
  文件:  {EXPORT_DIR / 'admin_client.p12'}
  密码:  admin_mtls_2024

  导入步骤:
    浏览器设置 → 隐私和安全 → 管理证书 → 个人 → 导入
    选择 admin_client.p12，输入密码 admin_mtls_2024

  注意:
    根CA证书 {BASE_DIR / 'pki_demo/certs/root_ca_cert.pem'}
    也需要导入到"受信任的根证书颁发机构"
""")
