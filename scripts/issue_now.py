"""签发已通过审核的CSR - 用于快速签发当前待签证书"""
import urllib.request, ssl, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE = "https://localhost"

import os

# 1. 登录admin（从环境变量读取密码）
_ADMIN_PWD = os.environ.get("PKI_ADMIN_PASSWORD", "admin123")
print("1. 登录admin...")
req = urllib.request.Request(f"{BASE}/api/auth/login",
    data=json.dumps({"username": "admin", "password": _ADMIN_PWD}).encode(),
    headers={"Content-Type": "application/json"})
resp = urllib.request.urlopen(req, timeout=10, context=ctx)
cookies = resp.headers.get_all('Set-Cookie')
data = json.loads(resp.read())
print(f"   用户: {data['user']['name']} ({data['user']['roleName']})")

# 2. 查询已通过待签发列表
print("\n2. 查看已通过待签发的CSR...")
req2 = urllib.request.Request(f"{BASE}/api/csr/approved")
for c in cookies:
    req2.add_header('Cookie', c.split(';')[0])
resp2 = urllib.request.urlopen(req2, timeout=10, context=ctx)
approved = json.loads(resp2.read())
print(f"   找到 {len(approved)} 个待签发:")
for a in approved:
    print(f"   - {a['id']} : {a['cn']} ({a['org']})")

# 3. 签发
if approved:
    print("\n3. 签发证书...")
    for a in approved:
        csr_id = a['id']
        req3 = urllib.request.Request(f"{BASE}/api/certificates/issue/{csr_id}", method="POST")
        for c in cookies:
            req3.add_header('Cookie', c.split(';')[0])
        try:
            resp3 = urllib.request.urlopen(req3, timeout=10, context=ctx)
            result = json.loads(resp3.read())
            print(f"   [OK] {csr_id}: {result.get('message', 'done')}")
        except urllib.request.HTTPError as e:
            print(f"   [FAIL] {csr_id}: {e.read().decode()}")
else:
    print("\n   [INFO] 没有待签发的CSR")

print("\n=== 完成 ===")
