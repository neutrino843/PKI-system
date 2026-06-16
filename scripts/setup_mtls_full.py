"""
完整mTLS客户端证书设置流程
1. 登录admin → 申请客户端证书
2. admin初审通过
3. ra_zhang二审通过
4. admin签发证书
5. 导出PKCS#12供浏览器使用
"""
import urllib.request, ssl, json, sys
from pathlib import Path
from datetime import datetime

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE = "https://localhost"
BASE_DIR = Path(__file__).parent.parent
EXPORT_DIR = BASE_DIR / "export"
EXPORT_DIR.mkdir(exist_ok=True)

def api(method, path, data=None, cookies=None):
    url = f"{BASE}{path}"
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.data = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    if cookies:
        for c in cookies:
            req.add_header("Cookie", c.split(';')[0])
    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
    body = json.loads(resp.read())
    new_cookies = resp.headers.get_all('Set-Cookie') or []
    return body, new_cookies

print("=" * 60)
print("  mTLS 客户端证书 -- 全自动设置")
print("=" * 60)

# 1. 登录admin
print("\n[1/6] 登录admin...")
resp, admin_cookies = api("POST", "/api/auth/login",
                          {"username": "admin", "password": "admin123"})
print(f"   OK - {resp['user']['name']} ({resp['user']['roleName']})")

# 2. 提交客户端证书申请
print("\n[2/6] 提交客户端证书申请 (CN=admin)...")
resp, _ = api("POST", "/api/csr/apply",
              {"cn": "admin", "org": "PKI管理系统"},
              admin_cookies)
csr_id = resp['csrId']
key_path = resp['keyPath']
print(f"   OK - CSR: {csr_id}")
print(f"   私钥: {key_path}")

# 3. 初审 (admin作为CA管理员有权审批)
print(f"\n[3/6] 初审通过 ({csr_id})...")
resp, _ = api("POST", "/api/csr/approve-first",
              {"csrId": csr_id, "note": "mTLS客户端证书-初审"},
              admin_cookies)
print(f"   OK - {resp['message']}")

# 4. 登录ra_zhang进行二审
print(f"\n[4/6] 二审通过...")
resp, ra_cookies = api("POST", "/api/auth/login",
                       {"username": "ra_zhang", "password": "ra123456"})
print(f"   OK - {resp['user']['name']} ({resp['user']['roleName']})")
resp, _ = api("POST", "/api/csr/approve-second",
              {"csrId": csr_id, "note": "mTLS客户端证书-二审"},
              ra_cookies)
print(f"   OK - {resp['message']}")

# 5. 签发证书
print(f"\n[5/6] admin签发证书...")
resp, admin_cookies = api("POST", "/api/auth/login",
                          {"username": "admin", "password": "admin123"})
resp, _ = api("POST", f"/api/certificates/issue/{csr_id}",
              {"extraSans": [], "extraIps": []},
              admin_cookies)
print(f"   OK - {resp['message']}")

# 6. 直接用crypto库导出PKCS#12（不依赖后端API的serial查找）
print(f"\n[6/6] 导出PKCS#12客户端证书...")
p12_pwd = _P12_PWD

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509.oid import NameOID

# 按修改时间找到最新签发的用户证书
certs_dir = BASE_DIR / "pki_demo" / "certs"
keys_dir = BASE_DIR / "pki_demo" / "keys"
cert_files = sorted(certs_dir.glob("user_*_cert.pem"),
                    key=lambda f: f.stat().st_mtime, reverse=True)

if not cert_files:
    print("   FAIL: 未找到已签发的用户证书文件")
    sys.exit(1)

cert_path = cert_files[0]
# 从文件名提取tag: user_{tag}_cert.pem
stem = cert_path.stem  # user_xxx_cert
# 去掉 user_ 前缀和 _cert 后缀
tag = stem[5:-5]  # len("user_")=5, len("_cert")=5
key_path = keys_dir / f"user_{tag}_private.pem"

print(f"   找到证书: {cert_path.name}")
print(f"   对应私钥: {key_path.name}")

# 加载用户证书
with open(cert_path, "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())
cn = user_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
serial_hex = format(user_cert.serial_number, 'x')
print(f"   CN: {cn}")
print(f"   序列号: {serial_hex}")

# 加载用户私钥
key_pwd = b"user_pwd"
with open(key_path, "rb") as f:
    user_key = serialization.load_pem_private_key(f.read(), password=key_pwd)

# 加载CA链
with open(BASE_DIR / "pki_demo/certs/inter_ca_cert.pem", "rb") as f:
    inter_ca = x509.load_pem_x509_certificate(f.read())
with open(BASE_DIR / "pki_demo/certs/root_ca_cert.pem", "rb") as f:
    root_ca = x509.load_pem_x509_certificate(f.read())

# 导出PKCS#12
p12_data = serialize_key_and_certificates(
    name=b"admin@PKI",
    key=user_key,
    cert=user_cert,
    cas=[inter_ca, root_ca],
    encryption_algorithm=serialization.BestAvailableEncryption(p12_pwd.encode())
)

p12_path = EXPORT_DIR / "admin_client.p12"
with open(p12_path, "wb") as f:
    f.write(p12_data)

# 也备份私钥PEM（用于验证）
key_pem_path = EXPORT_DIR / "admin_client_key.pem"
with open(key_pem_path, "wb") as f:
    f.write(user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 也导出证书PEM链（用于Nginx验证）
chain_pem_path = EXPORT_DIR / "admin_client_chain.pem"
with open(chain_pem_path, "wb") as f:
    f.write(user_cert.public_bytes(serialization.Encoding.PEM))
    f.write(b"\n")
    f.write(inter_ca.public_bytes(serialization.Encoding.PEM))

print(f"""
   [OK] PKCS#12: {p12_path} ({len(p12_data)} bytes)
   [OK] 私钥PEM: {key_pem_path}
   [OK] 证书链:  {chain_pem_path}

{'=' * 60}
  mTLS 客户端证书设置完成!
{'=' * 60}

  浏览器导入步骤:
    设置 → 隐私和安全 → 管理证书 → 个人 → 导入
    选择 admin_client.p12

  下一步将:
    1. 配置Nginx mTLS双向认证
    2. 后端增加证书自动登录
    3. 实现"必须出示证书才能访问"
{'=' * 60}
""")
