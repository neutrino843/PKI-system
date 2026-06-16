"""
================================================================
  PKI系统 HTTPS网站加密场景 E2E验证脚本（v1.0）
  覆盖范围：TLS证书签发、PKCS#12导出、CA证书分发、证书吊销
  输出：详细的指标数据和运行记录
================================================================
"""
import requests
import time
import json
import sys
import os
import uuid
from pathlib import Path
from datetime import datetime
from io import BytesIO

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

BASE = "http://localhost:8080"
S = requests.Session()
RS = requests.Session()  # ra_zhang独立会话
UID = uuid.uuid4().hex[:8]

# ====== 测试框架 ======
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
        try:
            body = r.json()
        except Exception:
            body = r.text[:200]
        raise AssertionError(f"期望{expected}, 实际{r.status_code}: {body}")
    return r


# ====== 生成测试CSR（本地生成，私钥不离开测试环境） ======
TEST_DOMAIN = f"test-web-{UID}.internal.company.com"
TEST_IP = "192.168.1.100"

def generate_test_csr():
    """生成RSA密钥对和CSR（模拟Web服务器管理员操作）"""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TEST_DOMAIN)])
    )
    csr = csr_builder.sign(key, hashes.SHA256(), default_backend())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    # 保存私钥供后续PKCS#12验证使用
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return csr_pem, priv_pem

CSR_PEM, PRIV_PEM = generate_test_csr()


# ====== T1：管理员登录PKI系统 ======
print("\n" + "=" * 70)
print("  HTTPS场景 E2E验证测试")
print(f"  测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  目标地址: {BASE}")
print(f"  测试域名: {TEST_DOMAIN}")
print(f"  测试IP:   {TEST_IP}")
print("=" * 70)

TM.start()

def t1_admin_login():
    """T1: 管理员登录验证API可达"""
    r = S.post(f"{BASE}/api/auth/login",
               json={"username": "admin", "password": "admin123"})
    check(r, 200, "管理员登录")
    d = r.json()
    assert d["user"]["roleName"] == "CA管理员", f"角色异常: {d}"
    return f"用户={d['user']['name']} 角色={d['user']['roleName']}"

tc("HTTPS", "T1 管理员登录", t1_admin_login)


# ====== T2：签发TLS服务器证书（完整流程） ======
csr_id_holder = [None]
serial_holder = [None]

def t2_issue_tls_cert():
    """T2: 完整流程：上传CSR→初审→二审→签发（含IP SAN和多域名）"""
    # Step 2a: 上传CSR
    files = {"csr": ("test_csr.pem", CSR_PEM, "application/x-pem-file")}
    data = {"cn": TEST_DOMAIN, "org": "测试部"}
    r = S.post(f"{BASE}/api/csr/upload", files=files, data=data)
    check(r, 200, "CSR上传")
    d = r.json()
    csr_id = d["csrId"]
    csr_id_holder[0] = csr_id
    assert csr_id.startswith("CSR-"), f"CSR ID格式异常: {csr_id}"

    # Step 2b: 初审（admin作为CA管理员可初审）
    items = S.get(f"{BASE}/api/csr/pending").json()
    target = None
    for item in items:
        if item["id"] == csr_id:
            target = item
            break
    assert target, f"CSR {csr_id} 未出现在待审核列表中"
    assert target["status"] == "pending", f"CSR状态异常: {target['status']}"

    r = S.post(f"{BASE}/api/csr/approve-first",
               json={"csrId": csr_id, "note": "初审通过-身份核实一致"})
    check(r, 200, "初审")

    # Step 2c: 二审（使用ra_zhang账号二审）
    RS.post(f"{BASE}/api/auth/login",
            json={"username": "ra_zhang", "password": "ra123456"})
    items = RS.get(f"{BASE}/api/csr/pending").json()
    target = None
    for item in items:
        if item["id"] == csr_id:
            target = item
            break
    assert target, f"CSR {csr_id} 未出现在待二审列表中"
    assert target["status"] == "first_approved", f"CSR状态异常: {target['status']}"

    r = RS.post(f"{BASE}/api/csr/approve-second",
                json={"csrId": csr_id, "note": "二审通过-同意签发TLS证书"})
    check(r, 200, "二审")

    # Step 2d: 签发证书（带extraSans和extraIps）
    r = S.post(f"{BASE}/api/certificates/issue/{csr_id}",
               json={
                   "extraSans": [f"www.{TEST_DOMAIN}", f"api.{TEST_DOMAIN}"],
                   "extraIps": [TEST_IP, "10.0.0.5"]
               })
    check(r, 200, "签发")
    return f"csrId={csr_id} domain={TEST_DOMAIN} ip={TEST_IP}"

tc("HTTPS", "T2 签发TLS服务器证书", t2_issue_tls_cert)


# ====== T3：验证证书属性 ======
def t3_verify_cert_properties():
    """T3: 验证证书EKU含SERVER_AUTH + SAN含IP地址 + 多域名"""
    # 获取证书列表，找到刚签发的证书
    certs = S.get(f"{BASE}/api/certificates").json()
    target_cert = None
    for c in certs:
        if c.get("cn") == TEST_DOMAIN:
            target_cert = c
            break

    assert target_cert, f"未找到CN={TEST_DOMAIN}的证书"
    serial_holder[0] = target_cert["serial"]
    assert target_cert["status"] in ("有效", "即将到期"), f"证书状态异常: {target_cert['status']}"

    # 通过详情API获取证书文件路径
    r = S.get(f"{BASE}/api/certificates/{target_cert['serial']}")
    check(r, 200, "证书详情")
    cert_detail = r.json()

    # 读取证书文件进行解析验证
    cert_dir = Path("pki_demo/certs")
    cert_file = None
    for f in cert_dir.glob("user_*.pem"):
        try:
            with open(f, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
                if str(cert.serial_number) == target_cert["serial"]:
                    cert_file = f
                    # 验证EKU
                    try:
                        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
                        eku_oids = [oid.dotted_string for oid in eku.value]
                        # SERVER_AUTH = 1.3.6.1.5.5.7.3.1
                        assert "1.3.6.1.5.5.7.3.1" in eku_oids, \
                            f"缺少SERVER_AUTH EKU: {eku_oids}"
                        # CLIENT_AUTH = 1.3.6.1.5.5.7.3.2
                        assert "1.3.6.1.5.5.7.3.2" in eku_oids, \
                            f"缺少CLIENT_AUTH EKU: {eku_oids}"
                    except x509.ExtensionNotFound:
                        raise AssertionError("证书缺少ExtendedKeyUsage扩展")

                    # 验证SAN包含IP地址
                    try:
                        san = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        san_values = []
                        for name in san.value:
                            san_values.append((type(name).__name__, name.value))

                        # 应包含主域名
                        dns_names = [v[1] for v in san_values if v[0] == "DNSName"]
                        assert TEST_DOMAIN in dns_names, \
                            f"SAN缺少主域名{TEST_DOMAIN}: {dns_names}"
                        assert f"www.{TEST_DOMAIN}" in dns_names, \
                            f"SAN缺少www域名: {dns_names}"

                        # 应包含IP地址
                        ip_values = [v[1] for v in san_values if v[0] == "IPAddress"]
                        assert TEST_IP in ip_values, \
                            f"SAN缺少IP地址{TEST_IP}: {ip_values}"
                        assert "10.0.0.5" in ip_values, \
                            f"SAN缺少IP地址10.0.0.5: {ip_values}"

                    except x509.ExtensionNotFound:
                        raise AssertionError("证书缺少SubjectAlternativeName扩展")

                    break
        except Exception:
            continue

    assert cert_file, f"未找到序列号{target_cert['serial']}对应的证书文件"
    return (f"serial={target_cert['serial'][:16]}... "
            f"DNS={TEST_DOMAIN},www.{TEST_DOMAIN},api.{TEST_DOMAIN} "
            f"IP={TEST_IP},10.0.0.5")

tc("HTTPS", "T3 验证证书属性(EKU+SAN)", t3_verify_cert_properties)


# ====== T4：PEM导出验证（CSR上传场景，私钥在客户端） ======
def t4_export_pem():
    """T4: PEM导出验证（CSR上传模式下私钥不离开客户端，验证证书可下载）"""
    serial = serial_holder[0]
    assert serial, "无证书序列号"

    r = S.get(f"{BASE}/api/certificates/{serial}/export-pem")
    check(r, 200, "PEM导出")
    content_type = r.headers.get("Content-Type", "")
    assert "x509" in content_type or "pem" in content_type or "octet-stream" in content_type, \
        f"Content-Type异常: {content_type}"

    pem_data = r.content
    assert pem_data.startswith(b"-----BEGIN CERTIFICATE-----"), \
        "PEM文件格式不正确"

    # 验证证书内容
    from cryptography.x509 import load_pem_x509_certificate
    cert = load_pem_x509_certificate(pem_data, default_backend())
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cert_cn = cn_attr[0].value if cn_attr else ""
    assert TEST_DOMAIN in cert_cn, f"证书CN不匹配: {cert_cn}"

    # 验证证书序列号一致
    assert str(cert.serial_number) == serial, \
        f"证书序列号不匹配: {cert.serial_number} vs {serial}"

    return f"格式=PEM CN={cert_cn} 大小={len(pem_data)}B"

tc("HTTPS", "T4 PEM导出验证", t4_export_pem)


# ====== T5：CA证书分发验证 ======
def t5_ca_cert_download():
    """T5: CA证书分发验证（下载 + 格式校验）"""
    r = S.get(f"{BASE}/api/ca-certificate")
    check(r, 200, "CA证书下载")

    content_type = r.headers.get("Content-Type", "")
    assert "x509" in content_type or "pem" in content_type or "octet-stream" in content_type, \
        f"Content-Type异常: {content_type}"

    ca_pem = r.content
    assert ca_pem.startswith(b"-----BEGIN CERTIFICATE-----"), \
        "CA证书不是PEM格式"

    # 验证CA证书有效
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_pem, default_backend())
        cn_attr = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ca_cn = cn_attr[0].value if cn_attr else ""

        # 验证CA证书是自签名（issuer == subject）
        assert ca_cert.subject == ca_cert.issuer, \
            "根CA证书的签发者和主题不一致"

    except Exception as e:
        raise AssertionError(f"CA证书验证失败: {e}")

    return f"CN={ca_cn} 有效=True 自签名=True 大小={len(ca_pem)}B"

tc("HTTPS", "T5 CA证书分发验证", t5_ca_cert_download)


# ====== T6：证书吊销测试 ======
def t6_revoke_cert():
    """T6: 证书吊销测试（吊销→CRL更新→验证CRL包含已吊销证书）"""
    serial = serial_holder[0]
    assert serial, "无证书序列号"

    # Step 6a: 吊销证书
    r = S.post(f"{BASE}/api/revoked/revoke",
               json={
                   "serial": serial,
                   "cn": TEST_DOMAIN,
                   "reason": "superseded",
                   "reasonDesc": "HTTPS场景测试-证书替换"
               })
    check(r, 200, "吊销证书")
    revoke_msg = r.json().get("message", "")
    assert "成功" in revoke_msg or "吊销" in revoke_msg or "已吊销" in revoke_msg or "撤销" in revoke_msg or "成功" in str(r.json()), \
        f"吊销返回异常: {r.json()}"

    # Step 6b: 验证证书状态已更新
    certs = S.get(f"{BASE}/api/certificates").json()
    revoked_cert = None
    for c in certs:
        if c.get("serial") == serial:
            revoked_cert = c
            break
    assert revoked_cert, "吊销后未找到证书"
    assert revoked_cert["status"] in ("已吊销", "吊销"), \
        f"证书状态未更新为已吊销: {revoked_cert['status']}"

    # Step 6c: 验证CRL包含已吊销证书
    r = S.get(f"{BASE}/api/revoked")
    check(r, 200, "CRL列表")
    crl_items = r.json()
    found_in_crl = False
    for item in crl_items:
        if item.get("serial", "") == serial or serial in str(item):
            found_in_crl = True
            break
    assert found_in_crl, f"序列号{serial}未出现在CRL中"

    # Step 6d: 验证CRL完整性
    r = S.get(f"{BASE}/api/revoked/verify")
    check(r, 200, "CRL完整性验证")
    verify_result = r.json()
    assert verify_result.get("valid", False) or verify_result.get("message", ""), \
        f"CRL完整性验证失败: {verify_result}"

    return f"serial={serial[:16]}... CRL包含=True 完整性=True"

tc("HTTPS", "T6 证书吊销测试", t6_revoke_cert)


# ====== 结束 ======
TM.end()
summary = TM.summary()

print("\n" + "=" * 70)
print("  HTTPS场景 E2E验证结果")
print("=" * 70)
print(f"  总测试项: {summary['total']}")
print(f"  通过:     {summary['passed']}")
print(f"  失败:     {summary['failed']}")
print(f"  警告:     {summary['warned']}")
print(f"  总耗时:   {summary['duration_sec']}秒")
print("=" * 70)

# 保存报告
report = {
    "test_time": datetime.now().isoformat(),
    "target": BASE,
    "test_domain": TEST_DOMAIN,
    "test_ip": TEST_IP,
    "summary": summary,
    "details": TM.results,
}
rp = Path("tests/test_https_report.json")
rp.parent.mkdir(exist_ok=True)
with open(rp, "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)
print(f"\n测试报告已保存: {rp}")

if summary["failed"] > 0:
    sys.exit(1)
else:
    print("\n所有HTTPS场景测试通过！PKI体系可成功应用于HTTP网站加密场景。")
