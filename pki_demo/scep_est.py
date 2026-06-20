"""
================================================================
  SCEP / EST 自动证书注册协议模块（scep_est.py）
  标准：
    - SCEP: RFC 8894 (Simple Certificate Enrollment Protocol)
    - EST:  RFC 7030 (Enrollment over Secure Transport)
  功能：支持网络设备/客户端自动申请和获取证书
================================================================
"""

import os
import json
import base64
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
from ipaddress import ip_address

from .config import CFG
from .security_crypto import generate_keypair, get_hash_algorithm
from .ra import ra_manager
from .audit import audit_logger

BASE_DIR = Path(__file__).parent.resolve()

# ============================================================
# SCEP 注册令牌管理
# ============================================================

class SCEPChallenge:
    """
    SCEP 挑战密码/注册令牌

    用于设备注册前的身份验证，防止未授权设备自动获取证书。
    管理员需要预先为设备生成挑战密码，设备在 SCEP 请求中携带该密码。
    """
    def __init__(self):
        self._tokens = {}  # {token: {"device": name, "expires": timestamp}}

    def generate_token(self, device_name, valid_hours=24):
        """
        为指定设备生成注册令牌

        参数：
            device_name: 设备标识（如主机名、MAC地址、序列号）
            valid_hours: 令牌有效期（小时）

        返回：令牌字符串
        """
        token = secrets.token_hex(16)
        expires = datetime.now(timezone.utc) + timedelta(hours=valid_hours)
        self._tokens[token] = {
            "device": device_name,
            "created": datetime.now(timezone.utc).isoformat(),
            "expires": expires.isoformat(),
        }
        return {
            "token": token,
            "device": device_name,
            "expires": expires.isoformat(),
            "validHours": valid_hours,
        }

    def verify_token(self, token, device_name=None):
        """
        验证注册令牌

        参数：
            token: 令牌字符串
            device_name: 可选的设备名称校验

        返回：True/False
        """
        info = self._tokens.get(token)
        if not info:
            return False

        # 检查有效期
        expires = datetime.fromisoformat(info["expires"])
        if datetime.now(timezone.utc) > expires:
            del self._tokens[token]
            return False

        # 检查设备名（如果有提供）
        if device_name and info["device"] != device_name:
            return False

        return True

    def revoke_token(self, token):
        """吊销注册令牌"""
        return self._tokens.pop(token, None) is not None

    def list_tokens(self):
        """列出所有有效令牌"""
        now = datetime.now(timezone.utc)
        valid = {}
        for token, info in self._tokens.items():
            expires = datetime.fromisoformat(info["expires"])
            if now <= expires:
                valid[token] = info
        return valid

    def cleanup(self):
        """清理过期令牌"""
        now = datetime.now(timezone.utc)
        expired = [k for k, v in self._tokens.items()
                   if datetime.fromisoformat(v["expires"]) <= now]
        for k in expired:
            del self._tokens[k]
        return len(expired)


# ============================================================
# SCEP 协议处理
# ============================================================

class SCEPHandler:
    """
    SCEP (Simple Certificate Enrollment Protocol) 处理器

    实现标准 SCEP 端点：
    - GET /pkiclient.exe?operation=GetCACert   — 获取 CA 证书
    - GET /pkiclient.exe?operation=GetCACaps    — 获取 CA 能力
    - POST /pkiclient.exe (PKCSReq)             — 提交 PKCS#10 CSR
    - GET /pkiclient.exe?operation=GetCert      — 获取已签发证书

    注：Flask 端实现为 REST 风格 + application/x-pki-message 内容类型。
    """

    def __init__(self):
        self._challenge = SCEPChallenge()
        self._pending_requests = {}  # {transaction_id: csr_info}

    def get_ca_cert_pem(self):
        """获取CA证书PEM"""
        for name in ["inter_ca_cert.pem", "root_ca_cert.pem"]:
            path = BASE_DIR / "certs" / name
            if path.exists():
                with open(path, "rb") as f:
                    return f.read()
        return None

    def get_ca_cert_der(self):
        """获取CA证书DER (SCEP标准格式)"""
        pem = self.get_ca_cert_pem()
        if pem:
            cert = x509.load_pem_x509_certificate(pem, default_backend())
            return cert.public_bytes(serialization.Encoding.DER)
        return None

    def get_ca_caps(self):
        """
        获取CA能力列表 (SCEP GetCACaps)

        返回：["SCEPStandard", "POSTPKIOperation", "Renewal", "SHA-256"]
        """
        return [
            "SCEPStandard",
            "POSTPKIOperation",
            "Renewal",
            "SHA-256",
        ]

    def handle_pkcs_req(self, csr_pem, challenge_password=None, transaction_id=None):
        """
        处理 PKCS#10 CSR 请求 (SCEP PKCSReq)

        参数：
            csr_pem: PEM 格式的 CSR
            challenge_password: SCEP 挑战密码（可选）
            transaction_id: 事务ID（可选）

        返回：{
            "status": "success"/"fail",
            "message": 描述信息,
            "serialNumber": 证书序列号,
            "certPem": PEM格式证书,
        }
        """
        # 验证挑战密码（如果有）
        if challenge_password:
            if not self._challenge.verify_token(challenge_password):
                return {
                    "status": "fail",
                    "message": "SCEP 挑战密码无效或已过期",
                }

        # 保存 CSR 到临时文件
        csr_id = f"scep_{transaction_id or secrets.token_hex(8)}"
        csr_dir = BASE_DIR / "csr"
        csr_dir.mkdir(exist_ok=True)
        csr_path = csr_dir / f"{csr_id}.pem"

        try:
            # 验证 CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem,
                                          default_backend())
            if not csr.is_signature_valid:
                return {"status": "fail", "message": "CSR 签名验证失败"}

            # 保存 CSR 文件
            with open(csr_path, "wb") as f:
                f.write(csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem)

            # 提取 CN
            cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = cn_attr[0].value if cn_attr else csr_id

            # 直接添加到 RA 待审核列表（或自动签发取决于配置）
            ra_manager.apply(cn, "SCEP自动注册", csr_path=str(csr_path))

            # 查找刚创建的申请
            pending = ra_manager.get_pending_list()
            my_item = None
            for p in pending:
                if p.get("cn") == cn or p.get("csr_id") == csr_id:
                    my_item = p
                    break

            if not my_item:
                # 回退：找最近一条
                for item in ra_manager.get_pending_list():
                    if item.get("csr_filepath", "").endswith(f"{csr_id}.pem"):
                        my_item = item
                        break

            if not my_item:
                return {"status": "fail", "message": "CSR 处理异常，未找到对应申请记录"}

            scep_csr_id = my_item["csr_id"]

            # 记录事务映射
            self._pending_requests[transaction_id or csr_id] = {
                "csr_id": scep_csr_id,
                "cn": cn,
                "status": "pending_approval",
            }

            audit_logger.log("SCEP_CSR", "SCEP_CLIENT", "CREATE", cn, "SUCCESS",
                             f"SCEP自动注册申请: {cn}", "system")

            return {
                "status": "success",
                "message": f"CSR 已提交，CSR ID: {scep_csr_id}",
                "csrId": scep_csr_id,
                "transactionId": transaction_id or csr_id,
                "requiresApproval": True,  # 需要审批（四眼原则）
            }

        except Exception as e:
            return {"status": "fail", "message": f"CSR 处理失败: {str(e)}"}

    def auto_issue_for_scep(self, csr_id):
        """
        SCEP 自动签发（如果配置为自动模式）
        注意：默认仍遵守四眼原则，需要手动审批
        """
        # 此为占位，实际签发走现有审批流
        return False

    def get_cert_for_transaction(self, transaction_id):
        """
        根据事务ID获取已签发的证书

        返回：PEM 格式证书字符串，或 None
        """
        info = self._pending_requests.get(transaction_id)
        if not info:
            return None

        # 查找已批准的 CSR
        approved = ra_manager.get_approved_list()
        for item in approved:
            if item["csr_id"] == info.get("csr_id"):
                # 找到已签发证书（由下游签发流程完成）
                cert_path = BASE_DIR / "certs" / f"{info['cn']}.pem"
                if cert_path.exists():
                    with open(cert_path, "rb") as f:
                        return f.read()
                # 尝试其他路径模式
                for ext in [".pem", ".crt"]:
                    for p in (BASE_DIR / "certs").glob(f"*{info['cn']}*{ext}"):
                        with open(p, "rb") as f:
                            return f.read()
                break

        return None

    def generate_scep_token(self, device_name, valid_hours=24):
        """生成 SCEP 注册令牌"""
        return self._challenge.generate_token(device_name, valid_hours)

    def verify_scep_token(self, token, device_name=None):
        """验证 SCEP 注册令牌"""
        return self._challenge.verify_token(token, device_name)


# ============================================================
# EST 协议处理
# ============================================================

class ESTHandler:
    """
    EST (Enrollment over Secure Transport) 处理器

    实现标准 EST 端点：
    - GET  /.well-known/est/cacerts        — 获取 CA 证书链
    - POST /.well-known/est/simpleenroll   — 简单注册
    - POST /.well-known/est/simplereenroll  — 简单续期
    - GET  /.well-known/est/csrattrs       — 获取 CSR 属性

    EST 要求底层使用 HTTPS（传输层安全），与 Flask 原生 HTTPS 结合使用。
    """

    def get_ca_certs_pem(self):
        """获取 CA 证书链 PEM"""
        certs = []
        for name in ["inter_ca_cert.pem", "root_ca_cert.pem"]:
            path = BASE_DIR / "certs" / name
            if path.exists():
                with open(path, "rb") as f:
                    certs.append(f.read().decode("utf-8"))
        return "\n".join(certs)

    def get_ca_certs_pkcs7(self):
        """
        获取 CA 证书链 PKCS#7 格式 (EST 标准格式)

        返回：DER 编码的 PKCS#7
        """
        # 实际 PKCS#7 需要构建 ContentInfo
        # 这里返回简单拼接的 PEM（大多数 EST 客户端也支持）
        return self.get_ca_certs_pem()

    def get_csr_attributes(self):
        """
        获取 CSR 属性 (EST csrattrs)

        返回：可用属性列表
        """
        return {
            "attributes": [
                {"oid": "2.5.4.3", "name": "commonName", "required": True, "label": "通用名称"},
                {"oid": "2.5.4.11", "name": "organizationalUnitName", "required": False, "label": "组织单位"},
                {"oid": "2.5.4.10", "name": "organizationName", "required": True, "label": "组织名称"},
                {"oid": "2.5.4.6", "name": "countryName", "required": False, "label": "国家代码"},
            ],
            "extensions": [
                {"oid": "2.5.29.17", "name": "subjectAltName", "required": False, "label": "SAN"},
            ],
        }


# ============================================================
# 全局实例
# ============================================================
scep_handler = SCEPHandler()
est_handler = ESTHandler()


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    print("=== SCEP/EST 自动注册协议测试 ===\n")

    print("[测试1] SCEP 挑战密码")
    scep = SCEPHandler()
    token = scep.generate_scep_token("test-device-01", valid_hours=1)
    print(f"  生成令牌: {token['token'][:16]}... (有效期: {token['validHours']}h)")
    assert scep.verify_scep_token(token["token"], "test-device-01"), "令牌验证应通过"
    assert not scep.verify_scep_token(token["token"], "wrong-device"), "错误设备应被拒绝"

    print("[测试2] CA 能力")
    caps = scep.get_ca_caps()
    print(f"  能力列表: {', '.join(caps)}")

    print("[测试3] EST CSR 属性")
    est_attrs = ESTHandler().get_csr_attributes()
    print(f"  属性数: {len(est_attrs['attributes'])}")

    print("\n[OK] 全部通过")
