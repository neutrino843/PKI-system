"""
================================================================
  ACME 自动证书管理协议模块（acme_server.py）
  标准：RFC 8555 - Automatic Certificate Management Environment
  功能：支持 ACME 客户端（如 certbot）自动申请和获取证书
        - HTTP-01 挑战验证（域名所有权验证）
        - 自动签发证书
        - 证书续期
================================================================
"""

import os
import json
import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509 import SubjectAlternativeName, DNSName

from .config import CFG
from .security_crypto import generate_keypair, get_hash_algorithm, get_signature_hash
from .security_crl import SecureRevokedList
from .audit import audit_logger

BASE_DIR = Path(__file__).parent.resolve()


# ============================================================
# 非负数（Nonce）管理
# ============================================================

class NonceManager:
    """ACME nonce（一次性随机数）管理，防重放攻击"""

    def __init__(self):
        self._nonces = {}  # {nonce: expiry_timestamp}
        self._max_nonces = 1000

    def generate(self):
        """生成新 nonce"""
        nonce = secrets.token_urlsafe(16)
        self._nonces[nonce] = time.time() + 300  # 5分钟有效
        self._cleanup()
        return nonce

    def verify(self, nonce):
        """验证并消耗 nonce"""
        if nonce in self._nonces:
            expiry = self._nonces.pop(nonce, 0)
            if time.time() <= expiry:
                return True
        return False

    def _cleanup(self):
        """清理过期 nonce"""
        now = time.time()
        expired = [k for k, v in self._nonces.items() if v < now]
        for k in expired:
            del self._nonces[k]
        # 限制队列长度
        while len(self._nonces) > self._max_nonces:
            oldest = min(self._nonces, key=lambda k: self._nonces[k])
            del self._nonces[oldest]


# ============================================================
# ACME 账户管理
# ============================================================

class ACMEAccountManager:
    """ACME 账户（与 Let's Encrypt 的账户概念相同）"""

    def __init__(self):
        self._accounts = {}  # {kid: account_info}

    def create_account(self, contact_email=None, terms_of_service_agreed=False):
        """创建 ACME 账户"""
        kid = secrets.token_urlsafe(16)
        account = {
            "kid": kid,
            "status": "valid",
            "contact": [f"mailto:{contact_email}"] if contact_email else [],
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "orders": [],
        }
        self._accounts[kid] = account
        return account

    def get_account(self, kid):
        """获取账户信息"""
        return self._accounts.get(kid)

    def deactivate_account(self, kid):
        """停用账户"""
        account = self._accounts.get(kid)
        if account:
            account["status"] = "deactivated"
            return True
        return False


# ============================================================
# ACME 订单与挑战管理
# ============================================================

class ACMEOrderManager:
    """ACME 订单管理（每个域名申请为一个 Order）"""

    def __init__(self):
        self._orders = {}       # {order_id: order_info}
        self._authorizations = {}  # {auth_id: auth_info}
        self._challenges = {}   # {challenge_id: challenge_info}
        self._certificates = {} # {cert_id: cert_info}

    def create_order(self, domains, account_kid):
        """
        创建 ACME 订单

        参数：
            domains: ["your-domain.example.com", "www.your-domain.example.com"] 域名列表
            account_kid: ACME 账户 ID

        返回：订单信息
        """
        order_id = secrets.token_urlsafe(12)
        now = datetime.now(timezone.utc)

        # 每个域名创建一个 Authorization
        authorizations = []
        for domain in domains:
            auth_id = secrets.token_urlsafe(12)
            auth = {
                "authId": auth_id,
                "domain": domain,
                "status": "pending",
                "expires": (now + timedelta(hours=24)).isoformat(),
                "challenges": [],
            }

            # HTTP-01 挑战
            token = secrets.token_urlsafe(20)
            thumbprint = self._make_thumbprint(token, account_kid)
            challenge_http = {
                "challengeId": f"{auth_id}_http01",
                "type": "http-01",
                "url": f"/acme/challenge/{auth_id}_http01",
                "token": token,
                "thumbprint": thumbprint,
                "status": "pending",
                "validationContent": f"{token}.{thumbprint}",
                "validationFilename": f".well-known/acme-challenge/{token}",
            }
            auth["challenges"].append(challenge_http)
            self._challenges[challenge_http["challengeId"]] = challenge_http
            authorizations.append(auth_id)
            self._authorizations[auth_id] = auth

        order = {
            "orderId": order_id,
            "accountKid": account_kid,
            "status": "pending",
            "expires": (now + timedelta(hours=24)).isoformat(),
            "identifiers": [{"type": "dns", "value": d} for d in domains],
            "authorizations": authorizations,
            "certificateId": None,
            "createdAt": now.isoformat(),
        }

        self._orders[order_id] = order
        return order

    def _make_thumbprint(self, token, account_kid):
        """生成 ACME thumbprint（用于 HTTP-01 验证）"""
        # 简化实现：实际ACME使用JWK thumbprint
        raw = f"{token}.{account_kid}"
        return base64.urlsafe_b64encode(
            hashlib.sha256(raw.encode()).digest()
        ).rstrip(b"=").decode()

    def verify_challenge(self, challenge_id):
        """
        验证 HTTP-01 挑战

        验证逻辑：检查 .well-known/acme-challenge/{token} 文件内容
        是否等于 {token}.{thumbprint}

        参数：
            challenge_id: 挑战 ID

        返回：(成功标志, 消息)
        """
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            return False, "挑战不存在"

        if challenge["type"] != "http-01":
            return False, "不支持的挑战类型"

        token = challenge["token"]
        expected = challenge["validationContent"]

        # 检查本地 ACME 验证文件
        well_known_dir = BASE_DIR / "data" / ".well-known" / "acme-challenge"
        challenge_file = well_known_dir / token

        if challenge_file.exists():
            try:
                actual = challenge_file.read_text().strip()
                if actual == expected:
                    challenge["status"] = "valid"
                    # 更新关联的 Authorization
                    for auth in self._authorizations.values():
                        if challenge_id in [c["challengeId"] for c in auth["challenges"]]:
                            auth["status"] = "valid"
                            break
                    # 检查是否所有 Authorization 都 valid 了
                    self._check_order_ready(challenge_id)
                    return True, "挑战验证通过"
                else:
                    return False, f"验证内容不匹配"
            except Exception as e:
                return False, f"验证文件读取失败: {e}"
        else:
            return False, (f"验证文件不存在: "
                          f"{well_known_dir / token}\n"
                          f"请在域名服务器创建此文件")

    def _check_order_ready(self, challenge_id):
        """检查订单是否所有挑战都通过"""
        for auth in self._authorizations.values():
            # 找到这个 challenge 所在的 authorization
            for c in auth["challenges"]:
                if c["challengeId"] == challenge_id:
                    # 检查此 authorization 所在订单的所有 authorization
                    for order in self._orders.values():
                        if auth["authId"] in order["authorizations"]:
                            all_valid = all(
                                self._authorizations[a]["status"] == "valid"
                                for a in order["authorizations"]
                            )
                            if all_valid and order["status"] == "pending":
                                order["status"] = "ready"
                            return

    def finalize_order(self, order_id, csr_pem):
        """
        完成订单（签发证书）

        参数：
            order_id: 订单 ID
            csr_pem: PEM 格式的 CSR

        返回：(成功标志, 结果字典)
        """
        order = self._orders.get(order_id)
        if not order:
            return False, {"error": "订单不存在"}
        if order["status"] not in ("ready", "pending"):
            return False, {"error": f"订单状态异常: {order['status']}"}

        # 验证所有 Authorization
        for auth_id in order["authorizations"]:
            auth = self._authorizations.get(auth_id)
            if not auth or auth["status"] != "valid":
                return False, {"error": f"域名验证未通过: {auth.get('domain', 'unknown')}"}

        # 签发证书
        try:
            cert_id = secrets.token_urlsafe(12)
            cert_pem = self._issue_certificate(csr_pem, order["identifiers"])

            order["status"] = "valid"
            order["certificateId"] = cert_id
            self._certificates[cert_id] = {
                "certId": cert_id,
                "orderId": order_id,
                "pem": cert_pem,
                "issuedAt": datetime.now(timezone.utc).isoformat(),
            }

            return True, {
                "certId": cert_id,
                "pem": cert_pem,
                "orderStatus": "valid",
            }

        except Exception as e:
            return False, {"error": f"证书签发失败: {e}"}

    def _issue_certificate(self, csr_pem, identifiers):
        """实际签发证书（使用 PKI 系统的 CA）"""
        from .unit4_sign_cert import sign_certificate

        csr = x509.load_pem_x509_csr(csr_pem.encode() if isinstance(csr_pem, str) else csr_pem,
                                      default_backend())

        # 使用系统 CA 签发证书
        cert_path = BASE_DIR / "certs" / f"acme_{secrets.token_hex(4)}.pem"
        # 保存并签发
        with open(BASE_DIR / "csr" / f"acme_{int(time.time())}.pem", "wb") as f:
            f.write(csr_pem.encode() if isinstance(csr_pem, str) else csr_pem)

        # 使用 sign_certificate 签发
        # 返回 PEM 格式
        from pathlib import Path as P
        ca_cert_path = BASE_DIR / "certs" / "inter_ca_cert.pem"
        if not ca_cert_path.exists():
            ca_cert_path = BASE_DIR / "certs" / "root_ca_cert.pem"

        ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
        ca_key_path = BASE_DIR / "keys" / "inter_ca_private.pem"
        if not ca_key_path.exists():
            ca_key_path = BASE_DIR / "keys" / "root_ca_private.pem"

        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=ca_pwd, backend=default_backend()
            )
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        now = datetime.now(timezone.utc)
        san_names = [DNSName(idn["value"]) for idn in identifiers]

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(SubjectAlternativeName(san_names), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]), critical=False)
            .sign(ca_key, get_signature_hash(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        with open(cert_path, "wb") as f:
            f.write(cert_pem.encode())

        return cert_pem

    def get_certificate(self, cert_id):
        """获取已签发的证书"""
        return self._certificates.get(cert_id)

    def get_order(self, order_id):
        """获取订单信息"""
        return self._orders.get(order_id)

    def get_authorization(self, auth_id):
        """获取授权信息"""
        auth = self._authorizations.get(auth_id)
        if not auth:
            return None
        return {
            "status": auth["status"],
            "domain": auth["domain"],
            "expires": auth["expires"],
            "challenges": [
                {
                    "type": c["type"],
                    "url": c["url"],
                    "token": c["token"],
                    "status": c["status"],
                }
                for c in auth["challenges"]
            ],
        }

    def get_challenge(self, challenge_id):
        """获取挑战信息"""
        return self._challenges.get(challenge_id)


# ============================================================
# ACME 服务器
# ============================================================

class ACMEServer:
    """
    ACME 协议服务器（RFC 8555）

    实现 ACME 目录 + HTTP-01 挑战 + 证书签发。
    兼容 certbot、acme.sh 等 ACME 客户端。
    """

    def __init__(self):
        self.nonce_mgr = NonceManager()
        self.account_mgr = ACMEAccountManager()
        self.order_mgr = ACMEOrderManager()

    def get_directory(self, base_url=""):
        """
        ACME 目录端点（/acme/directory）

        返回 ACME 客户端所需的所有端点 URL
        """
        return {
            "newNonce": f"{base_url}/acme/new-nonce",
            "newAccount": f"{base_url}/acme/new-account",
            "newOrder": f"{base_url}/acme/new-order",
            "newAuthz": f"{base_url}/acme/new-authz",
            "revokeCert": f"{base_url}/acme/revoke-cert",
            "keyChange": f"{base_url}/acme/key-change",
            "meta": {
                "termsOfService": f"{base_url}/acme/tos",
                "website": f"{base_url}/",
                "caaIdentities": ["PKI System ACME Server"],
                "externalAccountRequired": False,
            },
        }

    def create_account(self, payload):
        """创建 ACME 账户"""
        contact = payload.get("contact", [])
        email = ""
        for c in contact:
            if c.startswith("mailto:"):
                email = c[7:]

        agreed = payload.get("termsOfServiceAgreed", False)
        account = self.account_mgr.create_account(email, agreed)
        
        audit_logger.log("ACME_ACCOUNT", "ACME_CLIENT", "CREATE",
                        account["kid"], "SUCCESS",
                        f"ACME账户创建: {email or '匿名'}",
                        "system")
        return account

    def create_order(self, payload, account_kid):
        """创建 ACME 订单"""
        identifiers = payload.get("identifiers", [])
        domains = [idn["value"] for idn in identifiers
                   if idn.get("type") == "dns"]

        if not domains:
            return None, "无有效域名标识"

        order = self.order_mgr.create_order(domains, account_kid)

        # 审计
        audit_logger.log("ACME_ORDER", account_kid, "CREATE",
                        order["orderId"], "SUCCESS",
                        f"ACME订单创建: {', '.join(domains)}",
                        "system")

        return order, None

    def setup_http01_challenge_file(self, challenge_id):
        """
        设置 HTTP-01 验证文件（供客户端验证域名所有权）

        调用此方法后，ACME 客户端需要将此文件放置到域名的
        .well-known/acme-challenge/{token} 路径下

        参数：
            challenge_id: 挑战 ID

        返回：文件内容信息
        """
        challenge = self.order_mgr.get_challenge(challenge_id)
        if not challenge:
            return None

        return {
            "filename": challenge["validationFilename"],
            "content": challenge["validationContent"],
        }

    def verify_and_finalize(self, order_id, csr_pem):
        """验证挑战并完成订单（签发证书）"""
        success, result = self.order_mgr.finalize_order(order_id, csr_pem)
        if success:
            audit_logger.log("ACME_ISSUE", order_id, "CREATE",
                            result.get("certId", ""), "SUCCESS",
                            f"ACME证书已签发: {order_id}",
                            "system")
        return success, result

    def revoke_certificate(self, cert_pem, reason="unspecified"):
        """吊销 ACME 签发的证书"""
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode() if isinstance(cert_pem, str) else cert_pem,
                default_backend()
            )
            serial = str(cert.serial_number)

            # 添加到吊销列表
            crl = SecureRevokedList()
            crl.revoke(serial, reason)

            audit_logger.log("ACME_REVOKE", "ACME_CLIENT", "REVOKE",
                            serial, "SUCCESS",
                            f"ACME证书已吊销: {serial}",
                            "system")
            return True, "证书已吊销"
        except Exception as e:
            return False, f"吊销失败: {e}"


# ============================================================
# 全局实例
# ============================================================
acme_server = ACMEServer()


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    print("=== ACME 协议服务器测试 ===\n")

    acme = ACMEServer()

    # 测试 Nonce
    print("[测试1] Nonce 管理")
    nonce = acme.nonce_mgr.generate()
    print(f"  Nonce: {nonce[:20]}...")
    assert acme.nonce_mgr.verify(nonce), "Nonce 验证应通过"
    assert not acme.nonce_mgr.verify(nonce), "Nonce 消耗后应失败"
    print("  [OK]")

    # 测试目录
    print("\n[测试2] ACME 目录")
    directory = acme.get_directory("https://localhost:8443")
    print(f"  newNonce: {directory['newNonce'][:30]}...")
    print(f"  newAccount: {directory['newAccount'][:30]}...")
    print(f"  newOrder: {directory['newOrder'][:30]}...")

    # 测试账户
    print("\n[测试3] 账户创建")
    account = acme.create_account({"contact": ["mailto:admin@example.com"],
                                   "termsOfServiceAgreed": True})
    print(f"  KID: {account['kid'][:12]}...")
    print(f"  状态: {account['status']}")

    # 测试订单
    print("\n[测试4] 订单创建")
    order, err = acme.create_order({
        "identifiers": [{"type": "dns", "value": "your-domain.example.com"}]
    }, account["kid"])
    print(f"  订单ID: {order['orderId'][:12]}...")
    print(f"  状态: {order['status']}")
    print(f"  域名: {order['identifiers'][0]['value']}")

    # 测试 HTTP-01 挑战
    print("\n[测试5] HTTP-01 挑战")
    for auth_id in order["authorizations"]:
        auth = acme.order_mgr.get_authorization(auth_id)
        print(f"  域名: {auth['domain']}")
        for c in auth["challenges"]:
            print(f"  挑战类型: {c['type']}")
            print(f"  验证文件: .well-known/acme-challenge/{c['token']}")
            challenge_info = acme.setup_http01_challenge_file(c["url"].split("/")[-1])
            if challenge_info:
                print(f"  文件内容: {challenge_info['content'][:20]}...")

    print("\n[OK] 全部通过")
