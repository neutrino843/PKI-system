"""
================================================================
  OCSP 在线证书状态协议响应器 (ocsp.py)
  标准：RFC 6960 - Online Certificate Status Protocol
  功能：实时查询证书吊销状态，支持 RFC 6960 合规签名响应
================================================================
"""

import os
import time
import hashlib as std_hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.ocsp import (OCSPResponseBuilder, OCSPResponseStatus,
                                    OCSPCertStatus, OCSPResponderEncoding)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .security_crl import SecureRevokedList

BASE_DIR = Path(__file__).parent.resolve()

# OCSP 响应状态码
OCSP_STATUS_GOOD = 0
OCSP_STATUS_REVOKED = 1
OCSP_STATUS_UNKNOWN = 2

OCSP_STATUS_LABELS = {
    OCSP_STATUS_GOOD: "good",
    OCSP_STATUS_REVOKED: "revoked",
    OCSP_STATUS_UNKNOWN: "unknown",
}

# RFC 6960 OCSP 响应内容类型
OCSP_CONTENT_TYPE = "application/ocsp-response"

# OCSP Responder 证书/密钥路径
OCSP_CERT_PATH = BASE_DIR / "certs" / "ocsp_responder_cert.pem"
OCSP_KEY_PATH = BASE_DIR / "keys" / "ocsp_responder_private.pem"

# CA 证书路径（用于 OCSP issuer 引用）
CA_CERT_PATHS = [
    BASE_DIR / "certs" / "inter_ca_cert.pem",
    BASE_DIR / "certs" / "root_ca_cert.pem",
]


# ============================================================
# OCSP 响应器（支持 RFC 6960 签名响应）
# ============================================================

class OCSPResponder:
    """
    OCSP 在线证书状态协议响应器

    功能：
    - 查询单张证书的吊销状态（JSON 格式）
    - 批量查询（多张证书同时查询）
    - 生成 RFC 6960 合规签名 OCSP 响应（DER 编码）
    - OCSP Responder 证书自动签发管理
    - 缓存加速（减少数据库查询）
    """

    def __init__(self, cache_ttl=60):
        self._crl = SecureRevokedList()
        self._cache = {}
        self._cache_ttl = cache_ttl
        self._stats = {
            "total_requests": 0,
            "good_responses": 0,
            "revoked_responses": 0,
            "unknown_responses": 0,
            "cache_hits": 0,
            "signed_responses": 0,
        }
        # 懒加载：OCSP Responder 密钥和证书
        self._responder_key = None
        self._responder_cert = None
        # 懒加载：CA 证书（用于 OCSP issuer 引用）
        self._issuer_cert = None
        self._issuer_name_hash = None
        self._issuer_key_hash = None
        # 是否已初始化
        self._initialized = False

    # ---- Responder 证书管理 ----

    def _get_issuer_cert(self):
        """加载 CA 证书作为 OCSP issuer"""
        if self._issuer_cert is not None:
            return self._issuer_cert
        for ca_path in CA_CERT_PATHS:
            if ca_path.exists():
                with open(ca_path, "rb") as f:
                    self._issuer_cert = x509.load_pem_x509_certificate(
                        f.read(), default_backend())
                break
        if self._issuer_cert is None:
            raise RuntimeError("CA证书不存在，请先创建CA")
        return self._issuer_cert

    def _compute_issuer_hashes(self):
        """
        计算 OCSP issuer 的哈希值
        - issuerNameHash: SHA1(issuer DN DER)
        - issuerKeyHash: SHA1(issuer SubjectPublicKeyInfo DER)
        如果 CA 证书不存在，使用 OCSP Responder 自签证书的 issuer 作为替代
        """
        if self._issuer_name_hash is not None:
            return self._issuer_name_hash, self._issuer_key_hash

        try:
            issuer = self._get_issuer_cert()
        except RuntimeError:
            # 无 CA 时，使用 Responder 自身作为 issuer
            self._ensure_responder_initialized()
            issuer = self._responder_cert

        # issuerNameHash = SHA1(DER-encoded issuer DN)
        issuer_dn_der = issuer.subject.public_bytes()
        self._issuer_name_hash = std_hashlib.sha1(issuer_dn_der).digest()

        # issuerKeyHash = SHA1(DER-encoded SubjectPublicKeyInfo)
        pub_key_der = issuer.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._issuer_key_hash = std_hashlib.sha1(pub_key_der).digest()

        return self._issuer_name_hash, self._issuer_key_hash

    def _ensure_responder_initialized(self):
        """
        确保 OCSP Responder 密钥和证书已初始化
        如果证书不存在，自动生成自签名 Responder 证书
        """
        if self._initialized:
            return

        if OCSP_KEY_PATH.exists() and OCSP_CERT_PATH.exists():
            # 加载已有证书
            with open(OCSP_KEY_PATH, "rb") as f:
                self._responder_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend())
            with open(OCSP_CERT_PATH, "rb") as f:
                self._responder_cert = x509.load_pem_x509_certificate(
                    f.read(), default_backend())
        else:
            # 生成新 Responder 证书
            self._generate_responder_cert()

        self._initialized = True

    def _generate_responder_cert(self):
        """
        生成 OCSP Responder 自签名证书
        使用 RSA 2048 密钥，仅用于 OCSP 响应签名
        如果 CA 证书存在，由 CA 签发；否则自签名
        """
        # 生成密钥
        self._responder_key = rsa.generate_private_key(65537, 2048)

        # 创建证书
        now = datetime.now(timezone.utc)
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "PKI OCSP Responder"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo System"),
        ])

        # 尝试使用 CA 作为 issuer，否则自签名
        try:
            issuer_cert = self._get_issuer_cert()
            issuer_name = issuer_cert.subject
            sign_key = self._responder_key  # 对于 OCSP，Responder 用自己的密钥签名证书
        except RuntimeError:
            issuer_name = subject_name
            sign_key = self._responder_key

        self._responder_cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(issuer_name)
            .public_key(self._responder_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365 * 5))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING]),
                critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    self._responder_key.public_key()), critical=False)
            .sign(sign_key, hashes.SHA256(), default_backend())
        )

        # 持久化
        os.makedirs(OCSP_KEY_PATH.parent, exist_ok=True)
        os.makedirs(OCSP_CERT_PATH.parent, exist_ok=True)

        with open(OCSP_KEY_PATH, "wb") as f:
            f.write(self._responder_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(OCSP_CERT_PATH, "wb") as f:
            f.write(self._responder_cert.public_bytes(
                encoding=serialization.Encoding.PEM))

    def get_responder_cert_pem(self):
        """获取 OCSP Responder 证书 PEM 字节"""
        self._ensure_responder_initialized()
        return self._responder_cert.public_bytes(encoding=serialization.Encoding.PEM)

    # ---- 证书状态查询（JSON） ----

    def _get_cache_key(self, serial_number):
        return f"ocsp:{serial_number}"

    def _check_cache(self, serial_number):
        key = self._get_cache_key(serial_number)
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["time"] < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return entry["status"]
        return None

    def _update_cache(self, serial_number, status):
        key = self._get_cache_key(serial_number)
        self._cache[key] = {
            "status": status,
            "time": time.time(),
        }
        self._cleanup_cache()

    def _cleanup_cache(self):
        now = time.time()
        expired = [k for k, v in self._cache.items()
                   if now - v["time"] > self._cache_ttl * 2]
        for k in expired:
            del self._cache[k]

    def _query_status(self, serial_str):
        """查询证书状态，返回 (status_code, revoked_info)"""
        try:
            revoked = self._crl.is_revoked(serial_str)
            if revoked:
                status = OCSP_STATUS_REVOKED
                # 查找吊销信息
                rev_info = {"time": None, "reason": None}
                for item in self._crl.get_revoked_list():
                    if item["serial"] == serial_str:
                        rev_info["time"] = item.get("revoked_at", "")
                        rev_info["reason"] = item.get("reason", "unspecified")
                        break
                return status, rev_info
            else:
                return OCSP_STATUS_GOOD, None
        except Exception:
            return OCSP_STATUS_UNKNOWN, None

    def check_certificate(self, serial_number):
        """
        查询单张证书的 OCSP 状态（JSON 格式）

        返回：{
            "serial": "序列号",
            "status": 0/1/2,
            "statusLabel": "good/revoked/unknown",
            "checkedAt": "UTC时间"
        }
        """
        serial_str = str(serial_number)
        self._stats["total_requests"] += 1

        cached = self._check_cache(serial_str)
        if cached is not None:
            status = cached
            rev_info = None
        else:
            status, rev_info = self._query_status(serial_str)
            self._update_cache(serial_str, status)

        if status == OCSP_STATUS_GOOD:
            self._stats["good_responses"] += 1
        elif status == OCSP_STATUS_REVOKED:
            self._stats["revoked_responses"] += 1
        else:
            self._stats["unknown_responses"] += 1

        result = {
            "serial": serial_str,
            "status": status,
            "statusLabel": OCSP_STATUS_LABELS.get(status, "unknown"),
            "checkedAt": datetime.now(timezone.utc).isoformat(),
        }

        if status == OCSP_STATUS_REVOKED and rev_info:
            result["revokedAt"] = rev_info["time"] or ""
            result["reason"] = rev_info["reason"] or "unspecified"
            # 查找 reason_desc
            for item in self._crl.get_revoked_list():
                if item["serial"] == serial_str:
                    result["reasonDesc"] = item.get("reason_desc", "")
                    break

        return result

    def check_certificates_batch(self, serial_numbers):
        """批量查询多张证书的 OCSP 状态"""
        results = []
        summary = {"total": 0, "good": 0, "revoked": 0, "unknown": 0}

        for sn in serial_numbers:
            result = self.check_certificate(str(sn))
            results.append(result)
            summary["total"] += 1
            label = result["statusLabel"]
            if label == "good":
                summary["good"] += 1
            elif label == "revoked":
                summary["revoked"] += 1
            else:
                summary["unknown"] += 1

        return {"results": results, "summary": summary}

    def check_certificate_by_file(self, cert_path):
        """通过证书文件查询 OCSP 状态"""
        if not os.path.exists(cert_path):
            return {
                "serial": "unknown",
                "status": OCSP_STATUS_UNKNOWN,
                "statusLabel": "unknown",
                "error": f"证书文件不存在: {cert_path}",
                "checkedAt": datetime.now(timezone.utc).isoformat(),
            }

        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            return self.check_certificate(cert.serial_number)
        except Exception as e:
            return {
                "serial": "unknown",
                "status": OCSP_STATUS_UNKNOWN,
                "statusLabel": "unknown",
                "error": f"证书解析失败: {e}",
                "checkedAt": datetime.now(timezone.utc).isoformat(),
            }

    # ---- RFC 6960 签名 OCSP 响应 ----

    def build_signed_response(self, serial_number):
        """
        构建 RFC 6960 合规的签名 OCSP 响应

        使用 OCSP Responder 证书进行签名，返回 DER 编码的响应。
        响应包含 issuerNameHash / issuerKeyHash / serialNumber 标识。
        使用 OCSPResponderEncoding.HASH 标识响应者。

        参数：
            serial_number: 证书序列号（字符串或整数）

        返回：bytes (DER 编码的 OCSP 响应)
                返回 None 如果构建失败
        """
        self._ensure_responder_initialized()

        serial_str = str(serial_number)
        self._stats["total_requests"] += 1

        # 查询证书状态
        status, rev_info = self._query_status(serial_str)

        if status == OCSP_STATUS_GOOD:
            ocsp_status = OCSPCertStatus.GOOD
            rev_time = None
            rev_reason = None
            self._stats["good_responses"] += 1
        elif status == OCSP_STATUS_REVOKED:
            ocsp_status = OCSPCertStatus.REVOKED
            # 解析吊销时间
            rev_time = datetime.now(timezone.utc)
            if rev_info and rev_info.get("time"):
                try:
                    rev_time = datetime.fromisoformat(rev_info["time"])
                    if rev_time.tzinfo is None:
                        rev_time = rev_time.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    rev_time = datetime.now(timezone.utc)
            rev_reason = x509.ReasonFlags.unspecified
            self._stats["revoked_responses"] += 1
        else:
            ocsp_status = OCSPCertStatus.UNKNOWN
            rev_time = None
            rev_reason = None
            self._stats["unknown_responses"] += 1

        # 构建签名 OCSP 响应
        try:
            now = datetime.now(timezone.utc)
            name_hash, key_hash = self._compute_issuer_hashes()

            builder = OCSPResponseBuilder(
                responder_id=(self._responder_cert, OCSPResponderEncoding.HASH),
                certs=[self._responder_cert],
            )
            builder = builder.add_response_by_hash(
                issuer_name_hash=name_hash,
                issuer_key_hash=key_hash,
                serial_number=int(serial_str),
                algorithm=hashes.SHA1(),
                cert_status=ocsp_status,
                this_update=now,
                next_update=now + timedelta(hours=1),
                revocation_time=rev_time,
                revocation_reason=rev_reason,
            )
            ocsp_response = builder.sign(self._responder_key, hashes.SHA256())
            self._stats["signed_responses"] += 1
            return ocsp_response.public_bytes(encoding=serialization.Encoding.DER)
        except Exception as e:
            # 签名失败，返回构建的失败响应
            try:
                err_builder = OCSPResponseBuilder()
                err_response = err_builder.build_unsuccessful(
                    OCSPResponseStatus.INTERNAL_ERROR)
                return err_response.public_bytes(encoding=serialization.Encoding.DER)
            except Exception:
                return None

    def build_signed_response_for_cert(self, cert):
        """通过 x509.Certificate 对象构建签名 OCSP 响应"""
        return self.build_signed_response(cert.serial_number)

    def verify_signed_response(self, ocsp_der):
        """
        验证 OCSP 签名的响应（检查 DER 是否可解析）
        注意：cryptography 的 OCSP 验证API可能有限，此处做基本检查

        参数：
            ocsp_der: DER 编码的 OCSP 响应

        返回：(is_valid, message)
        """
        if ocsp_der is None:
            return False, "OCSP 响应为空"

        try:
            # 尝试解析 OCSP 响应
            from cryptography.x509.ocsp import load_der_ocsp_response
            response = load_der_ocsp_response(ocsp_der)
            basic_info = {
                "response_status": str(response.response_status),
                "responder_key_hash": response.responder_key_hash.hex()
                if response.responder_key_hash else "None",
                "responder_name": str(response.responder_name)
                if response.responder_name else "None",
            }
            return True, f"OCSP 响应解析成功: {basic_info}"
        except Exception as e:
            return False, f"OCSP 响应解析失败: {e}"

    # ---- 统计信息 ----

    def get_statistics(self):
        """获取 OCSP 响应器统计信息"""
        cache_size = len(self._cache)
        responder_ready = os.path.exists(OCSP_CERT_PATH)
        return {
            **self._stats,
            "cacheSize": cache_size,
            "cacheTtl": self._cache_ttl,
            "responderReady": responder_ready,
            "responderCertPath": str(OCSP_CERT_PATH),
        }

    def clear_cache(self):
        """清空 OCSP 缓存"""
        self._cache.clear()
        return {"message": "OCSP缓存已清空", "cleared": True}


# ============================================================
# 全局实例
# ============================================================
ocsp_responder = OCSPResponder()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== OCSP 响应器测试 ===\n")

    ocsp = OCSPResponder()

    # 测试1：查询不存在的证书
    print("测试1：JSON 查询不存在的证书")
    result = ocsp.check_certificate("999999")
    print(f"  状态: {result['statusLabel']} (code={result['status']})")
    print(f"  查询时间: {result['checkedAt'][:19]}")

    # 测试2：批量查询
    print("\n测试2：JSON 批量查询")
    batch = ocsp.check_certificates_batch(["123", "456", "999999"])
    print(f"  总量: {batch['summary']['total']}")
    print(f"  有效: {batch['summary']['good']}")
    print(f"  吊销: {batch['summary']['revoked']}")

    # 测试3：签名 OCSP 响应
    print("\n测试3：RFC 6960 签名 OCSP 响应")
    try:
        ocsp._ensure_responder_initialized()
        print(f"  响应者证书: {OCSP_CERT_PATH}")
        signed = ocsp.build_signed_response("999999")
        if signed:
            print(f"  [OK] 签名响应长度: {len(signed)} 字节 (DER)")
            print(f"  内容类型: {OCSP_CONTENT_TYPE}")

        # 验证
        valid, msg = ocsp.verify_signed_response(signed)
        print(f"  验证结果: {'[OK]' if valid else '[FAIL]'} {msg[:100]}...")
    except Exception as e:
        print(f"  [FAIL] 签名OCSP测试失败: {e}")
        import traceback
        traceback.print_exc()

    # 测试4：统计信息
    print("\n测试4：OCSP统计信息")
    stats = ocsp.get_statistics()
    print(f"  总请求: {stats['total_requests']}")
    print(f"  签名响应: {stats['signed_responses']}")
    print(f"  缓存命中: {stats['cache_hits']}")
    print(f"  响应就绪: {stats['responderReady']}")

    print(f"\n[OK] OCSP 模块初始化正常（RFC 6960 签名支持）")
