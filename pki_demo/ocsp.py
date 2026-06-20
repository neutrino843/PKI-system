"""
================================================================
  OCSP 在线证书状态协议响应器 (ocsp.py)
  标准：RFC 6960 - Online Certificate Status Protocol
  功能：实时查询证书吊销状态，替代CRL的延迟查询
================================================================
"""

import os
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from .security_crl import SecureRevokedList

BASE_DIR = Path(__file__).parent.resolve()

# OCSP 响应状态码
OCSP_STATUS_GOOD = 0        # 证书状态良好
OCSP_STATUS_REVOKED = 1     # 证书已吊销
OCSP_STATUS_UNKNOWN = 2     # 证书状态未知

OCSP_STATUS_LABELS = {
    OCSP_STATUS_GOOD: "good",
    OCSP_STATUS_REVOKED: "revoked",
    OCSP_STATUS_UNKNOWN: "unknown",
}


# ============================================================
# OCSP 响应器
# ============================================================

class OCSPResponder:
    """
    OCSP 在线证书状态协议响应器

    功能：
    - 查询单张证书的吊销状态
    - 批量查询（多张证书同时查询）
    - 缓存加速（减少数据库查询）

    对比CRL：
    - OCSP：实时查询，每次查一张，响应快
    - CRL：定时下载，批量查，有延迟（最长7天）
    """

    def __init__(self, cache_ttl=60):
        """
        初始化OCSP响应器

        参数：
            cache_ttl: 缓存有效期（秒），默认60秒
        """
        self._crl = SecureRevokedList()
        self._cache = {}
        self._cache_ttl = cache_ttl
        self._stats = {
            "total_requests": 0,
            "good_responses": 0,
            "revoked_responses": 0,
            "unknown_responses": 0,
            "cache_hits": 0,
        }

    def _get_cache_key(self, serial_number):
        """生成缓存键"""
        return f"ocsp:{serial_number}"

    def _check_cache(self, serial_number):
        """检查缓存"""
        key = self._get_cache_key(serial_number)
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["time"] < self._cache_ttl:
                self._stats["cache_hits"] += 1
                return entry["status"]
        return None

    def _update_cache(self, serial_number, status):
        """更新缓存"""
        key = self._get_cache_key(serial_number)
        self._cache[key] = {
            "status": status,
            "time": time.time(),
        }
        # 清理过期缓存
        self._cleanup_cache()

    def _cleanup_cache(self):
        """清理过期缓存"""
        now = time.time()
        expired = [k for k, v in self._cache.items()
                   if now - v["time"] > self._cache_ttl * 2]
        for k in expired:
            del self._cache[k]

    def check_certificate(self, serial_number):
        """
        查询单张证书的OCSP状态

        参数：
            serial_number: 证书序列号（字符串或整数）

        返回：{
            "serial": "证书序列号",
            "status": 0 (good) / 1 (revoked) / 2 (unknown),
            "statusLabel": "good" / "revoked" / "unknown",
            "revokedAt": "吊销时间（仅 revoked 时）",
            "reason": "吊销原因（仅 revoked 时）",
            "checkedAt": "查询时间"
        }
        """
        serial_str = str(serial_number)
        self._stats["total_requests"] += 1

        # 检查缓存
        cached = self._check_cache(serial_str)
        if cached is not None:
            status = cached
        else:
            # 查询吊销列表
            try:
                revoked = self._crl.is_revoked(serial_str)
                status = OCSP_STATUS_REVOKED if revoked else OCSP_STATUS_GOOD
            except Exception:
                status = OCSP_STATUS_UNKNOWN

            self._update_cache(serial_str, status)

        # 统计数据
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

        # 如果已吊销，附加吊销信息
        if status == OCSP_STATUS_REVOKED:
            for item in self._crl.get_revoked_list():
                if item["serial"] == serial_str:
                    result["revokedAt"] = item.get("revoked_at", "")
                    result["reason"] = item.get("reason", "unspecified")
                    result["reasonDesc"] = item.get("reason_desc", "")
                    break

        return result

    def check_certificates_batch(self, serial_numbers):
        """
        批量查询多张证书的OCSP状态

        参数：
            serial_numbers: 证书序列号列表

        返回：{
            "results": [ { 单张证书状态 }, ... ],
            "summary": {
                "total": 3,
                "good": 2,
                "revoked": 1,
                "unknown": 0
            }
        }
        """
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
        """
        通过证书文件查询OCSP状态

        参数：
            cert_path: 证书文件路径

        返回：同 check_certificate()
        """
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

    def get_statistics(self):
        """获取OCSP响应器统计信息"""
        cache_size = len(self._cache)
        return {
            **self._stats,
            "cacheSize": cache_size,
            "cacheTtl": self._cache_ttl,
        }

    def clear_cache(self):
        """清空OCSP缓存"""
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
    print("测试1：查询不存在的证书")
    result = ocsp.check_certificate("999999")
    print(f"  状态: {result['statusLabel']} (code={result['status']})")
    print(f"  查询时间: {result['checkedAt'][:19]}")

    # 测试2：批量查询
    print("\n测试2：批量查询")
    batch = ocsp.check_certificates_batch(["123", "456", "999999"])
    print(f"  总量: {batch['summary']['total']}")
    print(f"  有效: {batch['summary']['good']}")
    print(f"  吊销: {batch['summary']['revoked']}")

    # 测试3：统计信息
    print("\n测试3：OCSP统计信息")
    stats = ocsp.get_statistics()
    print(f"  总请求: {stats['total_requests']}")
    print(f"  缓存命中: {stats['cache_hits']}")
    print(f"  缓存大小: {stats['cacheSize']}")

    print(f"\n[OK] 模块初始化正常")
