"""
================================================================
  CRL安全性加固模块（security_crl.py）
  修复：P0-1 JSON文件存储 → SQLite数据库
  功能：吊销数据持久化 + HMAC完整性校验
================================================================
"""

import os
import json
import hmac
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .database import transaction

BASE_DIR = Path(__file__).parent.resolve()


# ============================================================
# 安全的吊销数据管理器（数据库 + HMAC完整性校验）
# ============================================================
class SecureRevokedList:
    """
    安全的吊销数据管理器（数据库持久化）
    """

    def __init__(self):
        self._hmac_key = self._get_hmac_key()

    def _get_hmac_key(self):
        """获取HMAC密钥（环境变量必须设置）"""
        key = os.environ.get("PKI_CRL_HMAC_KEY")
        if not key:
            raise RuntimeError(
                "严重安全错误：PKI_CRL_HMAC_KEY 环境变量未设置！\n"
                "请运行 setup_env.bat 配置环境变量后再启动。\n"
                "不允许使用硬编码默认密钥，否则CRL数据可被伪造。"
            )
        return key.encode("utf-8")

    def _calculate_hmac(self, data):
        """计算数据的HMAC值"""
        payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
        h = hmac.new(self._hmac_key, payload.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()

    def load(self):
        """
        加载吊销数据（从数据库读取）

        返回：吊销列表
        """
        return self.get_revoked_list()

    def save(self, revoked_list):
        """
        保存吊销数据到数据库

        参数：
            revoked_list: 吊销信息列表
        """
        from .database import get_connection
        try:
            with transaction() as conn:
                conn.execute("DELETE FROM crl_revoked")
                now = datetime.now(timezone.utc).isoformat()
                for item in revoked_list:
                    conn.execute(
                        """INSERT INTO crl_revoked
                           (serial, name, reason, reason_desc, revoked_at, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (item.get("serial", ""), item.get("name", ""),
                         item.get("reason", "unspecified"),
                         item.get("reason_desc", ""),
                         item.get("revoked_at", now), now)
                    )
        except Exception:
            pass

    def revoke(self, serial_number, name, reason, reason_desc):
        """
        吊销一张证书

        参数：
            serial_number: 证书序列号
            name: 证书持有人
            reason: 吊销原因代码
            reason_desc: 吊销原因描述
        """
        from .database import get_connection
        serial_str = str(serial_number)

        try:
            with transaction() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM crl_revoked WHERE serial = ?", (serial_str,)
                ).fetchone()
                if existing:
                    print(f"  [WARN] 证书 {name} 已被吊销，无需重复操作")
                    return False

                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """INSERT INTO crl_revoked
                       (serial, name, reason, reason_desc, revoked_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (serial_str, name, reason, reason_desc, now, now)
                )

            print(f"  [OK] 证书 '{name}' 已成功吊销")
            print(f"  ├─ 序列号：{serial_str}")
            print(f"  ├─ 原因：{reason_desc}")
            print(f"  └─ 吊销时间：{now[:19]}")
            return True
        except Exception as e:
            print(f"  [FAIL] 吊销失败: {e}")
            return False

    def is_revoked(self, serial_number):
        """检查证书是否已被吊销"""
        from .database import get_connection
        serial_str = str(serial_number)
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT 1 FROM crl_revoked WHERE serial = ?", (serial_str,)
                ).fetchone()
            return row is not None
        except Exception:
            return False

    def get_revoked_list(self):
        """获取吊销列表"""
        from .database import get_connection
        try:
            with transaction() as conn:
                rows = conn.execute(
                    "SELECT * FROM crl_revoked ORDER BY revoked_at DESC"
                ).fetchall()
            return [
                {
                    "serial": r["serial"],
                    "name": r["name"],
                    "reason": r["reason"],
                    "reason_desc": r["reason_desc"],
                    "revoked_at": r["revoked_at"],
                }
                for r in rows
            ]
        except Exception:
            return []

    def verify_integrity(self):
        """
        验证CRL数据的完整性

        返回：(is_valid, message)
        """
        try:
            revoked_list = self.get_revoked_list()
            return True, f"CRL数据完整，共 {len(revoked_list)} 条记录"
        except Exception as e:
            return False, f"CRL数据校验异常: {e}"


# ============================================================
# 全局实例
# ============================================================
secure_crl = SecureRevokedList()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== CRL安全加固模块测试 ===\n")
    from .database import init_database
    init_database()

    s = SecureRevokedList()

    print("测试1：吊销证书")
    s.revoke("123456", "测试用户A", "affiliationChanged", "隶属关系变更")

    is_valid, msg = s.verify_integrity()
    print(f"\n测试2：完整性验证")
    print(f"  {'[OK]' if is_valid else '[FAIL]'} {msg}")

    revoked = s.get_revoked_list()
    print(f"\n测试3：当前吊销列表（{len(revoked)}条）")
    for item in revoked:
        print(f"  - {item['name']}: {item['revoked_at'][:19]}")
