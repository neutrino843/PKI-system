"""
================================================================
  CRL安全性加固模块（security_crl.py）
  功能：修复CRL数据的完整性保护和吊销时间准确性

  修复风险项：
  - CRL-01：JSON吊销数据可篡改 → HMAC完整性校验
  - CRL-02：吊销时间不准确 → 真实吊销时间保留
  - COMM-02：数据完整性 → 读取时自动校验

  通俗解释：
  就像公安局的"挂失身份证数据库"——
  不仅记录谁什么时候挂失了身份证，
  还对数据库加了一把"防篡改电子锁"（HMAC），
  如果有人偷偷修改了数据库，立刻就能发现。
================================================================
"""

import os
import json
import hmac
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
CRL_DATA_FILE = BASE_DIR / "crl" / "revoked_certs_secure.json"


# ============================================================
# 安全的吊销数据管理器（含HMAC完整性校验）
# ============================================================
class SecureRevokedList:
    """
    安全的吊销数据管理器

    与老版本的区别：
    旧版：revoked_certs.json（明文JSON，可被随意修改）
    新版：revoked_certs_secure.json（含HMAC签名，防篡改）

    通俗解释：
    就像给重要文件加上"防伪封条"——
    任何人想打开文件修改内容，
    封条就会破损，立刻被发现。
    """

    def __init__(self):
        self._hmac_key = self._get_hmac_key()

    def _get_hmac_key(self):
        """获取HMAC密钥（从环境变量读取）"""
        key = os.environ.get("PKI_CRL_HMAC_KEY", "")
        if not key:
            # 开发环境使用默认密钥（生产环境必须设置环境变量）
            key = "pki_crl_dev_key_2026"
        return key.encode("utf-8")

    def _calculate_hmac(self, data):
        """计算数据的HMAC值"""
        payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
        h = hmac.new(self._hmac_key, payload.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()

    def load(self):
        """
        加载吊销数据（含完整性校验）

        返回：吊销列表，如果数据被篡改则返回空列表并告警
        """
        if not CRL_DATA_FILE.exists():
            return []

        try:
            with open(CRL_DATA_FILE, "r", encoding="utf-8") as f:
                container = json.load(f)

            stored_hmac = container.get("hmac", "")
            data = container.get("data", [])

            # 计算实际HMAC并与存储的比较
            expected_hmac = self._calculate_hmac(data)

            if stored_hmac != expected_hmac:
                print("\n[0x1f6a8] [安全告警] CRL吊销数据完整性校验失败！")
                print("   数据可能已被篡改！将使用空列表继续运行。")
                print(f"   预期HMAC：{expected_hmac[:16]}...")
                print(f"   实际HMAC：{stored_hmac[:16]}...")
                return []  # 数据不可信，返回空列表

            return data

        except (json.JSONDecodeError, KeyError) as e:
            print(f"\n[WARN] CRL数据文件解析失败：{e}")
            return []

    def save(self, revoked_list):
        """
        保存吊销数据（含HMAC签名）

        参数：
            revoked_list: 证书吊销信息列表
                每个条目包含：
                - serial: 证书序列号
                - name: 证书持有人
                - reason: 吊销原因
                - revoked_at: 真实的吊销时间（ISO格式）
        """
        # 计算HMAC
        hmac_value = self._calculate_hmac(revoked_list)

        container = {
            "hmac": hmac_value,
            "data": revoked_list,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        # 确保目录存在
        CRL_DATA_FILE.parent.mkdir(exist_ok=True)

        with open(CRL_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(container, f, ensure_ascii=False, indent=2)

    def revoke(self, serial_number, name, reason, reason_desc):
        """
        吊销一张证书（记录真实吊销时间）

        与旧版的区别：
        - 旧版：CRL生成时用当前时间覆盖所有吊销时间
        - 新版：吊销时立即记录真实时间，保存在数据中

        参数：
            serial_number: 证书序列号
            name: 证书持有人
            reason: 吊销原因代码
            reason_desc: 吊销原因描述
        """
        revoked_list = self.load()
        serial_str = str(serial_number)

        # 检查是否已吊销
        if any(item["serial"] == serial_str for item in revoked_list):
            print(f"  [WARN] 证书 {name} 已被吊销，无需重复操作")
            return False

        # 记录真实的吊销时间（精确到秒）
        real_revoked_at = datetime.now(timezone.utc).isoformat()

        revoked_list.append({
            "serial": serial_str,
            "name": name,
            "reason": reason,
            "reason_desc": reason_desc,
            "revoked_at": real_revoked_at,  # 保存真实吊销时间
        })

        self.save(revoked_list)

        print(f"  [OK] 证书 '{name}' 已成功吊销")
        print(f"  ├─ 序列号：{serial_str}")
        print(f"  ├─ 原因：{reason_desc}")
        print(f"  └─ 吊销时间：{real_revoked_at[:19]}")
        return True

    def is_revoked(self, serial_number):
        """检查证书是否已被吊销"""
        revoked_list = self.load()
        serial_str = str(serial_number)
        return any(item["serial"] == serial_str for item in revoked_list)

    def get_revoked_list(self):
        """获取吊销列表"""
        return self.load()

    def verify_integrity(self):
        """
        验证CRL数据的完整性

        返回：(is_valid, message)
        """
        if not CRL_DATA_FILE.exists():
            return True, "无CRL数据文件"

        try:
            revoked_list = self.load()
            # 如果load返回空列表但文件存在，可能数据被篡改
            if not revoked_list and CRL_DATA_FILE.stat().st_size > 50:
                return False, "CRL数据完整性校验失败（数据可能被篡改）"
            return True, f"CRL数据完整，共 {len(revoked_list)} 条记录"
        except Exception as e:
            return False, f"CRL数据校验异常：{e}"


# ============================================================
# 全局实例
# ============================================================
secure_crl = SecureRevokedList()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== CRL安全加固模块测试 ===\n")

    s = SecureRevokedList()

    # 测试1：吊销证书（使用真实时间）
    print("测试1：吊销证书（记录真实时间）")
    s.revoke("123456", "测试用户A", "affiliationChanged", "隶属关系变更")

    # 测试2：验证完整性
    is_valid, msg = s.verify_integrity()
    print(f"\n测试2：完整性验证")
    print(f"  {'[OK]' if is_valid else '[FAIL]'} {msg}")

    # 测试3：篡改检测
    print("\n测试3：篡改检测（模拟数据被修改）")
    if CRL_DATA_FILE.exists():
        with open(CRL_DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 模拟篡改数据
        data["data"].append({"serial": "FAKE", "name": "伪造"})
        with open(CRL_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)

        is_valid, msg = s.verify_integrity()
        print(f"  {'[OK] 检测到篡改' if not is_valid else '[FAIL] 未检测到'}")

    # 测试4：查询
    revoked = s.get_revoked_list()
    print(f"\n测试4：当前吊销列表（{len(revoked)}条）")
    for item in revoked:
        print(f"  - {item['name']}: {item['revoked_at'][:19]}")
