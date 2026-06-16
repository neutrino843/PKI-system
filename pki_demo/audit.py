

import os
import json
import hmac
import hashlib
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).parent.resolve()
AUDIT_LOG_FILE = BASE_DIR / "data" / "audit.log"
ALERT_LOG_FILE = BASE_DIR / "data" / "alerts.log"


# ============================================================
# 事件类型常量
# ============================================================
EVENT_LOGIN = "LOGIN"                   # 登录
EVENT_LOGOUT = "LOGOUT"                 # 退出
EVENT_CA_CREATE = "CA_CREATE"           # 创建根CA
EVENT_KEY_GEN = "KEY_GEN"               # 生成密钥
EVENT_CSR_CREATE = "CSR_CREATE"         # 创建CSR
EVENT_CSR_APPROVE = "CSR_APPROVE"       # 审核CSR
EVENT_CERT_ISSUE = "CERT_ISSUE"         # 签发证书
EVENT_CERT_REVOKE = "CERT_REVOKE"       # 吊销证书
EVENT_CRL_GEN = "CRL_GEN"               # 生成CRL
EVENT_P12_EXPORT = "P12_EXPORT"         # 导出PKCS#12
EVENT_AUTH_FAIL = "AUTH_FAIL"           # 认证失败
EVENT_USER_MGMT = "USER_MGMT"           # 用户管理操作

# TSA 事件类型
EVENT_TSA_TIMESTAMP = "TSA_TIMESTAMP"           # 时间戳签发
EVENT_TSA_VERIFY = "TSA_VERIFY"                 # 时间戳验签
EVENT_TSA_CERT_ISSUE = "TSA_CERT_ISSUE"         # TSA证书签发
EVENT_TSA_RATE_LIMIT = "TSA_RATE_LIMIT"         # 速率限制触发
EVENT_TSA_REPLAY = "TSA_REPLAY"                 # 重放攻击检测
EVENT_TSA_SCENARIO = "TSA_SCENARIO"             # 业务场景使用


# ============================================================
# 审计日志记录器
# ============================================================
class AuditLogger:
    """
    不可篡改的审计日志系统
    """

    def __init__(self):
        self._ensure_data_dir()
        self._alert_thresholds = {
            "REVOKE_CERT": {"count": 5, "window": 300},     # 5分钟内吊销超过5张
            "AUTH_FAIL": {"count": 5, "window": 300},       # 5分钟内认证失败超过5次
            "ISSUE_CERT": {"count": 20, "window": 300},     # 5分钟内签发超过20张
        }
        self._event_counts = defaultdict(list)

    def _ensure_data_dir(self):
        """确保数据目录存在"""
        data_dir = BASE_DIR / "data"
        data_dir.mkdir(exist_ok=True)

    def _get_hmac_key(self):
        """获取HMAC密钥（环境变量必须设置，拒绝硬编码默认值）"""
        key = os.environ.get("PKI_AUDIT_HMAC_KEY")
        if not key:
            raise RuntimeError(
                "严重安全错误：PKI_AUDIT_HMAC_KEY 环境变量未设置！\n"
                "请运行 setup_env.bat 配置环境变量后再启动。\n"
                "不允许使用硬编码默认密钥，否则审计日志可被伪造。"
            )
        return key.encode("utf-8")

    def _get_last_hash(self):
        """获取最后一条日志的哈希值（链式哈希的上一环）"""
        if not AUDIT_LOG_FILE.exists():
            return "0" * 64  # 初始哈希值

        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if not lines:
            return "0" * 64

        last_line = lines[-1].strip()
        try:
            last_entry = json.loads(last_line)
            return last_entry.get("hash", "0" * 64)
        except (json.JSONDecodeError, KeyError):
            return "0" * 64

    def _calculate_hash(self, entry):
        """
        计算日志条目的链式哈希

        通俗解释：
        就像用铁环串链子——每个铁环（日志条目）
        都扣着前一个铁环（前一条日志的哈希值）。
        如果有人想断开中间某个铁环，
        后面的铁环就全都扣不上了。
        """
        h = hmac.new(
            self._get_hmac_key(),
            digestmod=hashlib.sha256
        )
        # 对所有字段排序后计算哈希
        sorted_data = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        h.update(sorted_data.encode("utf-8"))
        return h.hexdigest()

    def log(self, event_type, username, action, resource,
            result="SUCCESS", detail="", user_role=""):
        """
        记录一条审计日志

        参数：
            event_type: 事件类型（如 LOGIN, CERT_ISSUE）
            username: 操作人用户名
            action: 操作动作（CREATE, READ, UPDATE, DELETE）
            resource: 操作对象（如证书序列号、文件名）
            result: 操作结果（SUCCESS, FAILURE）
            detail: 详细描述
            user_role: 操作人角色
        """
        prev_hash = self._get_last_hash()

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "username": username,
            "user_role": user_role or "",
            "action": action,
            "resource": str(resource),
            "result": result,
            "detail": detail,
            "prev_hash": prev_hash,
        }

        # 计算链式哈希
        entry["hash"] = self._calculate_hash(entry)

        # 写入日志文件
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

        # 检查异常模式
        self._check_alert_threshold(event_type)

        return entry

    def _check_alert_threshold(self, event_type):
        """
        检查异常操作阈值

        通俗解释：
        就像安防系统的"异常行为检测"——
        如果有人在短时间内做了很多敏感操作，
        系统会自动触发告警，提醒管理员注意。
        """
        now = time.time()
        threshold = self._alert_thresholds.get(event_type)

        if not threshold:
            return

        # 清理过期记录
        self._event_counts[event_type] = [
            t for t in self._event_counts[event_type]
            if now - t < threshold["window"]
        ]

        # 添加当前记录
        self._event_counts[event_type].append(now)

        # 检查是否超过阈值
        if len(self._event_counts[event_type]) >= threshold["count"]:
            alert_msg = (
                f"[告警] 事件 {event_type} 在 "
                f"{threshold['window']}秒内发生 "
                f"{len(self._event_counts[event_type])}次 "
                f"（阈值：{threshold['count']}次）"
            )
            self._write_alert(alert_msg)

    def _write_alert(self, alert_msg):
        """写入告警日志"""
        alert_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert": alert_msg,
        }
        with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_entry, ensure_ascii=False) + "\n")
        print(f"\n[WARN]  {alert_msg}")

    def verify_integrity(self):
        """
        验证审计日志的完整性

        通俗解释：
        检查整条"哈希链"是否完整——
        就像检查铁链上有没有被断开的环节。

        返回：
            (is_valid, checked_count, errors)
        """
        if not AUDIT_LOG_FILE.exists():
            return True, 0, []

        errors = []
        count = 0
        prev_hash = "0" * 64

        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    count += 1

                    # 检查哈希链连接
                    if entry.get("prev_hash", "") != prev_hash:
                        errors.append(
                            f"第{line_num}行：哈希链断裂！"
                            f"期望前序哈希 {prev_hash[:16]}...，"
                            f"实际 {entry.get('prev_hash', 'NONE')[:16]}..."
                        )

                    # 重新计算哈希，验证完整性
                    stored_hash = entry.get("hash", "")
                    # 移除hash字段后重新计算
                    entry_copy = {k: v for k, v in entry.items() if k != "hash"}
                    h = hmac.new(
                        self._get_hmac_key(),
                        json.dumps(entry_copy, sort_keys=True,
                                   ensure_ascii=False).encode("utf-8"),
                        hashlib.sha256
                    )
                    calculated_hash = h.hexdigest()

                    if calculated_hash != stored_hash:
                        errors.append(
                            f"第{line_num}行：日志内容被篡改！"
                        )

                    prev_hash = stored_hash

                except (json.JSONDecodeError, KeyError) as e:
                    errors.append(f"第{line_num}行：解析失败 - {e}")

        return len(errors) == 0, count, errors

    def query(self, event_type=None, username=None, limit=50):
        """
        查询审计日志

        参数：
            event_type: 事件类型过滤
            username: 用户名过滤
            limit: 返回条数
        """
        if not AUDIT_LOG_FILE.exists():
            return []

        results = []
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if event_type and entry.get("event_type") != event_type:
                        continue
                    if username and entry.get("username") != username:
                        continue
                    results.append(entry)
                except json.JSONDecodeError:
                    continue

        return results[-limit:]

    def get_statistics(self):
        """
        获取审计统计概览
        """
        if not AUDIT_LOG_FILE.exists():
            return {"total_events": 0, "by_type": {}, "by_user": {}}

        stats = {
            "total_events": 0,
            "by_type": defaultdict(int),
            "by_user": defaultdict(int),
        }

        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    stats["total_events"] += 1
                    stats["by_type"][entry["event_type"]] += 1
                    stats["by_user"][entry["username"]] += 1
                except (json.JSONDecodeError, KeyError):
                    continue

        return stats


# ============================================================
# 全局审计日志实例
# ============================================================
audit_logger = AuditLogger()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== 审计日志模块测试 ===\n")

    al = AuditLogger()

    # 测试1：记录多条日志
    print("记录测试日志...")
    al.log("LOGIN", "admin", "LOGIN", "system", "SUCCESS", "管理员登录系统", "ca_admin")
    al.log("CERT_ISSUE", "admin", "CREATE", "cert_001", "SUCCESS", "为用户张三签发证书", "ca_admin")
    al.log("CERT_REVOKE", "admin", "DELETE", "cert_001", "SUCCESS", "吊销张三证书", "ca_admin")

    # 测试2：验证完整性
    is_valid, count, errors = al.verify_integrity()
    print(f"\n日志完整性验证：{'[OK] 通过' if is_valid else '[FAIL] 失败'}")
    print(f"检查条目数：{count}")
    if errors:
        for e in errors:
            print(f"  [FAIL] {e}")

    # 测试3：查询日志
    print("\n最近操作日志：")
    for entry in al.query(limit=5):
        print(f"  [{entry['timestamp'][:19]}] {entry['event_type']} "
              f"- {entry['username']} - {entry['detail']}")

    # 测试4：统计
    stats = al.get_statistics()
    print(f"\n统计概览：")
    print(f"  总事件数：{stats['total_events']}")
    print(f"  按类型：{dict(stats['by_type'])}")
    print(f"  按用户：{dict(stats['by_user'])}")
