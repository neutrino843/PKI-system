"""
================================================================
  RA注册审核模块（ra.py）
  修复：P0-1 JSON文件存储 → SQLite数据库
  功能：实现证书申请的审核批准流程（CA与RA分离）
================================================================
"""

import os
import json
from datetime import datetime
from pathlib import Path

from .database import transaction

BASE_DIR = Path(__file__).parent.resolve()


# ============================================================
# CSR状态常量
# ============================================================
class CSRStatus:
    """CSR申请状态"""
    PENDING = "pending"                 # 待初审
    FIRST_APPROVED = "first_approved"   # 初审通过(需二审)
    APPROVED = "approved"               # 二审通过(可签发)
    REJECTED = "rejected"               # 已拒绝
    ISSUED = "issued"                   # 已签发


# ============================================================
# RA管理器
# ============================================================
class RAManager:
    """
    RA（注册中心）管理器（数据库持久化）

    负责：
    1. 接收用户的证书申请
    2. 审核用户身份信息
    3. 批准/拒绝申请
    4. 将批准的申请转交CA签发
    """

    # ============================================================
    # CSR申请提交
    # ============================================================

    def submit_csr(self, csr_id, username, org, csr_filepath, applicant="unknown"):
        """
        提交证书申请（用户操作）
        """
        from .database import get_connection
        try:
            with transaction() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM pending_csr WHERE csr_id = ?", (csr_id,)
                ).fetchone()
                if existing:
                    return False, "该申请已提交，请勿重复操作"

                now = datetime.now().isoformat()
                audit_entry = json.dumps([{
                    "action": "submit", "by": applicant,
                    "at": now, "note": "用户提交证书申请"
                }], ensure_ascii=False)

                conn.execute(
                    """INSERT INTO pending_csr
                       (csr_id, username, org, csr_filepath, applicant,
                        status, submitted_at, audit_history)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (csr_id, username, org, csr_filepath, applicant,
                     CSRStatus.PENDING, now, audit_entry)
                )
            return True, f"申请 {csr_id} 已提交，等待RA审核"
        except Exception as e:
            return False, f"提交失败: {e}"

    # ============================================================
    # 审核操作
    # ============================================================

    def approve_csr(self, csr_id, reviewer="ra_operator", review_note=""):
        """
        初审证书申请（RA操作员操作）- 四眼原则第1步
        """
        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM pending_csr WHERE csr_id = ? AND status = ?",
                    (csr_id, CSRStatus.PENDING)
                ).fetchone()

                if not row:
                    return False, f"未找到待初审的申请 {csr_id}"

                history = json.loads(row["audit_history"] or "[]")

                now = datetime.now().isoformat()
                history.append({
                    "action": "first_approve", "by": reviewer,
                    "at": now, "note": review_note or "RA初审通过"
                })

                conn.execute(
                    """UPDATE pending_csr SET
                       status = ?, reviewer_1 = ?, reviewed_at_1 = ?,
                       audit_history = ?
                       WHERE csr_id = ?""",
                    (CSRStatus.FIRST_APPROVED, reviewer, now,
                     json.dumps(history, ensure_ascii=False), csr_id)
                )
            return True, f"申请 {csr_id} 已通过初审，等待第二位RA审核员确认"
        except Exception as e:
            return False, f"初审失败: {e}"

    def second_approve_csr(self, csr_id, reviewer="ra_operator", review_note=""):
        """
        二审批准证书申请（四眼原则第2步，需与初审人不同）
        """
        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM pending_csr WHERE csr_id = ? AND status = ?",
                    (csr_id, CSRStatus.FIRST_APPROVED)
                ).fetchone()

                if not row:
                    return False, f"未找到待二审的申请 {csr_id}"

                if row["reviewer_1"] == reviewer:
                    return False, "四眼原则违规：二审人不能与初审人是同一人！"

                history = json.loads(row["audit_history"] or "[]")
                now = datetime.now().isoformat()
                history.append({
                    "action": "second_approve", "by": reviewer,
                    "at": now, "note": review_note or "RA二审通过"
                })

                # 移到已批准表
                conn.execute(
                    """INSERT INTO approved_csr
                       (csr_id, username, org, csr_filepath, applicant, status,
                        submitted_at, reviewer_1, reviewed_at_1,
                        approved_by, approved_at, audit_history)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (row["csr_id"], row["username"], row["org"],
                     row["csr_filepath"], row["applicant"],
                     CSRStatus.APPROVED, row["submitted_at"],
                     row["reviewer_1"], row["reviewed_at_1"],
                     reviewer, now,
                     json.dumps(history, ensure_ascii=False))
                )

                # 从待审核表删除
                conn.execute(
                    "DELETE FROM pending_csr WHERE csr_id = ?", (csr_id,)
                )
            return True, f"申请 {csr_id} 已通过二审（四眼原则完成），等待CA签发"
        except Exception as e:
            return False, f"二审失败: {e}"

    def reject_csr(self, csr_id, reviewer="ra_operator", reject_reason=""):
        """
        拒绝证书申请（RA操作员操作）
        """
        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM pending_csr WHERE csr_id = ? AND status IN (?, ?)",
                    (csr_id, CSRStatus.PENDING, CSRStatus.FIRST_APPROVED)
                ).fetchone()

                if not row:
                    return False, f"未找到申请 {csr_id}"

                history = json.loads(row["audit_history"] or "[]")
                now = datetime.now().isoformat()
                history.append({
                    "action": "reject", "by": reviewer,
                    "at": now, "note": reject_reason or "RA审核不通过"
                })

                conn.execute(
                    """UPDATE pending_csr SET
                       status = ?, rejected_by = ?, rejected_at = ?,
                       reject_reason = ?, audit_history = ?
                       WHERE csr_id = ?""",
                    (CSRStatus.REJECTED, reviewer, now, reject_reason,
                     json.dumps(history, ensure_ascii=False), csr_id)
                )
            return True, f"申请 {csr_id} 已拒绝"
        except Exception as e:
            return False, f"拒绝失败: {e}"

    # ============================================================
    # 查询操作
    # ============================================================

    def get_pending_list(self):
        """获取待审核列表"""
        from .database import get_connection
        try:
            with transaction() as conn:
                rows = conn.execute(
                    "SELECT * FROM pending_csr WHERE status IN (?, ?) ORDER BY submitted_at DESC",
                    (CSRStatus.PENDING, CSRStatus.FIRST_APPROVED)
                ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["audit_history"] = json.loads(item.get("audit_history") or "[]")
                result.append(item)
            return result
        except Exception:
            return []

    def get_approved_list(self):
        """获取已批准（待签发）列表"""
        from .database import get_connection
        try:
            with transaction() as conn:
                rows = conn.execute(
                    "SELECT * FROM approved_csr WHERE status = ? ORDER BY approved_at DESC",
                    (CSRStatus.APPROVED,)
                ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["audit_history"] = json.loads(item.get("audit_history") or "[]")
                result.append(item)
            return result
        except Exception:
            return []

    def get_issued_list(self):
        """获取已签发列表"""
        from .database import get_connection
        try:
            with transaction() as conn:
                rows = conn.execute(
                    "SELECT * FROM approved_csr WHERE status = ? ORDER BY issued_at DESC",
                    (CSRStatus.ISSUED,)
                ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["audit_history"] = json.loads(item.get("audit_history") or "[]")
                result.append(item)
            return result
        except Exception:
            return []

    def mark_issued(self, csr_id):
        """标记已签发"""
        from .database import get_connection
        try:
            with transaction() as conn:
                now = datetime.now().isoformat()
                conn.execute(
                    """UPDATE approved_csr SET status = ?, issued_at = ?
                       WHERE csr_id = ? AND status = ?""",
                    (CSRStatus.ISSUED, now, csr_id, CSRStatus.APPROVED)
                )
            return True
        except Exception:
            return False

    def get_statistics(self):
        """获取审核统计信息"""
        from .database import get_connection
        try:
            with transaction() as conn:
                pending = conn.execute(
                    "SELECT COUNT(*) as cnt FROM pending_csr WHERE status = ?",
                    (CSRStatus.PENDING,)
                ).fetchone()["cnt"]

                first_approved = conn.execute(
                    "SELECT COUNT(*) as cnt FROM pending_csr WHERE status = ?",
                    (CSRStatus.FIRST_APPROVED,)
                ).fetchone()["cnt"]

                approved = conn.execute(
                    "SELECT COUNT(*) as cnt FROM approved_csr WHERE status = ?",
                    (CSRStatus.APPROVED,)
                ).fetchone()["cnt"]

                issued = conn.execute(
                    "SELECT COUNT(*) as cnt FROM approved_csr WHERE status = ?",
                    (CSRStatus.ISSUED,)
                ).fetchone()["cnt"]

                rejected = conn.execute(
                    "SELECT COUNT(*) as cnt FROM pending_csr WHERE status = ?",
                    (CSRStatus.REJECTED,)
                ).fetchone()["cnt"]

            return {
                "pending_count": pending + first_approved,
                "approved_count": approved,
                "issued_count": issued,
                "rejected_count": rejected,
            }
        except Exception:
            return {"pending_count": 0, "approved_count": 0,
                    "issued_count": 0, "rejected_count": 0}


# ============================================================
# 全局实例
# ============================================================
ra_manager = RAManager()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== RA审核模块测试 ===\n")
    from .database import init_database
    init_database()

    ra = RAManager()

    print("测试1：用户提交证书申请")
    success, msg = ra.submit_csr("CSR-001", "User1", "研发部",
                                  "csr/user_User1_csr.pem", "User1")
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")

    print("\n测试2：待审核列表")
    pending = ra.get_pending_list()
    for item in pending:
        print(f"  - {item['csr_id']}: {item['username']}（{item['org']}）")

    print("\n测试3：RA批准申请")
    success, msg = ra.approve_csr("CSR-001", "张审核员", "身份信息核实无误")
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")

    print("\n测试4：待签发列表")
    approved = ra.get_approved_list()
    for item in approved:
        print(f"  - {item['csr_id']}: {item['username']}")

    stats = ra.get_statistics()
    print(f"\n测试5：审核统计")
    for k, v in stats.items():
        print(f"  {k}: {v}")
