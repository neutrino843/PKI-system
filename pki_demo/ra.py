"""
================================================================
  RA注册审核模块（ra.py）
  功能：实现证书申请的审核批准流程（CA与RA分离）

  修复风险项：
  - CLM-01：无RA审核机制 → RA负责审核，CA只信任RA

  工作流程对比：
  旧版：用户 → CA（直接签发）-> 无审核
  新版：用户 → RA（审核身份）→ CA（信任RA，签发证书）

  通俗解释：
  就像办理护照——
  用户先到派出所（RA）提交材料、审核身份，
  派出所审核通过后，把材料送到出入境管理局（CA），
  管理局只信任派出所的审核结果，不再重复审核。
================================================================
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
PENDING_FILE = BASE_DIR / "data" / "pending_csr.json"
APPROVED_FILE = BASE_DIR / "data" / "approved_csr.json"


# ============================================================
# CSR状态枚举
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
    RA（注册中心）管理器

    负责：
    1. 接收用户的证书申请
    2. 审核用户身份信息
    3. 批准/拒绝申请
    4. 将批准的申请转交CA签发

    通俗解释：
    RA就像派出所的办证窗口——
    1. 收材料（接收CSR）
    2. 核验身份（审核）
    3. 签字同意（批准）
    4. 送到CA制证（转交签发）
    """

    def __init__(self):
        self._ensure_data_dir()

    def _ensure_data_dir(self):
        """确保数据目录存在"""
        data_dir = BASE_DIR / "data"
        data_dir.mkdir(exist_ok=True)

    def _load_pending(self):
        """加载待审核列表"""
        if PENDING_FILE.exists():
            with open(PENDING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save_pending(self, pending_list):
        """保存待审核列表"""
        with open(PENDING_FILE, "w", encoding="utf-8") as f:
            json.dump(pending_list, f, ensure_ascii=False, indent=2)

    def _load_approved(self):
        """加载已批准列表"""
        if APPROVED_FILE.exists():
            with open(APPROVED_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save_approved(self, approved_list):
        """保存已批准列表"""
        with open(APPROVED_FILE, "w", encoding="utf-8") as f:
            json.dump(approved_list, f, ensure_ascii=False, indent=2)

    def submit_csr(self, csr_id, username, org, csr_filepath, applicant="unknown"):
        """
        提交证书申请（用户操作）

        参数：
            csr_id: 申请唯一ID
            username: 申请的用户名
            org: 组织/部门
            csr_filepath: CSR文件路径
            applicant: 申请人

        通俗解释：
        用户在RA窗口提交"身份证申请表"，
        窗口收下材料，放入"待审核"的文件夹。
        """
        pending = self._load_pending()

        # 检查是否重复提交
        if any(item["csr_id"] == csr_id for item in pending):
            return False, "该申请已提交，请勿重复操作"

        pending.append({
            "csr_id": csr_id,
            "username": username,
            "org": org,
            "csr_filepath": csr_filepath,
            "applicant": applicant,
            "status": CSRStatus.PENDING,
            "submitted_at": datetime.now().isoformat(),
            "audit_history": [
                {
                    "action": "submit",
                    "by": applicant,
                    "at": datetime.now().isoformat(),
                    "note": "用户提交证书申请"
                }
            ]
        })

        self._save_pending(pending)
        return True, f"申请 {csr_id} 已提交，等待RA审核"

    def approve_csr(self, csr_id, reviewer="ra_operator", review_note=""):
        """
        初审证书申请（RA操作员操作）- 四眼原则第1步

        参数：
            csr_id: 申请ID
            reviewer: 初审人
            review_note: 审核意见

        通俗解释：
        RA审核员1检查用户提交的材料，
        确认无误后签字同意（初审通过），
        还需要另一位RA审核员确认才能最终批准。
        """
        pending = self._load_pending()

        # 查找待审核的申请
        found = None
        for item in pending:
            if item["csr_id"] == csr_id and item["status"] == CSRStatus.PENDING:
                found = item
                break

        if not found:
            return False, f"未找到待初审的申请 {csr_id}"

        # 更新为初审通过
        found["status"] = CSRStatus.FIRST_APPROVED
        found["reviewer_1"] = reviewer
        found["reviewed_at_1"] = datetime.now().isoformat()
        found["audit_history"].append({
            "action": "first_approve",
            "by": reviewer,
            "at": datetime.now().isoformat(),
            "note": review_note or "RA初审通过"
        })

        self._save_pending(pending)
        return True, f"申请 {csr_id} 已通过初审，等待第二位RA审核员确认"

    def second_approve_csr(self, csr_id, reviewer="ra_operator", review_note=""):
        """
        二审批准证书申请（RA操作员操作）- 四眼原则第2步

        需要与初审人不同的RA操作员进行二审。
        """
        pending = self._load_pending()

        found = None
        for item in pending:
            if item["csr_id"] == csr_id and item["status"] == CSRStatus.FIRST_APPROVED:
                found = item
                break

        if not found:
            return False, f"未找到待二审的申请 {csr_id}"

        # 四眼原则：二审人不能与初审人是同一人
        if found.get("reviewer_1") == reviewer:
            return False, "四眼原则违规：二审人不能与初审人是同一人！"

        # 更新为二审通过（可签发）
        found["status"] = CSRStatus.APPROVED
        found["approved_by"] = reviewer
        found["approved_at"] = datetime.now().isoformat()
        found["audit_history"].append({
            "action": "second_approve",
            "by": reviewer,
            "at": datetime.now().isoformat(),
            "note": review_note or "RA二审通过"
        })

        # 移动到已批准列表
        approved = self._load_approved()
        approved.append(found)
        self._save_approved(approved)

        # 从待审核列表中移除
        pending = [item for item in pending if item["csr_id"] != csr_id]
        self._save_pending(pending)

        return True, f"申请 {csr_id} 已通过二审（四眼原则完成），等待CA签发"

    def reject_csr(self, csr_id, reviewer="ra_operator", reject_reason=""):
        """
        拒绝证书申请（RA操作员操作）
        """
        pending = self._load_pending()

        for item in pending:
            if item["csr_id"] == csr_id and item["status"] in [CSRStatus.PENDING, CSRStatus.FIRST_APPROVED]:
                item["status"] = CSRStatus.REJECTED
                item["rejected_by"] = reviewer
                item["rejected_at"] = datetime.now().isoformat()
                item["reject_reason"] = reject_reason
                item["audit_history"].append({
                    "action": "reject",
                    "by": reviewer,
                    "at": datetime.now().isoformat(),
                    "note": reject_reason or "RA审核不通过"
                })
                self._save_pending(pending)
                return True, f"申请 {csr_id} 已拒绝"

        return False, f"未找到申请 {csr_id}"

    def get_pending_list(self):
        """
        获取待审核列表（RA操作员查看）
        """
        return [item for item in self._load_pending()
                if item["status"] in [CSRStatus.PENDING, CSRStatus.FIRST_APPROVED]]

    def get_approved_list(self):
        """
        获取已批准列表（CA管理员查看）
        """
        return [item for item in self._load_approved()
                if item["status"] == CSRStatus.APPROVED]

    def mark_issued(self, csr_id):
        """
        标记已签发（CA签发后调用）

        通俗解释：
        CA制证完成后，在申请表上标记"已制证"，
        表示这份申请已经完成了全部流程。
        """
        approved = self._load_approved()
        for item in approved:
            if item["csr_id"] == csr_id:
                item["status"] = CSRStatus.ISSUED
                item["issued_at"] = datetime.now().isoformat()
                self._save_approved(approved)
                return True
        return False

    def get_statistics(self):
        """
        获取审核统计信息
        """
        pending = self._load_pending()
        approved_list = self._load_approved()

        return {
            "pending_count": len([i for i in pending if i["status"] == CSRStatus.PENDING]),
            "approved_count": len([i for i in approved_list if i["status"] in [CSRStatus.APPROVED, CSRStatus.ISSUED]]),
            "issued_count": len([i for i in approved_list if i["status"] == CSRStatus.ISSUED]),
            "rejected_count": len([i for i in pending if i["status"] == CSRStatus.REJECTED]),
        }


# ============================================================
# 全局实例
# ============================================================
ra_manager = RAManager()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== RA审核模块测试 ===\n")

    ra = RAManager()

    # 测试1：提交申请
    print("测试1：用户提交证书申请")
    success, msg = ra.submit_csr("CSR-001", "张三", "研发部",
                                  "csr/user_张三_csr.pem", "张三")
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")

    # 测试2：查看待审核
    print("\n测试2：待审核列表")
    pending = ra.get_pending_list()
    for item in pending:
        print(f"  - {item['csr_id']}: {item['username']}（{item['org']}）"
              f" 提交时间：{item['submitted_at'][:19]}")

    # 测试3：批准申请
    print("\n测试3：RA批准申请")
    success, msg = ra.approve_csr("CSR-001", "张审核员", "身份信息核实无误")
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")

    # 测试4：查看待签发
    print("\n测试4：待签发列表（RA已批准，等待CA签发）")
    approved = ra.get_approved_list()
    for item in approved:
        print(f"  - {item['csr_id']}: {item['username']}（批准人：{item['approved_by']}）")

    # 测试5：统计
    stats = ra.get_statistics()
    print(f"\n测试5：审核统计")
    for k, v in stats.items():
        print(f"  {k}: {v}")
