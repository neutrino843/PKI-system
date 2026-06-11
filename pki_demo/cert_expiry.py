"""
================================================================
  证书到期检查模块（cert_expiry.py）
  功能：检查证书有效期、到期提醒、自动续期

  修复风险项：
  - CLM-02：无证书到期提醒 → 扫描并告警即将到期的证书

  通俗解释：
  就像身份证到期前公安局会发短信提醒你换证——
  这个模块会定期扫描所有证书，
  找出快要过期的，提醒管理员及时处理。
================================================================
"""

import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend

BASE_DIR = Path(__file__).parent.resolve()
CERT_DIR = BASE_DIR / "certs"


# ============================================================
# 证书到期检查器
# ============================================================
class CertExpiryChecker:
    """
    证书到期检查器

    通俗解释：
    就像"身份证到期提醒服务"——
    自动扫描所有证书，告诉你：
    - 哪些证书已经过期了（红色告警）
    - 哪些证书30天内到期（黄色提醒）
    - 哪些证书还很健康（绿色通过）
    """

    def __init__(self, warning_days=30, critical_days=7):
        """
        初始化
        warning_days: 提前多少天发出到期警告（默认30天）
        critical_days: 提前多少天发出紧急警告（默认7天）
        """
        self.warning_days = warning_days
        self.critical_days = critical_days

    def scan_certificates(self, cert_dir=None):
        """
        扫描目录中的所有PEM证书并检查有效期

        参数：
            cert_dir: 证书目录，默认使用certs/

        返回：{
            "expired": [(文件名, 证书信息, 过期天数)],
            "critical": [(文件名, 证书信息, 剩余天数)],
            "warning": [(文件名, 证书信息, 剩余天数)],
            "valid": [(文件名, 证书信息, 剩余天数)]
        }
        """
        if cert_dir is None:
            cert_dir = CERT_DIR

        if not cert_dir.exists():
            return {"error": f"证书目录不存在：{cert_dir}"}

        result = {
            "expired": [],    # 已过期
            "critical": [],   # 7天内到期
            "warning": [],    # 30天内到期
            "valid": [],      # 有效期充足
        }

        now = datetime.now(timezone.utc)

        for cert_file in cert_dir.glob("*.pem"):
            try:
                with open(cert_file, "rb") as f:
                    cert = x509.load_pem_x509_certificate(
                        f.read(), default_backend()
                    )

                # 获取证书名称
                cn = cert.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                cert_name = cn[0].value if cn else cert_file.stem

                # 计算到期天数
                expiry = cert.not_valid_after_utc
                remaining_days = (expiry - now).days

                cert_info = {
                    "filename": cert_file.name,
                    "name": cert_name,
                    "serial": cert.serial_number,
                    "issued": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
                    "expiry": expiry.strftime("%Y-%m-%d"),
                    "remaining_days": remaining_days,
                }

                if remaining_days < 0:
                    # 已过期
                    cert_info["overdue_days"] = -remaining_days
                    result["expired"].append(cert_info)
                elif remaining_days <= self.critical_days:
                    # 7天内到期（紧急）
                    result["critical"].append(cert_info)
                elif remaining_days <= self.warning_days:
                    # 30天内到期（提醒）
                    result["warning"].append(cert_info)
                else:
                    # 有效期充足
                    result["valid"].append(cert_info)

            except Exception as e:
                print(f"  [WARN] 读取证书失败：{cert_file.name} - {e}")

        return result

    def print_expiry_report(self):
        """
        打印证书到期报告
        """
        print("\n" + "=" * 60)
        print("  证书到期检查报告")
        print(f"  检查日期：{datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("=" * 60)

        results = self.scan_certificates()

        if "error" in results:
            print(f"  [FAIL] {results['error']}")
            return

        # 已过期
        if results["expired"]:
            print(f"\n[已过期] 已过期证书（{len(results['expired'])}张）")
            print("-" * 50)
            for cert in results["expired"]:
                print(f"  [FAIL] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（已过期{cert['overdue_days']}天）")
                print(f"     文件：{cert['filename']}")

        # 紧急到期
        if results["critical"]:
            print(f"\n[紧急] 即将到期（{self.critical_days}天内，{len(results['critical'])}张）")
            print("-" * 50)
            for cert in results["critical"]:
                print(f"  [WARN] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（剩余{cert['remaining_days']}天）")

        # 提醒到期
        if results["warning"]:
            print(f"\n[提醒] 将到期（{self.warning_days}天内，{len(results['warning'])}张）")
            print("-" * 50)
            for cert in results["warning"]:
                print(f"  [INFO] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（剩余{cert['remaining_days']}天）")

        # 有效证书
        if results["valid"]:
            print(f"\n[有效] 有效证书（{len(results['valid'])}张）")
            print("-" * 50)
            for cert in results["valid"]:
                print(f"  [OK] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（剩余{cert['remaining_days']}天）")

        # 汇总
        total = sum(len(v) for v in results.values())
        print(f"\n{'='*60}")
        print(f"  汇总：共 {total} 张证书")
        print(f"  [已过期] {len(results['expired'])}  |  "
              f"[紧急] {len(results['critical'])}  |  "
              f"[提醒] {len(results['warning'])}  |  "
              f"[有效] {len(results['valid'])}")


# ============================================================
# 全局实例
# ============================================================
cert_expiry = CertExpiryChecker()


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== 证书到期检查模块测试 ===\n")

    checker = CertExpiryChecker()
    checker.print_expiry_report()
