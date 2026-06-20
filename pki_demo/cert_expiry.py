"""
================================================================
  证书到期检查与自动告警模块（cert_expiry.py）
  功能：扫描证书有效期、生成检查报告、邮件/Webhook告警
  增强：新增 SMTP 邮件通知 + 企业微信/钉钉 Webhook 推送
================================================================
"""

import os
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend

BASE_DIR = Path(__file__).parent.resolve()
CERT_DIR = BASE_DIR / "certs"


# ============================================================
# 告警通知器
# ============================================================

class AlertNotifier:
    """
    证书到期告警通知器
    支持：控制台打印、SMTP邮件、企业微信Webhook、钉钉Webhook
    """

    def __init__(self):
        self.smtp_enabled = False
        self.smtp_config = {}
        self.webhook_url = ""
        self.webhook_type = ""  # "wecom" or "dingtalk"
        self._load_config()

    def _load_config(self):
        """从环境变量加载通知配置"""
        # SMTP 配置
        smtp_host = os.environ.get("PKI_SMTP_HOST", "")
        smtp_port = os.environ.get("PKI_SMTP_PORT", "465")
        smtp_user = os.environ.get("PKI_SMTP_USER", "")
        smtp_pass = os.environ.get("PKI_SMTP_PASS", "")
        smtp_from = os.environ.get("PKI_SMTP_FROM", "")
        smtp_to = os.environ.get("PKI_SMTP_TO", "")

        if smtp_host and smtp_user and smtp_pass and smtp_to:
            self.smtp_enabled = True
            self.smtp_config = {
                "host": smtp_host,
                "port": int(smtp_port),
                "user": smtp_user,
                "password": smtp_pass,
                "from_addr": smtp_from or smtp_user,
                "to_addr": smtp_to,
            }

        # Webhook 配置（企业微信或钉钉）
        webhook = os.environ.get("PKI_WEBHOOK_URL", "")
        if webhook:
            self.webhook_url = webhook
            if "qyapi.weixin.qq.com" in webhook:
                self.webhook_type = "wecom"
            elif "dingtalk.com" in webhook or "oapi.dingtalk.com" in webhook:
                self.webhook_type = "dingtalk"
            else:
                self.webhook_type = "generic"

    def send_smtp_alert(self, subject, body):
        """通过SMTP发送邮件告警"""
        if not self.smtp_enabled:
            return False, "SMTP未配置"

        try:
            import smtplib
            from email.mime.text import MIMEText

            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = self.smtp_config["from_addr"]
            msg["To"] = self.smtp_config["to_addr"]

            cfg = self.smtp_config
            if cfg["port"] == 465:
                with smtplib.SMTP_SSL(cfg["host"], cfg["port"]) as server:
                    server.login(cfg["user"], cfg["password"])
                    server.sendmail(cfg["from_addr"], [cfg["to_addr"]],
                                    msg.as_string())
            else:
                with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
                    server.starttls()
                    server.login(cfg["user"], cfg["password"])
                    server.sendmail(cfg["from_addr"], [cfg["to_addr"]],
                                    msg.as_string())

            return True, "邮件发送成功"
        except ImportError:
            return False, "smtplib 不可用（Python 标准库应内置）"
        except Exception as e:
            return False, f"邮件发送失败: {e}"

    def send_webhook_alert(self, title, content):
        """通过Webhook发送告警（企业微信/钉钉）"""
        if not self.webhook_url:
            return False, "Webhook未配置"

        try:
            if self.webhook_type == "wecom":
                payload = json.dumps({
                    "msgtype": "markdown",
                    "markdown": {
                        "content": f"## {title}\n{content}",
                    }
                }).encode("utf-8")
            elif self.webhook_type == "dingtalk":
                payload = json.dumps({
                    "msgtype": "markdown",
                    "markdown": {
                        "title": title,
                        "text": f"## {title}\n{content}",
                    }
                }).encode("utf-8")
            else:
                # 通用Webhook：直接POST JSON
                payload = json.dumps({
                    "title": title,
                    "content": content,
                }).encode("utf-8")

            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = resp.read().decode("utf-8")
                return True, f"Webhook发送成功: {result[:100]}"

        except urllib.error.HTTPError as e:
            return False, f"Webhook HTTP错误: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            return False, f"Webhook连接失败: {e.reason}"
        except Exception as e:
            return False, f"Webhook发送失败: {e}"

    def is_configured(self):
        """检查是否配置了至少一种通知方式"""
        return self.smtp_enabled or bool(self.webhook_url)

    def get_config_status(self):
        """获取配置状态"""
        return {
            "smtpEnabled": self.smtp_enabled,
            "smtpTo": self.smtp_config.get("to_addr", ""),
            "webhookUrl": self.webhook_url[:50] + "..." if len(self.webhook_url) > 50 else self.webhook_url,
            "webhookType": self.webhook_type,
            "anyConfigured": self.is_configured(),
        }


# ============================================================
# 证书到期检查器（增强版）
# ============================================================

class CertExpiryChecker:
    """
    证书到期检查器（支持告警通知）
    """

    def __init__(self, warning_days=30, critical_days=7):
        self.warning_days = warning_days
        self.critical_days = critical_days
        self.notifier = AlertNotifier()

    def scan_certificates(self, cert_dir=None):
        """
        扫描目录中的所有PEM证书并检查有效期

        参数：
            cert_dir: 证书目录，默认使用certs/

        返回：{
            "expired": [证书信息],
            "critical": [证书信息],
            "warning": [证书信息],
            "valid": [证书信息]
        }
        """
        if cert_dir is None:
            cert_dir = CERT_DIR

        if not cert_dir.exists():
            return {"error": f"证书目录不存在：{cert_dir}"}

        result = {
            "expired": [],
            "critical": [],
            "warning": [],
            "valid": [],
        }

        now = datetime.now(timezone.utc)

        for cert_file in cert_dir.glob("*.pem"):
            try:
                with open(cert_file, "rb") as f:
                    cert = x509.load_pem_x509_certificate(
                        f.read(), default_backend()
                    )

                cn = cert.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                cert_name = cn[0].value if cn else cert_file.stem

                expiry = cert.not_valid_after_utc
                remaining_days = (expiry - now).days

                cert_info = {
                    "filename": cert_file.name,
                    "name": cert_name,
                    "serial": str(cert.serial_number),
                    "issued": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
                    "expiry": expiry.strftime("%Y-%m-%d"),
                    "remaining_days": remaining_days,
                }

                if remaining_days < 0:
                    cert_info["overdue_days"] = -remaining_days
                    result["expired"].append(cert_info)
                elif remaining_days <= self.critical_days:
                    result["critical"].append(cert_info)
                elif remaining_days <= self.warning_days:
                    result["warning"].append(cert_info)
                else:
                    result["valid"].append(cert_info)

            except Exception as e:
                print(f"  [WARN] 读取证书失败：{cert_file.name} - {e}")

        return result

    def send_alerts(self, scan_result):
        """
        根据扫描结果发送告警通知

        参数：
            scan_result: scan_certificates() 的返回结果

        返回：{
            "sent": True/False,
            "details": [(channel, success, message), ...]
        }
        """
        if "error" in scan_result:
            return {"sent": False, "details": [("console", False, scan_result["error"])]}

        has_issues = bool(scan_result["expired"] or scan_result["critical"] or scan_result["warning"])
        if not has_issues:
            return {"sent": False, "details": [("console", True, "所有证书状态正常，无需告警")]}

        # 构建告警内容
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        title = f"[PKI证书到期告警] {now_str}"

        content_lines = []
        total = sum(len(v) for v in scan_result.values())

        if scan_result["expired"]:
            content_lines.append(f"### 🚨 已过期 ({len(scan_result['expired'])}张)")
            for c in scan_result["expired"]:
                content_lines.append(f"- **{c['name']}**：已过期{c['overdue_days']}天（到期日{c['expiry']}）")

        if scan_result["critical"]:
            content_lines.append(f"### ⚠️ 紧急 ({len(scan_result['critical'])}张)")
            for c in scan_result["critical"]:
                content_lines.append(f"- **{c['name']}**：剩余{c['remaining_days']}天（到期日{c['expiry']}）")

        if scan_result["warning"]:
            content_lines.append(f"### 📢 提醒 ({len(scan_result['warning'])}张)")
            for c in scan_result["warning"]:
                content_lines.append(f"- **{c['name']}**：剩余{c['remaining_days']}天（到期日{c['expiry']}）")

        content = "\n".join(content_lines)
        summary = (f"共 {total} 张证书，"
                    f"已过期 {len(scan_result['expired'])} 张，"
                    f"紧急 {len(scan_result['critical'])} 张，"
                    f"提醒 {len(scan_result['warning'])} 张")

        details = []

        # 控制台输出
        print(f"\n[PKI证书告警] {summary}")
        print(content)
        details.append(("console", True, summary))

        # 发送邮件
        if self.notifier.smtp_enabled:
            ok, msg = self.notifier.send_smtp_alert(title, content)
            details.append(("smtp", ok, msg))

        # 发送Webhook
        if self.notifier.webhook_url:
            webhook_content = "\n".join(content_lines)
            ok, msg = self.notifier.send_webhook_alert(title, webhook_content)
            details.append(("webhook", ok, msg))

        return {"sent": True, "summary": summary, "details": details}

    def scan_and_alert(self, cert_dir=None):
        """
        扫描并发送告警（一步完成）

        返回：{
            "scan": 扫描结果,
            "alerts": 告警结果
        }
        """
        scan_result = self.scan_certificates(cert_dir)
        alert_result = self.send_alerts(scan_result)
        return {"scan": scan_result, "alerts": alert_result}

    def get_notifier_status(self):
        """获取通知器配置状态"""
        return self.notifier.get_config_status()

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

        if results["expired"]:
            print(f"\n[已过期] 已过期证书（{len(results['expired'])}张）")
            print("-" * 50)
            for cert in results["expired"]:
                print(f"  [FAIL] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（已过期{cert['overdue_days']}天）")

        if results["critical"]:
            print(f"\n[紧急] 即将到期（{self.critical_days}天内，{len(results['critical'])}张）")
            print("-" * 50)
            for cert in results["critical"]:
                print(f"  [WARN] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（剩余{cert['remaining_days']}天）")

        if results["warning"]:
            print(f"\n[提醒] 将到期（{self.warning_days}天内，{len(results['warning'])}张）")
            print("-" * 50)
            for cert in results["warning"]:
                print(f"  [INFO] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（剩余{cert['remaining_days']}天）")

        if results["valid"]:
            print(f"\n[有效] 有效证书（{len(results['valid'])}张）")
            print("-" * 50)
            for cert in results["valid"]:
                print(f"  [OK] {cert['name']}")
                print(f"     到期日：{cert['expiry']}（剩余{cert['remaining_days']}天）")

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
    print("=== 证书到期检查与告警模块测试 ===\n")

    checker = CertExpiryChecker()

    # 测试扫描
    print("[测试1] 扫描证书")
    results = checker.scan_certificates()
    if "error" not in results:
        print(f"  过期: {len(results['expired'])} | 紧急: {len(results['critical'])} | "
              f"提醒: {len(results['warning'])} | 有效: {len(results['valid'])}")

    # 测试通知器状态
    print(f"\n[测试2] 通知器配置")
    status = checker.get_notifier_status()
    print(f"  SMTP: {'已配置' if status['smtpEnabled'] else '未配置'}")
    print(f"  Webhook: {'已配置' if status['webhookUrl'] else '未配置'}")

    # 测试报告
    print(f"\n[测试3] 打印报告")
    checker.print_expiry_report()

    print(f"\n[OK] 模块初始化正常")
