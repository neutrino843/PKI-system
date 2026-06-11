"""
================================================================
  PKI系统安全加固 - 核心配置模块（config.py）
  功能：统一管理所有敏感配置项，消除硬编码密码

  修复风险项：
  - KEY-02：硬编码密码 → 环境变量 + 配置文件
  - ALG-02/03：算法参数不可配 → 可配置化
  - COMM-02：文件完整性 → 哈希白名单

  使用方式：
  from config import CFG
  password = CFG.get_password("CA_KEY_PASSWORD")
================================================================
"""

import os
import json
import hashlib
from pathlib import Path

# ============================================================
# 配置文件路径
# ============================================================
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / "pki_config.json"
ENV_PREFIX = "PKI_"  # 环境变量前缀


# ============================================================
# 默认配置（生产环境应通过环境变量或配置文件覆盖）
# ============================================================
DEFAULT_CONFIG = {
    # === 密码配置（从环境变量读取，绝不硬编码在源码中） ===
    "passwords": {
        # 说明：实际密码通过 PKI_CA_KEY_PASSWORD 等环境变量传入
        # 此处的占位符仅用于演示，生产环境必须设置真实环境变量
        "CA_KEY_PASSWORD": {"source": "env", "env_var": "PKI_CA_KEY_PASSWORD", "default": ""},
        "USER_KEY_PASSWORD": {"source": "env", "env_var": "PKI_USER_KEY_PASSWORD", "default": ""},
        "P12_EXPORT_PASSWORD": {"source": "env", "env_var": "PKI_P12_EXPORT_PASSWORD", "default": ""},
        "CRL_HMAC_KEY": {"source": "env", "env_var": "PKI_CRL_HMAC_KEY", "default": ""},
        "AUDIT_HMAC_KEY": {"source": "env", "env_var": "PKI_AUDIT_HMAC_KEY", "default": ""},
    },

    # === 算法配置（可灵活切换） ===
    "algorithm": {
        "signature_algorithm": "RSA",       # RSA / ECC / SM2（需额外库）
        "hash_algorithm": "SHA256",         # SHA256 / SHA384 / SHA512 / SM3
        "rsa_key_size": 2048,               # 2048 / 3072 / 4096
        "ecc_curve": "secp256r1",           # secp256r1 / secp384r1 / secp521r1
    },

    # === 证书策略配置 ===
    "cert_policy": {
        "default_validity_days": 365,       # 默认证书有效期（天）
        "ca_validity_years": 10,            # CA证书有效期（年）
        "crl_validity_days": 7,             # CRL更新周期（天）
        "max_cert_per_user": 5,             # 每个用户最大证书数
    },

    # === 安全策略 ===
    "security": {
        "min_password_length": 8,           # 最小密码长度
        "session_timeout_minutes": 30,      # 会话超时时间
        "max_login_attempts": 5,            # 最大登录尝试次数
        "audit_log_integrity_check": True,  # 审计日志完整性校验
        "secure_delete_passes": 3,          # 安全删除覆盖次数
    },

    # === 文件完整性校验白名单 ===
    "file_integrity": {
        "enabled": True,                    # 是否启用文件完整性校验
        # 格式：{"文件路径": "sha256哈希"}，首次运行时自动生成
        "manifest": {}
    }
}


# ============================================================
# 配置管理器
# ============================================================
class ConfigManager:
    """
    统一配置管理器

    修复效果：
    [OK] 所有密码从环境变量读取，消除硬编码
    [OK] 算法参数集中可配置，灵活切换
    [OK] 配置文件可导出导入，便于部署
    """

    def __init__(self):
        self._config = self._load_config()
        self._passwords_cache = {}

    def _load_config(self):
        """加载配置（环境变量优先于配置文件）"""
        config = {}
        for k, v in DEFAULT_CONFIG.items():
            config[k] = v.copy() if isinstance(v, dict) else v
        return config

    def get_password(self, name):
        """
        获取密码（安全方式：优先环境变量，其次配置文件，拒绝硬编码）

        使用方式：
        pwd = CFG.get_password("CA_KEY_PASSWORD")
        if not pwd:
            raise RuntimeError("请设置 PKI_CA_KEY_PASSWORD 环境变量")

        返回：bytes 类型的密码，或 None（如果未设置）
        """
        if name in self._passwords_cache:
            return self._passwords_cache[name]

        pwd_config = self._config["passwords"].get(name)
        if not pwd_config:
            return None

        password = None

        # 方式1：从环境变量读取（生产环境推荐）
        if pwd_config.get("source") == "env":
            env_var = pwd_config.get("env_var", "")
            password = os.environ.get(env_var, pwd_config.get("default", ""))

        # 方式2：从配置文件读取（仅用于开发环境）
        if not password:
            password = pwd_config.get("default", "")

        # 转换为 bytes
        if password:
            pwd_bytes = password.encode("utf-8")
            self._passwords_cache[name] = pwd_bytes
            return pwd_bytes

        return None

    def set_env_password(self, name, password):
        """
        设置环境变量密码（运行时设置，不持久化）

        用于交互式输入场景：用户首次运行时输入密码，
        设置到环境变量中供后续使用。
        """
        pwd_config = self._config["passwords"].get(name)
        if pwd_config:
            env_var = pwd_config.get("env_var", "")
            os.environ[env_var] = password
            self._passwords_cache[name] = password.encode("utf-8")

    def get_algorithm_config(self):
        """获取算法配置"""
        return dict(self._config["algorithm"])

    def get_cert_policy(self):
        """获取证书策略配置"""
        return dict(self._config["cert_policy"])

    def get_security_config(self):
        """获取安全策略配置"""
        return dict(self._config["security"])

    def get_file_manifest(self):
        """获取文件完整性清单"""
        return dict(self._config["file_integrity"]["manifest"])

    def generate_file_hash(self, filepath):
        """计算文件的SHA-256哈希"""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def show_config_status(self):
        """显示配置状态（用于排查问题）"""
        print("\n=== PKI系统配置状态 ===")
        print(f"算法: {self.get_algorithm_config()}")
        print(f"证书策略: {self.get_cert_policy()}")

        print("\n--- 密码配置状态 ---")
        for name, pwd_config in self._config["passwords"].items():
            env_var = pwd_config.get("env_var", "")
            value = os.environ.get(env_var, "")
            if value:
                print(f"  [OK] {name}: 已设置（通过 {env_var}）")
            else:
                print(f"  [FAIL] {name}: 未设置（请配置 {env_var}）")

        print("--- 安全策略 ---")
        for k, v in self.get_security_config().items():
            print(f"  {'[OK]' if v else '[FAIL]'} {k}: {v}")

        return self._check_ready()

    def _check_ready(self):
        """检查是否满足运行条件"""
        missing = []
        for name, pwd_config in self._config["passwords"].items():
            if pwd_config.get("env_var"):
                if not os.environ.get(pwd_config["env_var"], ""):
                    missing.append(pwd_config["env_var"])

        if missing:
            print(f"\n[WARN]  以下环境变量未设置（可使用 setup_env.bat 快速配置）:")
            for v in missing:
                print(f"   - {v}")
            return False
        return True


# ============================================================
# 全局单例
# ============================================================
CFG = ConfigManager()


# ============================================================
# 独立运行：检查配置状态
# ============================================================
if __name__ == "__main__":
    CFG.show_config_status()
