"""
================================================================
  LDAP/AD 目录集成模块（ldap_auth.py）
  功能：
    - LDAP 服务器连接与配置管理
    - 从 AD/LDAP 同步用户到 PKI 系统
    - 使用 LDAP 密码验证登录（SSO）
  标准：RFC 4510 - Lightweight Directory Access Protocol
================================================================
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path

from .database import transaction
from .auth import UserManager, _hash_password
from .audit import audit_logger

BASE_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / "data" / "ldap_config.json"


# ============================================================
# LDAP 配置管理
# ============================================================

class LDAPConfig:
    """LDAP 连接配置"""

    def __init__(self):
        self.server = ""
        self.port = 389
        self.use_tls = False
        self.bind_dn = ""
        self.bind_password = ""
        self.base_dn = ""
        self.user_filter = "(objectClass=person)"
        self.username_attr = "sAMAccountName"  # AD 默认
        self.name_attr = "displayName"
        self.email_attr = "mail"
        self.department_attr = "department"
        self.enabled = False
        self._load()

    def _load(self):
        """从文件加载配置"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                for key, value in data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
            except Exception:
                pass
        # 环境变量覆盖
        if os.environ.get("PKI_LDAP_SERVER"):
            self.server = os.environ["PKI_LDAP_SERVER"]
        if os.environ.get("PKI_LDAP_BIND_DN"):
            self.bind_dn = os.environ["PKI_LDAP_BIND_DN"]
        if os.environ.get("PKI_LDAP_BIND_PASSWORD"):
            self.bind_password = os.environ["PKI_LDAP_BIND_PASSWORD"]
        if os.environ.get("PKI_LDAP_BASE_DN"):
            self.base_dn = os.environ["PKI_LDAP_BASE_DN"]
        if os.environ.get("PKI_LDAP_ENABLED", "").lower() in ("1", "true", "yes"):
            self.enabled = True

    def save(self):
        """保存配置到文件"""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "server": self.server,
            "port": self.port,
            "use_tls": self.use_tls,
            "bind_dn": self.bind_dn,
            "bind_password": self.bind_password,
            "base_dn": self.base_dn,
            "user_filter": self.user_filter,
            "username_attr": self.username_attr,
            "name_attr": self.name_attr,
            "email_attr": self.email_attr,
            "department_attr": self.department_attr,
            "enabled": self.enabled,
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True

    def to_dict(self):
        """导出配置字典（排除密码）"""
        return {
            "server": self.server,
            "port": self.port,
            "use_tls": self.use_tls,
            "bind_dn": self.bind_dn,
            "base_dn": self.base_dn,
            "user_filter": self.user_filter,
            "username_attr": self.username_attr,
            "name_attr": self.name_attr,
            "email_attr": self.email_attr,
            "department_attr": self.department_attr,
            "enabled": self.enabled,
            "configured": bool(self.server and self.base_dn),
        }


# ============================================================
# LDAP 连接与用户同步
# ============================================================

class LDAPConnector:
    """
    LDAP 目录连接器

    功能：
    - 测试 LDAP 服务器连接
    - 从 AD/LDAP 搜索用户
    - 同步用户到 PKI 本地数据库
    - LDAP 密码验证（SSO 登录）
    """

    def __init__(self):
        self.config = LDAPConfig()
        self._conn = None

    def test_connection(self):
        """
        测试 LDAP 服务器连接

        返回：(成功标志, 消息)
        """
        cfg = self.config
        if not cfg.server:
            return False, "LDAP 服务器地址未配置"

        try:
            import ldap3

            server = ldap3.Server(cfg.server, port=cfg.port,
                                  use_ssl=cfg.use_tls,
                                  connect_timeout=5)
            conn = ldap3.Connection(server, cfg.bind_dn, cfg.bind_password,
                                    auto_bind=True)
            conn.unbind()
            return True, f"LDAP 连接成功: {cfg.server}:{cfg.port}"
        except ImportError:
            return False, "ldap3 库未安装，请执行: pip install ldap3"
        except Exception as e:
            return False, f"LDAP 连接失败: {e}"

    def _get_connection(self):
        """获取 LDAP 连接"""
        if self._conn and self._conn.bound:
            return self._conn

        cfg = self.config
        if not cfg.server or not cfg.base_dn:
            return None

        try:
            import ldap3
            server = ldap3.Server(cfg.server, port=cfg.port,
                                  use_ssl=cfg.use_tls,
                                  connect_timeout=5)
            self._conn = ldap3.Connection(server, cfg.bind_dn, cfg.bind_password,
                                          auto_bind=True)
            return self._conn
        except ImportError:
            return None
        except Exception:
            return None

    def search_users(self, search_base=None, search_filter=None):
        """
        从 LDAP 搜索用户

        参数：
            search_base: 搜索基DN（默认使用配置的 base_dn）
            search_filter: LDAP 过滤器（默认使用配置的 user_filter）

        返回：用户列表 [{"username": ..., "name": ..., "email": ..., "department": ...}]
        """
        conn = self._get_connection()
        if not conn:
            return []

        cfg = self.config
        base = search_base or cfg.base_dn
        filt = search_filter or cfg.user_filter

        try:
            search_attrs = [cfg.username_attr, cfg.name_attr,
                           cfg.email_attr, cfg.department_attr]
            conn.search(
                search_base=base,
                search_filter=filt,
                attributes=search_attrs + ["dn"],
                size_limit=500,
            )

            users = []
            for entry in conn.entries:
                try:
                    username = str(getattr(entry, cfg.username_attr, ""))
                    if not username:
                        continue
                    user = {
                        "username": username,
                        "name": str(getattr(entry, cfg.name_attr, username)) or username,
                        "email": str(getattr(entry, cfg.email_attr, "")),
                        "department": str(getattr(entry, cfg.department_attr, "")),
                        "dn": str(entry.entry_dn),
                    }
                    users.append(user)
                except Exception:
                    continue
            return users

        except Exception as e:
            print(f"  [WARN] LDAP 搜索失败: {e}")
            return []

    def sync_users(self, dry_run=False):
        """
        从 LDAP 同步用户到 PKI 本地数据库

        参数：
            dry_run: 试运行模式（只返回差异，不写入数据库）

        返回：同步结果字典
        """
        ldap_users = self.search_users()
        if not ldap_users:
            return {
                "status": "error",
                "message": "LDAP 未返回任何用户，请检查配置",
                "total": 0,
                "created": 0,
                "skipped": 0,
                "users": [],
            }

        um = UserManager()
        result = {"total": len(ldap_users), "created": 0, "skipped": 0,
                  "errors": 0, "users": []}

        for user in ldap_users:
            try:
                # 检查用户是否已存在
                from .database import get_connection
                with transaction() as conn:
                    row = conn.execute(
                        "SELECT username FROM users WHERE username = ?",
                        (user["username"],)
                    ).fetchone()

                if row:
                    # 用户已存在，更新信息
                    if not dry_run:
                        with transaction() as conn:
                            conn.execute(
                                """UPDATE users SET name = ?, updated_at = ?
                                   WHERE username = ?""",
                                (user["name"], datetime.now(timezone.utc).isoformat(),
                                 user["username"])
                            )
                    result["skipped"] += 1
                    user["action"] = "skipped"
                else:
                    # 新用户，创建账号
                    if not dry_run:
                        # 生成随机密码（LDAP 验证走 SSO，本地密码不重要）
                        import secrets
                        random_pwd = secrets.token_hex(16)
                        with transaction() as conn:
                            conn.execute(
                                """INSERT INTO users
                                   (username, password, name, role, is_active, created_at)
                                   VALUES (?, ?, ?, 'end_user', 1, ?)""",
                                (user["username"], _hash_password(random_pwd),
                                 user["name"], datetime.now(timezone.utc).isoformat())
                            )
                    result["created"] += 1
                    user["action"] = "created"

                result["users"].append({
                    "username": user["username"],
                    "name": user["name"],
                    "email": user.get("email", ""),
                    "department": user.get("department", ""),
                    "action": user.get("action", "created"),
                })

            except Exception as e:
                result["errors"] += 1
                result["users"].append({
                    "username": user["username"],
                    "error": str(e),
                    "action": "error",
                })

        result["status"] = "success"
        result["dryRun"] = dry_run
        result["message"] = (f"LDAP 同步完成: "
                            f"新创建 {result['created']}, "
                            f"已跳过 {result['skipped']}, "
                            f"错误 {result['errors']}")

        if dry_run:
            result["message"] = result["message"].replace("同步完成", "试运行完成")

        return result

    def authenticate(self, username, password):
        """
        LDAP 用户认证（SSO）

        流程：
        1. 先在本地数据库查找用户
        2. 用户存在且 LDAP 启用 -> 尝试 LDAP 验证
        3. LDAP 验证通过 -> 返回用户信息

        参数：
            username: 用户名
            password: LDAP 密码

        返回：用户信息字典或 None
        """
        if not self.config.enabled:
            return None

        conn = self._get_connection()
        if not conn:
            return None

        cfg = self.config
        try:
            # 查找用户的 DN
            import ldap3
            conn.search(
                search_base=cfg.base_dn,
                search_filter=f"(&{cfg.user_filter}({cfg.username_attr}={username}))",
                attributes=["dn"],
                size_limit=1,
            )

            if not conn.entries:
                return None

            user_dn = str(conn.entries[0].entry_dn)

            # 用用户密码绑定验证
            user_conn = ldap3.Connection(
                ldap3.Server(cfg.server, port=cfg.port, use_ssl=cfg.use_tls,
                            connect_timeout=5),
                user_dn, password, auto_bind=True
            )
            user_conn.unbind()

            # LDAP 验证通过 -> 返回本地用户信息
            um = UserManager()
            # 使用本地存储的密码验证（我们实际使用 LDAP SSO）
            # 从本地查找用户
            from .database import get_connection
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                    (username,)
                ).fetchone()

            if row:
                return {
                    "username": row["username"],
                    "name": row["name"],
                    "role": row["role"],
                    "source": "ldap",
                }

            return None

        except ldap3.core.exceptions.LDAPBindError:
            return None  # 密码错误
        except ldap3.core.exceptions.LDAPException:
            return None  # 连接错误
        except ImportError:
            return None
        except Exception:
            return None


# ============================================================
# 全局实例
# ============================================================
ldap_connector = LDAPConnector()


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    print("=== LDAP/AD 目录集成模块测试 ===\n")

    connector = LDAPConnector()
    cfg = connector.config

    print("[测试1] 配置状态")
    print(f"  服务器: {cfg.server or '(未配置)'}")
    print(f"  端口: {cfg.port}")
    print(f"  Base DN: {cfg.base_dn or '(未配置)'}")
    print(f"  启用: {cfg.enabled}")

    print("\n[测试2] 配置导出")
    info = cfg.to_dict()
    print(f"  configured: {info['configured']}")

    print("\n[测试3] 连接测试")
    ok, msg = connector.test_connection()
    print(f"  { '[OK]' if ok else '[INFO]' }: {msg}")

    print("\n[测试4] 用户同步（试运行）")
    if cfg.server and cfg.base_dn:
        result = connector.sync_users(dry_run=True)
        print(f"  状态: {result['status']}")
        print(f"  LDAP用户数: {result['total']}")
        print(f"  待创建: {result['created']}")
        print(f"  已存在: {result['skipped']}")
    else:
        print("  [SKIP] LDAP 未配置，跳过")

    print(f"\n[OK] 模块初始化正常")
