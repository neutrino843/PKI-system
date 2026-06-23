"""
================================================================
  身份认证与权限管理模块（auth.py）
================================================================
"""

import os
import json
import hashlib
import secrets
import time
from datetime import datetime
from functools import wraps
from enum import Enum
from pathlib import Path

from .database import transaction, init_database

BASE_DIR = Path(__file__).parent.resolve()

# 密码哈希常量
PBKDF2_ITERATIONS = 600000  # PBKDF2迭代次数
HASH_ALGO = "sha256"         # 底层哈希算法
SALT_BYTES = 16              # 盐值字节数

# 会话超时（30分钟）
SESSION_TIMEOUT = 30 * 60


# ============================================================
# 角色定义
# ============================================================
class Role(Enum):
    """用户角色枚举"""
    CA_ADMIN = "ca_admin"        # CA管理员——最高权限
    RA_OPERATOR = "ra_operator"  # RA操作员——审核申请
    AUDITOR = "auditor"          # 审计员——只读查看
    END_USER = "end_user"        # 终端用户——申请和使用自己的证书


ROLE_HIERARCHY = {
    Role.CA_ADMIN: 100,
    Role.RA_OPERATOR: 80,
    Role.AUDITOR: 60,
    Role.END_USER: 40,
}


# ============================================================
# 权限定义
# ============================================================
class Permission(Enum):
    """操作权限枚举"""
    MANAGE_ROOT_CA = "manage_root_ca"           # 管理根CA
    ISSUE_CERT = "issue_cert"                    # 签发证书
    REVOKE_CERT = "revoke_cert"                  # 吊销证书
    GENERATE_CRL = "generate_crl"                # 生成CRL
    APPROVE_CSR = "approve_csr"                  # 审核CSR
    VERIFY_IDENTITY = "verify_identity"          # 验证身份
    APPLY_CERT = "apply_cert"                    # 申请证书
    VIEW_OWN_CERT = "view_own_cert"              # 查看自己的证书
    EXPORT_P12 = "export_p12"                    # 导出PKCS#12
    VIEW_AUDIT_LOG = "view_audit_log"            # 查看审计日志
    VIEW_ALL_CERTS = "view_all_certs"            # 查看所有证书
    MANAGE_USERS = "manage_users"                # 管理用户
    # TSA 时间戳服务权限
    TSA_TIMESTAMP = "tsa_timestamp"              # 申请时间戳
    TSA_VERIFY = "tsa_verify"                    # 验证时间戳
    TSA_MANAGE = "tsa_manage"                    # 管理TSA服务


# 角色-权限映射表
ROLE_PERMISSIONS = {
    Role.CA_ADMIN: [
        Permission.MANAGE_ROOT_CA, Permission.ISSUE_CERT,
        Permission.REVOKE_CERT, Permission.GENERATE_CRL,
        Permission.VIEW_ALL_CERTS, Permission.VIEW_AUDIT_LOG,
        Permission.MANAGE_USERS, Permission.APPLY_CERT,
        Permission.VIEW_OWN_CERT, Permission.EXPORT_P12,
        Permission.TSA_TIMESTAMP, Permission.TSA_VERIFY,
        Permission.TSA_MANAGE,
    ],
    Role.RA_OPERATOR: [
        Permission.APPROVE_CSR, Permission.ISSUE_CERT,
        Permission.VERIFY_IDENTITY,
        Permission.VIEW_ALL_CERTS, Permission.APPLY_CERT,
        Permission.VIEW_OWN_CERT, Permission.EXPORT_P12,
        Permission.TSA_TIMESTAMP, Permission.TSA_VERIFY,
    ],
    Role.AUDITOR: [
        Permission.VIEW_AUDIT_LOG, Permission.VIEW_ALL_CERTS,
        Permission.VIEW_OWN_CERT, Permission.TSA_VERIFY,
    ],
    Role.END_USER: [
        Permission.APPLY_CERT, Permission.VIEW_OWN_CERT,
        Permission.EXPORT_P12, Permission.TSA_TIMESTAMP,
        Permission.TSA_VERIFY,
    ],
}


# ============================================================
# 权限校验装饰器
# ============================================================
class AuthorizationError(Exception):
    """权限不足异常"""
    pass


def require_permission(*permissions):
    """
    权限校验装饰器——检查当前登录用户是否有指定权限
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_user = get_current_user()
            if not current_user:
                raise AuthorizationError("未登录，请先登录系统")

            user_role = Role(current_user.get("role", "end_user"))
            user_perms = ROLE_PERMISSIONS.get(user_role, [])

            for perm in permissions:
                if perm not in user_perms:
                    raise AuthorizationError(
                        f"权限不足！需要 {perm.value} 权限，"
                        f"当前角色：{user_role.value}"
                    )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# 密码工具函数
# ============================================================

def _hash_password(password):
    """PBKDF2-HMAC-SHA256 + 随机盐 -> salt$hash"""
    salt = secrets.token_hex(SALT_BYTES)
    pwd_hash = hashlib.pbkdf2_hmac(
        HASH_ALGO, password.encode("utf-8"),
        salt.encode("utf-8"), PBKDF2_ITERATIONS
    ).hex()
    return f"{salt}${pwd_hash}"


def _verify_password(password, stored):
    """验证密码：从 salt$hash 中提取盐值后重算比较"""
    if "$" not in stored:
        return False
    salt, expected_hash = stored.split("$", 1)
    actual_hash = hashlib.pbkdf2_hmac(
        HASH_ALGO, password.encode("utf-8"),
        salt.encode("utf-8"), PBKDF2_ITERATIONS
    ).hex()
    return actual_hash == expected_hash


# ============================================================
# 用户管理
# ============================================================
class UserManager:
    """
    用户管理器（数据库持久化）
    """

    def __init__(self):
        self._init_default_users()

    def _init_default_users(self):
        """初始化默认用户（仅数据库无用户时创建，仅用于开发/演示）

        警告：默认密码仅适用于本地演示环境！
        生产部署前必须：
          1. 删除此方法或注释掉调用
          2. 通过管理员接口创建真实用户
          3. 使用强密码策略
        """
        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
                if row["cnt"] == 0:
                    # DEV ONLY: 所有密码均为开发演示用途
                    default_users = [
                        ("admin", _hash_password("admin123"), "系统管理员", "ca_admin"),
                        ("ra_zhang", _hash_password("ra123456"), "RA审核员", "ra_operator"),
                        ("auditor_li", _hash_password("audit123"), "审计员", "auditor"),
                        ("user_wang", _hash_password("user1234"), "普通用户", "end_user"),
                    ]
                    now = datetime.now().isoformat()
                    for username, pwd, name, role in default_users:
                        conn.execute(
                            """INSERT OR IGNORE INTO users
                               (username, password, name, role, is_active, created_at)
                               VALUES (?, ?, ?, ?, 1, ?)""",
                            (username, pwd, name, role, now)
                        )
        except Exception:
            pass  # 表尚未创建时静默处理

    def authenticate(self, username, password):
        """用户认证：返回用户信息字典或None"""
        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                    (username,)
                ).fetchone()
        except Exception:
            return None

        if not row:
            return None

        if not _verify_password(password, row["password"]):
            return None

        return {
            "username": row["username"],
            "name": row["name"],
            "role": row["role"],
        }

    def list_users(self, role_filter=None):
        """列出所有用户"""
        from .database import get_connection
        try:
            with transaction() as conn:
                if role_filter:
                    rows = conn.execute(
                        "SELECT * FROM users WHERE role = ? ORDER BY username",
                        (role_filter,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM users ORDER BY username"
                    ).fetchall()
            return [
                {
                    "username": r["username"],
                    "name": r["name"],
                    "role": r["role"],
                    "is_active": bool(r["is_active"]),
                }
                for r in rows
            ]
        except Exception:
            return []

    def add_user(self, username, password, name, role):
        """添加用户"""
        from .database import get_connection
        try:
            with transaction() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM users WHERE username = ?", (username,)
                ).fetchone()
                if existing:
                    return False
                conn.execute(
                    """INSERT INTO users
                       (username, password, name, role, is_active, created_at)
                       VALUES (?, ?, ?, ?, 1, ?)""",
                    (username, _hash_password(password), name, role,
                     datetime.now().isoformat())
                )
            return True
        except Exception:
            return False

    def deactivate_user(self, username):
        """停用用户"""
        from .database import get_connection
        try:
            with transaction() as conn:
                conn.execute(
                    "UPDATE users SET is_active = 0, updated_at = ? WHERE username = ?",
                    (datetime.now().isoformat(), username)
                )
            return True
        except Exception:
            return False

    def update_user_role(self, username, new_role):
        """更新用户角色"""
        valid_roles = {"ca_admin", "ra_operator", "auditor", "end_user"}
        if new_role not in valid_roles:
            return False, f"无效角色: {new_role}"

        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT role FROM users WHERE username = ?", (username,)
                ).fetchone()
                if not row:
                    return False, f"用户不存在: {username}"
                if username == "admin":
                    return False, "不能修改admin账号的角色"
                old_role = row["role"]
                conn.execute(
                    """UPDATE users SET role = ?, updated_at = ?
                       WHERE username = ?""",
                    (new_role, datetime.now().isoformat(), username)
                )
            return True, f"用户{username}角色已从{old_role}变更为{new_role}"
        except Exception as e:
            return False, f"更新失败: {e}"


# ============================================================
# 会话管理（持久化）
# ============================================================

class SessionManager:
    """
    会话管理器（数据库持久化，支持多用户并发，重启不丢失）
    """

    def __init__(self):
        self._current_sid = None
        self._cached_user = None

    def _cleanup_expired(self):
        """清理过期会话"""
        from .database import get_connection
        try:
            with transaction() as conn:
                now = time.time()
                threshold = now - SESSION_TIMEOUT
                conn.execute(
                    "DELETE FROM sessions WHERE last_access < ?", (threshold,)
                )
        except Exception:
            pass

    def login(self, username, password):
        """
        用户登录（持久化会话到数据库）

        返回：(成功标志, 消息)
        """
        um = UserManager()
        user = um.authenticate(username, password)

        if user:
            sid = secrets.token_hex(32)
            now = time.time()
            now_iso = datetime.now().isoformat()

            from .database import get_connection
            try:
                with transaction() as conn:
                    conn.execute(
                        """INSERT INTO sessions
                           (session_id, username, user_info_json, login_time, last_access, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (sid, username, json.dumps(user, ensure_ascii=False),
                         now, now, now_iso)
                    )
            except Exception:
                return False, "会话创建失败"

            self._current_sid = sid
            self._cached_user = user
            return True, f"登录成功！欢迎 {user['name']}（角色：{_role_cn(user['role'])}）"
        else:
            return False, "登录失败：用户名或密码错误"

    def logout(self):
        """退出登录（从数据库删除会话）"""
        if self._current_sid:
            from .database import get_connection
            try:
                with transaction() as conn:
                    conn.execute(
                        "DELETE FROM sessions WHERE session_id = ?",
                        (self._current_sid,)
                    )
            except Exception:
                pass
        self._current_sid = None
        self._cached_user = None

    def get_current_user(self):
        """获取当前登录用户（自动续期滑动过期）"""
        if not self._current_sid:
            return None

        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE session_id = ?",
                    (self._current_sid,)
                ).fetchone()
        except Exception:
            return None

        if not row:
            self._current_sid = None
            self._cached_user = None
            return None

        now = time.time()
        if (now - row["last_access"]) > SESSION_TIMEOUT:
            # 会话过期
            try:
                with transaction() as conn:
                    conn.execute(
                        "DELETE FROM sessions WHERE session_id = ?",
                        (self._current_sid,)
                    )
            except Exception:
                pass
            self._current_sid = None
            self._cached_user = None
            return None

        # 续期（滑动过期）
        try:
            with transaction() as conn:
                conn.execute(
                    "UPDATE sessions SET last_access = ? WHERE session_id = ?",
                    (now, self._current_sid)
                )
        except Exception:
            pass

        user = json.loads(row["user_info_json"])
        self._cached_user = user
        return user

    def restore_session(self, session_id):
        """从数据库恢复会话（用于跨请求/跨启动恢复）"""
        from .database import get_connection
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE session_id = ?",
                    (session_id,)
                ).fetchone()
        except Exception:
            return None

        if not row:
            return None

        now = time.time()
        if (now - row["last_access"]) > SESSION_TIMEOUT:
            try:
                with transaction() as conn:
                    conn.execute(
                        "DELETE FROM sessions WHERE session_id = ?",
                        (session_id,)
                    )
            except Exception:
                pass
            return None

        self._current_sid = session_id
        user = json.loads(row["user_info_json"])
        self._cached_user = user

        # 更新访问时间
        try:
            with transaction() as conn:
                conn.execute(
                    "UPDATE sessions SET last_access = ? WHERE session_id = ?",
                    (now, session_id)
                )
        except Exception:
            pass

        return user

    def list_sessions(self):
        """列出所有活跃会话"""
        self._cleanup_expired()
        from .database import get_connection
        try:
            with transaction() as conn:
                rows = conn.execute(
                    "SELECT username, MAX(last_access) as last_access "
                    "FROM sessions GROUP BY username ORDER BY last_access DESC"
                ).fetchall()
            return [r["username"] for r in rows]
        except Exception:
            return []

    def check_permission(self, permission):
        """检查当前用户是否有指定权限"""
        user = self.get_current_user()
        if not user:
            return False
        role = Role(user["role"])
        perms = ROLE_PERMISSIONS.get(role, [])
        return permission in perms


# ============================================================
# 全局实例
# ============================================================
_session_manager = SessionManager()


def get_current_user():
    """获取当前登录用户"""
    return _session_manager.get_current_user()


def login_required(func):
    """登录校验装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            raise AuthorizationError("请先登录系统")
        return func(*args, **kwargs)
    return wrapper


# ============================================================
# 辅助函数
# ============================================================
def _role_cn(role_en):
    """角色英文转中文"""
    mapping = {
        "ca_admin": "CA管理员",
        "ra_operator": "RA操作员",
        "auditor": "审计员",
        "end_user": "终端用户",
    }
    return mapping.get(role_en, role_en)


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== 身份认证模块测试 ===\n")

    init_database()
    um = UserManager()
    sm = SessionManager()

    print("系统用户列表：")
    for u in um.list_users():
        print(f"  - {u['username']} ({u['name']}) 角色: {u['role']}")

    print("\n测试登录（admin / admin123）：")
    success, msg = sm.login("admin", "admin123")
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")

    if success:
        user = sm.get_current_user()
        print(f"\n当前用户信息：{user}")

        print("\n权限检查：")
        print(f"  管理根CA：{'[OK]' if sm.check_permission(Permission.MANAGE_ROOT_CA) else '[FAIL]'}")
        print(f"  签发证书：{'[OK]' if sm.check_permission(Permission.ISSUE_CERT) else '[FAIL]'}")
        print(f"  审核CSR：{'[OK]' if sm.check_permission(Permission.APPROVE_CSR) else '[FAIL]'}")

        sm.logout()
        print("\n已退出登录")
