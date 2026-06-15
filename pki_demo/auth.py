"""
================================================================
  身份认证与权限控制模块（auth.py）
  功能：用户登录认证 + RBAC权限控制

  修复风险项：
  - AUTH-01：无用户登录认证 → 用户名密码认证
  - AUTH-02：无角色权限 → RBAC角色控制
  - AUTH-03：无操作授权 → 装饰器级别权限校验
  - AUTH-05：无会话管理 → 会话超时控制

  通俗解释：
  就像公司的门禁系统——
  不同的人有不同的门禁卡（角色），
  能进不同的门（操作权限）。
  保安（管理员）能进所有门，
  普通员工只能进自己的办公室。
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

BASE_DIR = Path(__file__).parent.resolve()
USERS_FILE = BASE_DIR / "data" / "users.json"
SESSIONS_FILE = BASE_DIR / "data" / "sessions.json"

# 密码哈希常量
PBKDF2_ITERATIONS = 600000  # PBKDF2迭代次数
HASH_ALGO = "sha256"         # 底层哈希算法
SALT_BYTES = 16              # 盐值字节数


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
    # CA管理操作
    MANAGE_ROOT_CA = "manage_root_ca"           # 管理根CA
    ISSUE_CERT = "issue_cert"                    # 签发证书
    REVOKE_CERT = "revoke_cert"                  # 吊销证书
    GENERATE_CRL = "generate_crl"                # 生成CRL

    # RA操作
    APPROVE_CSR = "approve_csr"                  # 审核CSR
    VERIFY_IDENTITY = "verify_identity"          # 验证身份

    # 通用操作
    APPLY_CERT = "apply_cert"                    # 申请证书
    VIEW_OWN_CERT = "view_own_cert"              # 查看自己的证书
    EXPORT_P12 = "export_p12"                    # 导出PKCS#12

    # 审计操作
    VIEW_AUDIT_LOG = "view_audit_log"            # 查看审计日志
    VIEW_ALL_CERTS = "view_all_certs"            # 查看所有证书

    # 用户管理
    MANAGE_USERS = "manage_users"                # 管理用户


# 角色-权限映射表
ROLE_PERMISSIONS = {
    Role.CA_ADMIN: [
        Permission.MANAGE_ROOT_CA,
        Permission.ISSUE_CERT,
        Permission.REVOKE_CERT,
        Permission.GENERATE_CRL,
        Permission.VIEW_ALL_CERTS,
        Permission.VIEW_AUDIT_LOG,
        Permission.MANAGE_USERS,
        Permission.APPLY_CERT,
        Permission.VIEW_OWN_CERT,
        Permission.EXPORT_P12,
    ],
    Role.RA_OPERATOR: [
        Permission.APPROVE_CSR,
        Permission.VERIFY_IDENTITY,
        Permission.VIEW_ALL_CERTS,
        Permission.APPLY_CERT,
        Permission.VIEW_OWN_CERT,
        Permission.EXPORT_P12,
    ],
    Role.AUDITOR: [
        Permission.VIEW_AUDIT_LOG,
        Permission.VIEW_ALL_CERTS,
        Permission.VIEW_OWN_CERT,
    ],
    Role.END_USER: [
        Permission.APPLY_CERT,
        Permission.VIEW_OWN_CERT,
        Permission.EXPORT_P12,
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

    使用方式：
    @require_permission(Permission.REVOKE_CERT)
    def revoke_certificate(...):
        ...

    通俗解释：
    就像进办公楼需要刷门禁卡——
    这个装饰器就是门禁读卡器，
    检查你的卡有没有开这扇门的权限。
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 获取当前登录用户
            from config import CFG
            current_user = get_current_user()
            if not current_user:
                raise AuthorizationError("未登录，请先登录系统")

            # 检查用户角色是否有对应权限
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
# 用户管理
# ============================================================
class UserManager:
    """
    用户管理器

    通俗解释：
    就像公司的人事档案管理系统——
    记录每个员工的姓名、职位、工号等信息。
    """

    def __init__(self):
        self._ensure_data_dir()
        self._init_default_users()

    def _ensure_data_dir(self):
        """确保数据目录存在"""
        data_dir = BASE_DIR / "data"
        data_dir.mkdir(exist_ok=True)

    def _init_default_users(self):
        """初始化默认用户"""
        if not USERS_FILE.exists():
            default_users = {
                "admin": {
                    "password": self._hash_password("admin123"),
                    "role": "ca_admin",
                    "name": "系统管理员",
                    "created_at": datetime.now().isoformat(),
                    "is_active": True,
                },
                "ra_zhang": {
                    "password": self._hash_password("ra123456"),
                    "role": "ra_operator",
                    "name": "张审核员",
                    "created_at": datetime.now().isoformat(),
                    "is_active": True,
                },
                "auditor_li": {
                    "password": self._hash_password("audit123"),
                    "role": "auditor",
                    "name": "李审计员",
                    "created_at": datetime.now().isoformat(),
                    "is_active": True,
                },
                "user_wang": {
                    "password": self._hash_password("user1234"),
                    "role": "end_user",
                    "name": "王普通用户",
                    "created_at": datetime.now().isoformat(),
                    "is_active": True,
                },
            }
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(default_users, f, ensure_ascii=False, indent=2)

    def _atomic_save_users(self, users_data):
        """原子写入用户数据：先写临时文件再重命名，防止写入中断数据损坏"""
        tmp_path = str(USERS_FILE) + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(users_data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(USERS_FILE))

    def _hash_password(self, password):
        """
        密码哈希（使用PBKDF2-HMAC-SHA256 + 随机盐）

        安全性对比：
        旧版：SHA256(password + 固定全局盐) —— 秒级可破解
        新版：PBKDF2-HMAC-SHA256(password + 随机每用户盐, 60万次迭代) —— 抗暴力破解

        返回：salt$hash 格式的字符串
        """
        salt = secrets.token_hex(SALT_BYTES)
        pwd_hash = hashlib.pbkdf2_hmac(
            HASH_ALGO,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            PBKDF2_ITERATIONS
        ).hex()
        return f"{salt}${pwd_hash}"

    def _verify_password(self, password, stored):
        """
        验证密码（从存储格式中提取盐值后重算比较）

        参数：
            password: 用户输入的明文密码
            stored: 存储的 salt$hash 格式字符串
        """
        if "$" not in stored:
            return False
        salt, expected_hash = stored.split("$", 1)
        actual_hash = hashlib.pbkdf2_hmac(
            HASH_ALGO,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            PBKDF2_ITERATIONS
        ).hex()
        return actual_hash == expected_hash

    def authenticate(self, username, password):
        """
        用户认证

        返回：认证成功返回用户信息字典，失败返回None
        """
        if not USERS_FILE.exists():
            return None

        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)

        user = users.get(username)
        if not user:
            return None

        if not user.get("is_active", True):
            return None

        if not self._verify_password(password, user["password"]):
            return None

        return {
            "username": username,
            "name": user["name"],
            "role": user["role"],
        }

    def list_users(self, role_filter=None):
        """列出所有用户（供管理员使用）"""
        if not USERS_FILE.exists():
            return []

        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)

        result = []
        for username, info in users.items():
            if role_filter and info["role"] != role_filter:
                continue
            result.append({
                "username": username,
                "name": info["name"],
                "role": info["role"],
                "is_active": info["is_active"],
            })
        return result

    def add_user(self, username, password, name, role):
        """添加用户（仅CA管理员）"""
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)

        if username in users:
            return False

        users[username] = {
            "password": self._hash_password(password),
            "role": role,
            "name": name,
            "created_at": datetime.now().isoformat(),
            "is_active": True,
        }

        self._atomic_save_users(users)
        return True

    def deactivate_user(self, username):
        """停用用户"""
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)

        if username not in users:
            return False

        users[username]["is_active"] = False

        self._atomic_save_users(users)
        return True

    def update_user_role(self, username, new_role):
        """更新用户角色（仅CA管理员操作）"""
        valid_roles = {"ca_admin", "ra_operator", "auditor", "end_user"}
        if new_role not in valid_roles:
            return False, f"无效角色: {new_role}"

        with open(USERS_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)

        if username not in users:
            return False, f"用户不存在: {username}"

        if username == "admin":
            return False, "不能修改admin账号的角色"

        old_role = users[username]["role"]
        users[username]["role"] = new_role
        users[username]["updated_at"] = datetime.now().isoformat()

        self._atomic_save_users(users)
        return True, f"用户{username}角色已从{old_role}变更为{new_role}"


# ============================================================
# 会话管理
# ============================================================
SESSION_TIMEOUT = 30 * 60  # 30分钟超时

class SessionManager:
    """
    会话管理器（支持多用户并发）

    旧版缺陷：使用单变量存储，后登录覆盖前用户
    新版修复：使用Dict存储多用户会话，每个会话有独立session ID

    通俗解释：
    就像网站的登录态管理——
    每个用户登录后获得一个唯一的"令牌"（session_id），
    服务器根据令牌识别是哪个用户在操作。
    """

    def __init__(self):
        self._sessions = {}  # {session_id: {"user": user_info, "login_time": timestamp}}
        self._current_sid = None
        self._current_user = None
        self._login_time = None

    def login(self, username, password):
        """
        用户登录

        返回：(成功标志, 消息)
        """
        um = UserManager()
        user = um.authenticate(username, password)

        if user:
            # 生成随机session ID
            sid = secrets.token_hex(32)
            now = time.time()
            self._sessions[sid] = {
                "user": user,
                "login_time": now
            }
            self._current_sid = sid
            self._current_user = user
            self._login_time = now
            return True, f"登录成功！欢迎 {user['name']}（角色：{_role_cn(user['role'])}）"
        else:
            return False, "登录失败：用户名或密码错误"

    def logout(self):
        """退出登录"""
        if self._current_sid:
            self._sessions.pop(self._current_sid, None)
        self._current_sid = None
        self._current_user = None
        self._login_time = None

    def get_current_user(self):
        """获取当前登录用户"""
        if not self._current_sid:
            return None

        session = self._sessions.get(self._current_sid)
        if not session:
            self._current_sid = None
            self._current_user = None
            self._login_time = None
            return None

        # 检查会话是否超时
        if (time.time() - session["login_time"]) > SESSION_TIMEOUT:
            self._sessions.pop(self._current_sid, None)
            self._current_sid = None
            self._current_user = None
            self._login_time = None
            return None

        # 更新访问时间（滑动过期）
        session["login_time"] = time.time()
        self._current_user = session["user"]
        self._login_time = session["login_time"]
        return session["user"]

    def list_sessions(self):
        """列出所有活跃会话（管理员用）"""
        now = time.time()
        active = []
        expired = []
        for sid, session in list(self._sessions.items()):
            if (now - session["login_time"]) > SESSION_TIMEOUT:
                expired.append(sid)
            else:
                active.append(session["user"]["username"])
        # 清理过期会话
        for sid in expired:
            self._sessions.pop(sid, None)
        return active

    def check_permission(self, permission):
        """检查当前用户是否有指定权限"""
        user = self.get_current_user()
        if not user:
            return False

        role = Role(user["role"])
        perms = ROLE_PERMISSIONS.get(role, [])
        return permission in perms


# ============================================================
# 全局会话管理器
# ============================================================
_session_manager = SessionManager()


def get_current_user():
    """获取当前登录用户（供装饰器使用）"""
    return _session_manager.get_current_user()


def login_required(func):
    """
    登录校验装饰器——必须登录才能操作
    """
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

    um = UserManager()
    sm = SessionManager()

    # 测试1：列出所有用户
    print("系统用户列表：")
    for u in um.list_users():
        print(f"  - {u['username']} ({u['name']}) 角色: {u['role']}")

    # 测试2：登录测试
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
