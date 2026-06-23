"""
PKI系统 - REST API 后端服务
基于Flask封装现有pki_demo模块，为前端提供HTTP API接口
"""
import os
import sys
import json
import hashlib
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# 确保能导入pki_demo模块
BASE_DIR = Path(__file__).parent.resolve()
PKI_DEMO_DIR = BASE_DIR / "pki_demo"
sys.path.insert(0, str(BASE_DIR))

# 设置开发环境默认HMAC密钥（防止未配置环境变量时崩溃）
# 生产环境应通过环境变量 PKI_CRL_HMAC_KEY / PKI_AUDIT_HMAC_KEY 设置强密码
os.environ.setdefault("PKI_CRL_HMAC_KEY", "pki_demo_crl_hmac_key_32bytes")
os.environ.setdefault("PKI_AUDIT_HMAC_KEY", "pki_demo_audit_hmac_key_32bytes")

from flask import Flask, request, jsonify, send_from_directory, send_file, session, Response
from flask_cors import CORS

# 导入PKI后端模块
from pki_demo.config import CFG
from pki_demo.auth import (_session_manager as auth_sm, Permission, Role,
                  ROLE_PERMISSIONS, UserManager, require_permission,
                  AuthorizationError)
from pki_demo.audit import audit_logger
from pki_demo.ra import ra_manager
from pki_demo.security_crl import SecureRevokedList
from pki_demo.security_crypto import (get_hash_algorithm, get_signature_hash,
    sign_certificate_with_hash, sign_csr_with_hash, sign_crl_with_hash,
    get_rsa_key_size, generate_keypair, FileIntegrityChecker)
from pki_demo.backup import BackupManager
from pki_demo.cert_expiry import CertExpiryChecker
from pki_demo.database import init_database, transaction

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import SubjectAlternativeName, DNSName, RFC822Name, IPAddress
from ipaddress import ip_address

# 标准 API 错误码
from pki_demo.api_errors import ErrorCode, ERROR_HTTP_STATUS, success, error, validation_error, paginated_result

# 证书模板引擎
from pki_demo.cert_template import (CertTemplateType, list_templates,
    get_template, apply_template_to_builder, validate_template_params,
    get_default_validity)

# OCSP 在线证书状态协议
from pki_demo.ocsp import ocsp_responder, OCSP_CONTENT_TYPE

# SCEP/EST 自动注册协议
from pki_demo.scep_est import scep_handler, est_handler

# LDAP/AD 目录集成
from pki_demo.ldap_auth import ldap_connector, LDAPConfig

# ACME 自动证书管理协议
from pki_demo.acme_server import acme_server

# ============================================================
# 内部访问证书校验（仅允许持有合法证书的人员启动程序）
# ============================================================
# 在校验通过之前，程序不会继续加载和初始化任何业务逻辑
# 环境变量 PKI_SKIP_ACCESS_CHECK=1 可跳过校验（仅开发调试用）
# ============================================================
if not os.environ.get("PKI_SKIP_ACCESS_CHECK"):
    from pki_demo.access_control import check_and_exit
    check_and_exit()

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("PKI_FLASK_SECRET", "DEV_ONLY_change_me_in_production")
CORS(app, origins=["http://localhost:8080", "http://127.0.0.1:8080"],
     supports_credentials=True)


@app.before_request
def restore_session():
    """
    在每个请求处理前从Flask session cookie恢复登录状态
    确保即使服务重启，已登录用户的会话仍然有效（基于持久化session DB）
    """
    sid = session.get("session_id")
    if sid:
        current = auth_sm.get_current_user()
        if not current:
            # 当前进程会话为空，尝试从数据库恢复
            auth_sm.restore_session(sid)


# ============================================================
# 全局异常处理器
# ============================================================

class APIError(Exception):
    """API 业务异常"""
    def __init__(self, code=ErrorCode.SYS_INTERNAL_ERROR, message="服务器内部错误",
                 details=None, http_status=None):
        self.code = code
        self.message = message
        self.details = details
        self.http_status = http_status or ERROR_HTTP_STATUS.get(code, 500)
        super().__init__(self.message)


@app.errorhandler(APIError)
def handle_api_error(exc):
    return error(code=exc.code, message=exc.message,
                 details=exc.details, http_status=exc.http_status)


@app.errorhandler(404)
def handle_404(exc):
    return error(code=ErrorCode.RESOURCE_NOT_FOUND,
                 message="请求的资源不存在", http_status=404)


@app.errorhandler(405)
def handle_405(exc):
    return error(code=ErrorCode.PARAM_INVALID,
                 message="不支持的请求方法", http_status=405)


@app.errorhandler(500)
def handle_500(exc):
    return error(code=ErrorCode.SYS_INTERNAL_ERROR,
                 message="服务器内部错误", http_status=500)


# ============================================================
# 辅助函数
# ============================================================

# 中国时区偏移：UTC+8
LOCAL_TZ = timezone(timedelta(hours=8))

def to_local_time(utc_iso_str):
    """将UTC ISO时间字符串转换为北京时间（UTC+8）"""
    if not utc_iso_str:
        return ""
    try:
        # 去除末尾的Z
        s = utc_iso_str.replace("Z", "")
        if "+" in utc_iso_str or (len(utc_iso_str) > 19 and utc_iso_str[19] == "+"):
            # 已经是带时区的时间
            dt = datetime.fromisoformat(utc_iso_str)
        else:
            dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone(LOCAL_TZ)
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return utc_iso_str[:19]

def require_permission_api(perm):
    """API层权限校验装饰器"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = auth_sm.get_current_user()
            if not user:
                return error(code=ErrorCode.AUTH_UNAUTHORIZED,
                             message="请先登录", http_status=401)
            if not auth_sm.check_permission(perm):
                return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                             message="权限不足，无法执行此操作", http_status=403)
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# 安全加固：输入校验常量
MAX_INPUT_LENGTH = 200       # 普通文本最大长度
MAX_NAME_LENGTH = 50         # 用户名/显示名称最大长度
MAX_PASSWORD_LENGTH = 128    # 密码最大长度
MAX_ORG_LENGTH = 100         # 组织名最大长度
ALLOWED_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]+$')

def sanitize_string(value, max_len=MAX_INPUT_LENGTH):
    """安全字符串处理：去除首尾空格、替换控制字符（兼容UTF-8）、超长截断"""
    if not value or not isinstance(value, str):
        return ""
    value = value.strip()
    # 逐字符替换控制字符（兼容UTF-8多字节序列，不破坏中文字符）
    cleaned = []
    for ch in value:
        cp = ord(ch)
        if cp < 0x20 and cp not in (0x09, 0x0a, 0x0d):  # 保留 TAB/LF/CR
            continue
        if cp == 0x7f:
            continue
        cleaned.append(ch)
    value = "".join(cleaned)
    return value[:max_len]


# CN字段白名单：只允许中文、字母、数字、空格、常见标点
CN_PATTERN = re.compile(r'^[\u4e00-\u9fff\u3400-\u4dbfa-zA-Z0-9\s\-_\.\(\)\[\]]+$')

def validate_cn_field(cn_value):
    """
    验证CN字段合法性（防注入、防路径遍历）

    规则：
    - 不能为空
    - 不能包含路径遍历符（../）
    - 不能包含特殊控制字符
    - 只允许中文、字母、数字、空格和常见标点
    """
    if not cn_value or not isinstance(cn_value, str):
        return False, "CN字段不能为空"
    cn_value = cn_value.strip()
    if len(cn_value) < 1 or len(cn_value) > MAX_NAME_LENGTH:
        return False, f"CN字段长度需在1-{MAX_NAME_LENGTH}个字符之间"
    if "../" in cn_value or "..\\" in cn_value:
        return False, "CN字段不能包含路径遍历符"
    if not CN_PATTERN.match(cn_value):
        return False, "CN字段包含非法字符（只允许中文、字母、数字、空格和常见标点）"
    return True, cn_value

def validate_safe_path(path_str):
    """防止路径遍历攻击：禁止包含 ../ 或绝对路径"""
    normalized = os.path.normpath(path_str).replace("\\", "/")
    if ".." in normalized.split("/"):
        return False
    if path_str.startswith("/") or (len(path_str) > 1 and path_str[1] == ":"):
        return False
    return True

def get_current_user():
    return auth_sm.get_current_user()

def get_current_username():
    user = get_current_user()
    return user["username"] if user else "unknown"

def get_current_role():
    user = get_current_user()
    return user["role"] if user else "end_user"

def load_cert_info(cert_path):
    """加载并解析证书信息"""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        is_ca = False
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except:
            pass
        # 检查吊销状态
        s = SecureRevokedList()
        revoked = s.is_revoked(cert.serial_number)

        # 计算过期状态
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        days_left = (not_after - now).days
        if days_left < 0:
            status = "已过期"
        elif days_left <= 7:
            status = "即将到期"
        elif revoked:
            status = "已吊销"
        else:
            status = "有效"

        return {
            "id": cert_path.stem,
            "serial": str(cert.serial_number),
            "cn": cn[0].value if cn else "未知",
            "org": org[0].value if org else "未知",
            "type": "CA证书" if is_ca else "用户证书",
            "issuer": issuer_cn[0].value if issuer_cn else "未知",
            "issuedAt": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
            "expiresAt": not_after.strftime("%Y-%m-%d"),
            "remainingDays": max(days_left, 0),
            "status": status,
            "isCA": is_ca,
            "isRevoked": revoked,
            "path": str(cert_path)
        }
    except Exception as e:
        return {"error": str(e), "path": str(cert_path)}

def get_cert_list():
    """获取所有证书列表"""
    certs = []
    for f in sorted(PKI_DEMO_DIR.glob("certs/*.pem")):
        info = load_cert_info(f)
        if "error" not in info:
            certs.append(info)
    # 按签发时间倒序
    certs.sort(key=lambda c: c.get("issuedAt", ""), reverse=True)
    return certs


# ============================================================
# API - 认证
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="请求数据不能为空", http_status=400)
    username = sanitize_string(data.get("username", ""), MAX_NAME_LENGTH)
    password = data.get("password", "").strip()
    if not username or not password:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="用户名和密码不能为空", http_status=400)
    if len(password) > MAX_PASSWORD_LENGTH:
        return error(code=ErrorCode.PARAM_TOO_LONG,
                     message="密码长度超限", http_status=400)

    ok, msg = auth_sm.login(username, password)
    if ok:
        user = auth_sm.get_current_user()
        # 将会话ID存入Flask session cookie（自动加密签名）
        session["session_id"] = auth_sm._current_sid
        session["username"] = username
        audit_logger.log("LOGIN", username, "LOGIN", "system", "SUCCESS",
                         f"用户{user['name']}登录系统", user["role"])
        role_map = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                     "auditor": "审计员", "end_user": "终端用户"}
        return success({
            "user": {
                "id": user["username"],
                "name": user["name"],
                "role": user["role"],
                "roleName": role_map.get(user["role"], user["role"])
            }
        }, message=msg)
    else:
        audit_logger.log("AUTH_FAIL", username, "LOGIN", "system", "FAILURE",
                         f"登录失败", "")
        return error(code=ErrorCode.AUTH_LOGIN_FAILED,
                     message=msg, http_status=401)


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    user = get_current_user()
    if user:
        audit_logger.log("LOGOUT", get_current_username(), "LOGOUT",
                         "system", "SUCCESS", f"用户{user['name']}退出系统",
                         get_current_role())
    auth_sm.logout()
    session.clear()
    return jsonify({"message": "已退出登录"})


@app.route("/api/auth/me", methods=["GET"])
def api_me():
    user = get_current_user()
    if not user:
        return error(code=ErrorCode.AUTH_UNAUTHORIZED,
                     message="未登录", http_status=401)
    role_map = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                 "auditor": "审计员", "end_user": "终端用户"}
    return success({
        "id": user["username"],
        "name": user["name"],
        "role": user["role"],
        "roleName": role_map.get(user["role"], user["role"])
    })


@app.route("/api/auth/cert-login", methods=["POST"])
def api_cert_login():
    """
    客户端证书自动登录（mTLS）
    从反向代理传递的 X-Client-Cert-* 头中提取客户端证书信息，
    自动创建登录会话（无需密码）。
    支持: Nginx $ssl_client_s_dn, Flask HTTPS 客户端证书
    """
    verify = request.headers.get("X-Client-Cert-Verify", "")
    if verify != "SUCCESS":
        audit_logger.log("CERT_LOGIN_FAIL", "anonymous", "LOGIN", "system", "FAILURE",
                         f"客户端证书验证失败: verify={verify}", "")
        return error(code=ErrorCode.AUTH_CERT_LOGIN_FAILED,
                     message="缺少有效客户端证书", http_status=401)

    subject_dn = request.headers.get("X-Client-Cert-Subject", "")

    if not subject_dn:
        audit_logger.log("CERT_LOGIN_FAIL", "anonymous", "LOGIN", "system", "FAILURE",
                         "请求头中无 X-Client-Cert-Subject", "")
        return error(code=ErrorCode.AUTH_CERT_LOGIN_FAILED,
                     message="请求中无客户端证书信息", http_status=401)

    # 解析 Subject DN，提取 CN 字段
    # 反向代理格式示例:
    #   Nginx $ssl_client_s_dn: CN=admin,O=Org,C=CN  (RFC 2253)
    #   OpenSSL format: /C=CN/O=Org/CN=admin
    cn = ""
    # 策略1: 按斜杠拆分（OpenSSL格式）
    for part in subject_dn.split("/"):
        p = part.strip()
        if p.startswith("CN="):
            cn = p[3:]
            break
    # 策略2: 如果策略1取到了但包含逗号（实际是RFC2253整段），截取第一个值
    if cn and "," in cn:
        cn = cn.split(",")[0].strip()
    # 策略3: RFC 2253 格式直接正则提取（处理没有斜杠的情况）
    if not cn:
        import re as _re
        m = _re.search(r'(?:^|,\s*)CN=([^,]+)', subject_dn)
        if m:
            cn = m.group(1).strip()

    if not cn:
        audit_logger.log("CERT_LOGIN_FAIL", "anonymous", "LOGIN", "system", "FAILURE",
                         f"无法从证书主题中提取CN: {subject_dn}", "")
        return error(code=ErrorCode.AUTH_CERT_LOGIN_FAILED,
                     message="无法从客户端证书中提取用户标识", http_status=401)

    # 在 users 表中查找匹配用户（CN 匹配 username）
    user_info = None
    try:
        with transaction() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (cn,)
            ).fetchone()
            if row:
                user_info = {
                    "username": row["username"],
                    "name": row["name"],
                    "role": row["role"],
                }
    except Exception:
        pass

    # 如果按 username 未找到，尝试按显示名称 name 匹配
    if not user_info:
        try:
            with transaction() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE name = ? AND is_active = 1",
                    (cn,)
                ).fetchone()
                if row:
                    user_info = {
                        "username": row["username"],
                        "name": row["name"],
                        "role": row["role"],
                    }
        except Exception:
            pass

    if not user_info:
        audit_logger.log("CERT_LOGIN_FAIL", cn, "LOGIN", "system", "FAILURE",
                         f"客户端证书CN({cn})未匹配到系统用户", "")
        return error(code=ErrorCode.AUTH_CERT_LOGIN_FAILED,
                     message=f"证书CN({cn})未匹配到系统用户", http_status=401)

    # 创建持久化会话（与普通 login 相同机制）
    sid = secrets.token_hex(32)
    now = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        with transaction() as conn:
            conn.execute(
                """INSERT INTO sessions
                   (session_id, username, user_info_json, login_time, last_access, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (sid, user_info["username"],
                 json.dumps(user_info, ensure_ascii=False),
                 now, now, now_iso)
            )
    except Exception as e:
        return error(code=ErrorCode.SYS_DB_ERROR,
                     message=f"会话创建失败: {e}", http_status=500)

    # 设置当前会话状态
    auth_sm._current_sid = sid
    auth_sm._cached_user = user_info
    session["session_id"] = sid
    session["username"] = user_info["username"]

    role_map = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                 "auditor": "审计员", "end_user": "终端用户"}

    audit_logger.log("CERT_LOGIN", user_info["username"], "LOGIN", "system", "SUCCESS",
                     f"客户端证书自动登录: {user_info['name']}({user_info['role']})",
                     user_info["role"])

    return success({
        "user": {
            "id": user_info["username"],
            "name": user_info["name"],
            "role": user_info["role"],
            "roleName": role_map.get(user_info["role"], user_info["role"])
        }
    }, message=f"客户端证书登录成功！欢迎 {user_info['name']}")


@app.route("/api/auth/users", methods=["GET"])
def api_users():
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except:
        pass
    um = UserManager()
    users = um.list_users()
    role_map = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                 "auditor": "审计员", "end_user": "终端用户"}
    result = []
    for u in users:
        result.append({
            "id": u["username"],
            "name": u["name"],
            "role": u["role"],
            "roleName": role_map.get(u["role"], u["role"]),
            "isActive": u.get("is_active", True)
        })
    return jsonify(result)


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    """用户注册（仅允许注册 end_user 角色）"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "请求数据不能为空"}), 400
    username = sanitize_string(data.get("username", ""), MAX_NAME_LENGTH)
    password = data.get("password", "").strip()
    name = sanitize_string(data.get("name", ""), MAX_NAME_LENGTH)

    if not username or not password or not name:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="用户名、密码和显示名称不能为空", http_status=400)
    if len(username) < 3 or len(username) > MAX_NAME_LENGTH:
        return error(code=ErrorCode.PARAM_INVALID,
                     message="用户名长度需在3-50个字符之间", http_status=400)
    if len(password) < 6:
        return error(code=ErrorCode.PARAM_INVALID,
                     message="密码长度至少6位", http_status=400)
    if len(password) > MAX_PASSWORD_LENGTH:
        return error(code=ErrorCode.PARAM_TOO_LONG,
                     message="密码长度不能超过128位", http_status=400)
    if len(name) < 1 or len(name) > MAX_NAME_LENGTH:
        return error(code=ErrorCode.PARAM_TOO_LONG,
                     message="显示名称长度超限", http_status=400)
    # 用户名只允许字母数字和下划线
    if not ALLOWED_USERNAME_PATTERN.match(username):
        return validation_error("username", "用户名只能包含字母、数字和下划线")

    um = UserManager()
    ok_ = um.add_user(username, password, name, "end_user")
    if ok_:
        audit_logger.log("USER_CREATE", get_current_username() if get_current_user() else "anonymous",
                         "CREATE", username, "SUCCESS", f"注册新用户:{name}({username})", "end_user")
        return success({"username": username}, message="注册成功，请登录")
    else:
        return error(code=ErrorCode.AUTH_USER_EXISTS,
                     message="用户名已存在", http_status=409)


@app.route("/api/auth/promote-reviewer", methods=["POST"])
def api_promote_reviewer():
    """管理员将普通用户提升为权限审核员"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json()
    username = data.get("username", "").strip()
    if not username:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="用户名不能为空", http_status=400)
    if username == get_current_username():
        return error(code=ErrorCode.PARAM_INVALID,
                     message="不能操作自己的账号", http_status=400)

    um = UserManager()
    ok_, msg = um.update_user_role(username, "ra_operator")
    if ok_:
        audit_logger.log("ROLE_CHANGE", get_current_username(), "UPDATE",
                         username, "SUCCESS",
                         f"将用户{username}提升为权限审核员", get_current_role())
        return success(message=msg)
    return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                 message=msg, http_status=400)


@app.route("/api/auth/demote-user", methods=["POST"])
def api_demote_user():
    """管理员将审核员降级为普通用户"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json()
    username = data.get("username", "").strip()
    if not username:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="用户名不能为空", http_status=400)
    if username == get_current_username():
        return error(code=ErrorCode.PARAM_INVALID,
                     message="不能操作自己的账号", http_status=400)

    um = UserManager()
    ok_, msg = um.update_user_role(username, "end_user")
    if ok_:
        audit_logger.log("ROLE_CHANGE", get_current_username(), "UPDATE",
                         username, "SUCCESS",
                         f"将用户{username}降级为普通用户", get_current_role())
        return success(message=msg)
    return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                 message=msg, http_status=400)


# ============================================================
# API - LDAP/AD 目录集成
# ============================================================

@app.route("/api/ldap/config", methods=["GET"])
def api_ldap_get_config():
    """获取 LDAP 配置"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)
    return success(ldap_connector.config.to_dict(),
                   message="LDAP配置获取成功")


@app.route("/api/ldap/config", methods=["POST"])
def api_ldap_save_config():
    """保存 LDAP 配置"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    cfg = ldap_connector.config
    for key in ["server", "port", "use_tls", "bind_dn", "bind_password",
                 "base_dn", "user_filter", "username_attr", "name_attr",
                 "email_attr", "department_attr", "enabled"]:
        if key in data:
            if key in ("port",):
                setattr(cfg, key, int(data[key]))
            elif key in ("use_tls", "enabled"):
                val = data[key]
                if isinstance(val, bool):
                    setattr(cfg, key, val)
                else:
                    setattr(cfg, key, str(val).lower() in ("1", "true", "yes"))
            else:
                setattr(cfg, key, str(data[key]))

    cfg.save()
    audit_logger.log("LDAP_CONFIG", get_current_username(), "UPDATE",
                     "ldap", "SUCCESS", "LDAP配置已更新", get_current_role())
    return success(cfg.to_dict(), message="LDAP配置已保存")


@app.route("/api/ldap/test", methods=["POST"])
def api_ldap_test():
    """测试 LDAP 连接"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    ok, msg = ldap_connector.test_connection()
    if ok:
        return success({"connected": True}, message=msg)
    return error(code=ErrorCode.SYS_CONFIG_ERROR,
                 message=msg, http_status=400)


@app.route("/api/ldap/sync", methods=["POST"])
def api_ldap_sync():
    """从 LDAP 同步用户"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    dry_run = data.get("dryRun", False)

    result = ldap_connector.sync_users(dry_run=dry_run)

    if result["status"] == "error":
        return error(code=ErrorCode.SYS_INTERNAL_ERROR,
                     message=result["message"], http_status=500)

    audit_logger.log("LDAP_SYNC", get_current_username(), "SYNC",
                     "ldap", "SUCCESS",
                     f"LDAP同步: 创建{result['created']} 跳过{result['skipped']} 错误{result['errors']}",
                     get_current_role())
    return success(result, message=result["message"])


@app.route("/api/ldap/search", methods=["POST"])
def api_ldap_search():
    """搜索 LDAP 用户"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    search_filter = data.get("filter", "")
    search_base = data.get("base", "")

    users = ldap_connector.search_users(
        search_base=search_base or None,
        search_filter=search_filter or None
    )
    return success({"users": users, "total": len(users)},
                   message=f"搜索到 {len(users)} 个用户")


# ============================================================
# API - 仪表盘统计
# ============================================================

@app.route("/api/stats", methods=["GET"])
def api_stats():
    certs = get_cert_list()
    total = len(certs)
    valid = sum(1 for c in certs if c["status"] == "有效")
    expiring = sum(1 for c in certs if c["status"] == "即将到期")
    revoked = sum(1 for c in certs if c["status"] == "已吊销")
    expired = sum(1 for c in certs if c["status"] == "已过期")

    # CRL中的吊销数
    s = SecureRevokedList()
    crl_count = len(s.get_revoked_list())

    # 待审核CSR
    pending = ra_manager.get_pending_list()
    pending_count = len(pending)

    # 备份数
    bm = BackupManager()
    backup_count = len(bm.list_backups())

    return jsonify({
        "totalCerts": total,
        "validCerts": valid,
        "expiringCerts": expiring,
        "revokedCerts": revoked,
        "expiredCerts": expired,
        "crlRevokedCount": crl_count,
        "pendingCsrCount": pending_count,
        "backupCount": backup_count,
        "caCerts": sum(1 for c in certs if c.get("isCA"))
    })


# ============================================================
# API - 证书管理
# ============================================================

@app.route("/api/certificates", methods=["GET"])
def api_certificates():
    certs = get_cert_list()
    user = get_current_user()
    role = user.get("role", "end_user") if user else "end_user"

    # 权限隔离：只有审核员和管理员可查看全部证书
    if role not in ("ra_operator", "ca_admin"):
        return jsonify([])

    # 过滤：只返回用户证书
    status_filter = request.args.get("status", "all")
    search = request.args.get("search", "").lower()

    filtered = [c for c in certs if not c.get("isCA")]
    if status_filter and status_filter != "all":
        filtered = [c for c in filtered if c["status"] == status_filter]
    if search:
        filtered = [c for c in filtered if
                    search in c["cn"].lower() or
                    search in c["serial"].lower() or
                    search in c["org"].lower()]
    return jsonify(filtered)


@app.route("/api/certificates/<serial>", methods=["GET"])
def api_certificate_detail(serial):
    for f in sorted(PKI_DEMO_DIR.glob("certs/*.pem")):
        info = load_cert_info(f)
        if info.get("serial") == serial:
            return jsonify(info)
    return jsonify({"error": "未找到该证书"}), 404


# ============================================================
# API - CSR申请
# ============================================================

@app.route("/api/csr/apply", methods=["POST"])
def api_csr_apply():
    user = get_current_user()
    if not user:
        return jsonify({"error": "未登录"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "请求数据不能为空"}), 400
    cn_raw = data.get("cn", "")
    org = sanitize_string(data.get("org", ""), MAX_ORG_LENGTH)
    valid, result = validate_cn_field(cn_raw)
    if not valid:
        return jsonify({"error": result}), 400
    cn = result
    if not org:
        return jsonify({"error": "所属组织不能为空"}), 400

    try:
        # 生成安全文件名（使用时间戳+哈希，避免中文等特殊字符导致文件写入失败）
        safe_tag = hashlib.sha256(cn.encode('utf-8')).hexdigest()[:12]
        ts = datetime.now().strftime('%Y%m%d%H%M%S')

        # 生成密钥对（根据配置自动选择 RSA/ECC/SM2）
        private_key = generate_keypair()
        # 保存私钥
        user_pwd = CFG.get_password("USER_KEY_PASSWORD")
        if not user_pwd:
            return jsonify({"error": "PKI_USER_KEY_PASSWORD未设置"}), 500
        key_path = PKI_DEMO_DIR / "keys" / f"user_{safe_tag}_{ts}_private.pem"
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(user_pwd)
        )
        with open(key_path, "wb") as f:
            f.write(pem_data)

        # 生成CSR
        csr_builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        csr_pem = sign_csr_with_hash(csr_builder, private_key, get_signature_hash(), default_backend())
        csr_path = PKI_DEMO_DIR / "csr" / f"user_{safe_tag}_{ts}_csr.pem"
        with open(csr_path, "wb") as f:
            f.write(csr_pem)

        # 提交RA
        csr_id = f"CSR-{safe_tag}-{ts}"
        success, msg = ra_manager.submit_csr(
            csr_id, cn, org, str(csr_path), get_current_username()
        )
        if not success:
            return jsonify({"error": msg}), 400

        audit_logger.log("CSR_CREATE", get_current_username(), "CREATE",
                         csr_id, "SUCCESS", f"用户{cn}提交证书申请", get_current_role())

        return jsonify({"message": "申请已提交", "csrId": csr_id,
                        "keyPath": str(key_path), "csrPath": str(csr_path)})
    except Exception as e:
        return jsonify({"error": f"申请失败: {str(e)}"}), 500


@app.route("/api/csr/upload", methods=["POST"])
def api_csr_upload():
    """用户上传本地生成的CSR（私钥不离开客户端）"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "未登录"}), 401

    csr_file = request.files.get("csr")
    if not csr_file:
        return jsonify({"error": "请上传CSR文件"}), 400

    cn = sanitize_string(request.form.get("cn", ""), 200)
    org = sanitize_string(request.form.get("org", ""), 200)
    if not cn or not org:
        return jsonify({"error": "CN和ORG不能为空"}), 400

    try:
        csr_data = csr_file.read()
        csr = x509.load_pem_x509_csr(csr_data, default_backend())
        # 验证CSR签名（确认上传者持有对应私钥）
        if not csr.is_signature_valid:
            return jsonify({"error": "CSR签名验证失败，请确认使用正确私钥生成"}), 400
        # 验证CSR的CN与提交的CN一致
        csr_cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        csr_cn = csr_cn_attr[0].value if csr_cn_attr else ""
        if csr_cn != cn:
            return jsonify({"error": f"CSR的CN({csr_cn})与提交的CN({cn})不一致"}), 400

        safe_tag = hashlib.sha256(cn.encode('utf-8')).hexdigest()[:12]
        ts = datetime.now().strftime('%Y%m%d%H%M%S')
        csr_path = PKI_DEMO_DIR / "csr" / f"user_{safe_tag}_{ts}_csr.pem"
        with open(csr_path, "wb") as f:
            f.write(csr_data)

        csr_id = f"CSR-{safe_tag}-{ts}"
        success, msg = ra_manager.submit_csr(
            csr_id, cn, org, str(csr_path), get_current_username()
        )
        if not success:
            return jsonify({"error": msg}), 400

        audit_logger.log("CSR_CREATE", get_current_username(), "CREATE",
                         csr_id, "SUCCESS", f"用户上传CSR: {cn}", get_current_role())
        return jsonify({"message": "CSR已提交", "csrId": csr_id,
                        "csrPath": str(csr_path)})
    except Exception as e:
        return jsonify({"error": f"CSR上传失败: {str(e)}"}), 500


@app.route("/api/csr/pending", methods=["GET"])
def api_csr_pending():
    """获取待审核CSR列表（仅审核员和管理员可查看全部）"""
    user = get_current_user()
    if not user:
        return jsonify({"error": "未登录"}), 401

    role = user.get("role", "end_user")
    pending = ra_manager.get_pending_list()

    # 权限隔离：只有审核员和管理员可看全部申请
    if role not in ("ra_operator", "ca_admin"):
        # 普通用户只能看自己的申请（通过 my-applications 接口）
        return jsonify([])

    result = []
    for item in pending:
        status_text = "待初审"
        if item["status"] == "first_approved":
            status_text = "待二审"
        result.append({
            "id": item["csr_id"],
            "cn": item["username"],
            "org": item["org"],
            "submittedAt": item["submitted_at"][:19],
            "status": item["status"],
            "statusText": status_text,
            "firstBy": item.get("reviewer_1", ""),
            "currentApprover": status_text
        })
    return jsonify(result)


@app.route("/api/csr/approve-first", methods=["POST"])
def api_csr_approve_first():
    try:
        require_permission_api(Permission.APPROVE_CSR)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json()
    csr_id = data.get("csrId", "")
    note = data.get("note", "")

    success, msg = ra_manager.approve_csr(csr_id, get_current_username(), note)
    if success:
        audit_logger.log("CSR_FIRST_APPROVE", get_current_username(), "UPDATE",
                         csr_id, "SUCCESS", msg, get_current_role())
        return jsonify({"message": msg})
    return jsonify({"error": msg}), 400


@app.route("/api/csr/approve-second", methods=["POST"])
def api_csr_approve_second():
    try:
        require_permission_api(Permission.APPROVE_CSR)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json()
    csr_id = data.get("csrId", "")
    note = data.get("note", "")

    success, msg = ra_manager.second_approve_csr(csr_id, get_current_username(), note)
    if success:
        audit_logger.log("CSR_SECOND_APPROVE", get_current_username(), "UPDATE",
                         csr_id, "SUCCESS", msg, get_current_role())
        # 二审通过后自动签发证书
        try:
            _issue_single_cert(csr_id)
            return jsonify({"message": f"申请 {csr_id} 已通过二审，证书已自动签发"})
        except Exception as e:
            return jsonify({
                "message": msg,
                "warning": f"审核通过，但证书自动签发失败: {str(e)}，请使用签发按钮手动签发"
            })
    return jsonify({"error": msg}), 400


@app.route("/api/csr/reject", methods=["POST"])
def api_csr_reject():
    try:
        require_permission_api(Permission.APPROVE_CSR)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json()
    csr_id = data.get("csrId", "")
    reason = data.get("reason", "未说明原因")

    # 调用RA的reject方法
    success, msg = ra_manager.reject_csr(csr_id, get_current_username(), reason)
    if success:
        return jsonify({"message": msg})
    return jsonify({"error": msg}), 400


@app.route("/api/csr/approved", methods=["GET"])
def api_csr_approved():
    approved = ra_manager.get_approved_list()
    result = []
    for item in approved:
        result.append({
            "id": item["csr_id"],
            "cn": item["username"],
            "org": item["org"],
            "submittedAt": item.get("submitted_at", "")[:19],
            "approvedAt": item.get("approved_at", "")[:19],
            "issued": False  # 在approved_list中均为待签发
        })
    return jsonify(result)


@app.route("/api/csr/my-applications", methods=["GET"])
def api_csr_my_applications():
    """获取当前用户自己的申请记录（pending + approved）"""
    username = get_current_username()
    if not username:
        return jsonify({"error": "未登录"}), 401

    # 从pending中查询
    pending_list = ra_manager.get_pending_list()
    my_pending = [item for item in pending_list if item.get("applicant") == username]

    # 从approved（待签发）中查询
    approved_list = ra_manager.get_approved_list()
    my_approved = [item for item in approved_list if item.get("applicant") == username]

    # 从已签发中查询
    issued_list = ra_manager.get_issued_list()
    my_issued = [item for item in issued_list if item.get("applicant") == username]

    result = []
    for item in my_pending:
        status_text = "待初审"
        if item["status"] == "first_approved":
            status_text = "待二审"
        result.append({
            "id": item["csr_id"],
            "cn": item["username"],
            "org": item["org"],
            "submittedAt": item.get("submitted_at", "")[:19],
            "status": item["status"],
            "statusText": status_text,
        })
    for item in my_approved:
        result.append({
            "id": item["csr_id"],
            "cn": item["username"],
            "org": item["org"],
            "submittedAt": item.get("submitted_at", "")[:19],
            "status": "approved",
            "statusText": "已批准待签发",
        })
    for item in my_issued:
        result.append({
            "id": item["csr_id"],
            "cn": item["username"],
            "org": item["org"],
            "submittedAt": item.get("submitted_at", "")[:19],
            "status": "issued",
            "statusText": "已签发",
        })

    # 按提交时间倒序
    result.sort(key=lambda x: x.get("submittedAt", ""), reverse=True)
    return jsonify(result)


# ============================================================
# API - 证书模板
# ============================================================

@app.route("/api/cert-templates", methods=["GET"])
def api_cert_templates():
    """获取所有证书模板列表"""
    return success(data=list_templates(), message="获取证书模板列表成功")


# ============================================================
# API - 证书签发（集成模板引擎）
# ============================================================

@app.route("/api/certificates/issue/<csr_id>", methods=["POST"])
def api_issue_cert(csr_id):
    try:
        require_permission_api(Permission.ISSUE_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    extra_sans = data.get("extraSans", [])
    extra_ips = data.get("extraIps", [])
    template_type = data.get("templateType", CertTemplateType.TLS_CLIENT.value)
    validity_days = data.get("validityDays", 0)

    # 验证模板参数
    valid, err_msg = validate_template_params(template_type, validity_days or None)
    if not valid:
        return error(code=ErrorCode.PARAM_INVALID, message=err_msg, http_status=400)

    try:
        _issue_single_cert(csr_id, san_dns=extra_sans, san_ip=extra_ips,
                           template_type=template_type, validity_days=validity_days)
        return success(message=f"证书已签发: {csr_id}")
    except Exception as e:
        return error(code=ErrorCode.CERT_ISSUE_FAILED,
                     message=f"证书签发失败: {str(e)}", http_status=500)


def _issue_single_cert(csr_id, san_dns=None, san_ip=None,
                       template_type=CertTemplateType.TLS_CLIENT.value,
                       validity_days=0):
    """签发单一证书（集成证书模板引擎）
    Args:
        csr_id: 已批准的CSR ID
        san_dns: 额外的DNS名称列表（如多域名证书）
        san_ip:  额外的IP地址列表（如无域名的内部服务器）
        template_type: 证书模板类型（默认TLS客户端证书）
        validity_days: 证书有效期（天），0表示使用模板默认值
    """
    approved = ra_manager.get_approved_list()
    item = next((x for x in approved if x["csr_id"] == csr_id), None)
    if not item:
        raise Exception(f"未找到已批准申请: {csr_id}")

    csr_path = item["csr_filepath"]
    if not os.path.exists(csr_path):
        raise Exception(f"CSR文件不存在: {csr_path}")

    # 加载CA
    ca_cert_path = BASE_DIR / "pki_demo/certs/inter_ca_cert.pem"
    ca_key_path = BASE_DIR / "pki_demo/keys/inter_ca_private.pem"
    if not ca_cert_path.exists():
        ca_cert_path = BASE_DIR / "pki_demo/certs/root_ca_cert.pem"
        ca_key_path = BASE_DIR / "pki_demo/keys/root_ca_private.pem"

    ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
    if not ca_pwd:
        raise Exception("CA_KEY_PASSWORD未设置")

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(), password=ca_pwd, backend=default_backend()
        )
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read(), default_backend())

    now = datetime.now(timezone.utc)

    # 确定有效期
    if validity_days and validity_days > 0:
        use_validity = validity_days
    else:
        use_validity = get_default_validity(template_type)

    # 构建SubjectAlternativeName（SAN）扩展
    cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn_value = cn_attr[0].value if cn_attr else "unknown"
    san_names = []
    # DNSName要求ASCII-only，对中文CN使用idna编码
    try:
        ascii_cn = cn_value.encode("idna").decode("ascii")
        san_names.append(DNSName(ascii_cn))
    except (UnicodeError, ValueError):
        fallback = "user-" + hashlib.sha256(cn_value.encode("utf-8")).hexdigest()[:12]
        san_names.append(DNSName(fallback))
        san_names.append(DNSName(fallback + ".pki.internal"))
    # 添加额外的DNS名称
    for dns in (san_dns or []):
        san_names.append(DNSName(dns))
    # 添加IP地址SAN
    for ip_str in (san_ip or []):
        san_names.append(IPAddress(ip_address(ip_str)))
    # RFC822Name同样要求ASCII
    try:
        safe_local = cn_value.encode("idna").decode("ascii")[:32]
    except (UnicodeError, ValueError):
        safe_local = "user" + hashlib.sha256(cn_value.encode("utf-8")).hexdigest()[:8]
    san_names.append(RFC822Name(f"{safe_local}@pki.internal"))

    # 构建证书
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=use_validity))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    )

    # 应用证书模板（EKU + KeyUsage）
    user_cert = apply_template_to_builder(user_cert, template_type)

    # CA签名
    cert_pem = sign_certificate_with_hash(user_cert, ca_key, get_signature_hash(), default_backend())

    # 从CSR ID提取标识(tag+ts)，与密钥文件命名一致
    csr_parts = csr_id.split('-')  # CSR-{safe_tag}-{ts}
    safe_tag = csr_parts[1] if len(csr_parts) >= 2 else hashlib.sha256(item['username'].encode('utf-8')).hexdigest()[:12]
    csr_ts = csr_parts[2] if len(csr_parts) >= 3 else datetime.now().strftime('%Y%m%d%H%M%S')
    cert_filename = f"user_{safe_tag}_{csr_ts}_cert.pem"
    cert_path = BASE_DIR / "pki_demo/certs" / cert_filename
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    ra_manager.mark_issued(item["csr_id"])
    audit_logger.log("CERT_ISSUE", get_current_username(), "CREATE",
                     cert_filename, "SUCCESS",
                     f"为用户{item['username']}签发证书", get_current_role())

    return cert_pem


# ============================================================
# API - CRL吊销管理
# ============================================================

@app.route("/api/revoked", methods=["GET"])
def api_revoked():
    s = SecureRevokedList()
    items = s.get_revoked_list()
    result = []
    for item in items:
        result.append({
            "serial": item["serial"],
            "cn": item["name"],
            "revokedAt": to_local_time(item.get("revoked_at", "")),
            "reason": item.get("reason", "unspecified"),
            "reasonDesc": item.get("reason_desc", "未指定"),
            "revokedBy": item.get("revoked_by", "系统")
        })
    return jsonify(result)


@app.route("/api/revoked/revoke", methods=["POST"])
def api_revoke_cert():
    try:
        require_permission_api(Permission.REVOKE_CERT)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json()
    serial = data.get("serial", "")
    cn = data.get("cn", "")
    reason = data.get("reason", "unspecified")
    reason_desc = data.get("reasonDesc", "未指定")

    s = SecureRevokedList()
    result = s.revoke(serial, cn, reason, reason_desc)
    if result:
        audit_logger.log("CERT_REVOKE", get_current_username(), "DELETE",
                         serial, "SUCCESS",
                         f"吊销证书{cn},原因:{reason_desc}", get_current_role())
        return jsonify({"message": f"证书已吊销: {cn}"})
    return jsonify({"error": "吊销失败，可能已被吊销"}), 400


@app.route("/api/revoked/check/<serial>", methods=["GET"])
def api_check_revoked(serial):
    s = SecureRevokedList()
    revoked = s.is_revoked(serial)
    info = {"serial": serial, "revoked": revoked}
    if revoked:
        for item in s.get_revoked_list():
            if item["serial"] == serial:
                info["reason"] = item.get("reason", "unknown")
                info["reasonDesc"] = item.get("reason_desc", "未知")
                info["revokedAt"] = item.get("revoked_at", "")[:19]
                break
    return jsonify(info)


@app.route("/api/revoked/generate-crl", methods=["POST"])
def api_generate_crl():
    try:
        require_permission_api(Permission.GENERATE_CRL)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    s = SecureRevokedList()
    revoked_list = s.get_revoked_list()
    if not revoked_list:
        return jsonify({"error": "没有已吊销的证书"}), 400

    try:
        ca_cert_path = BASE_DIR / "pki_demo/certs/inter_ca_cert.pem"
        ca_key_path = BASE_DIR / "pki_demo/keys/inter_ca_private.pem"
        if not ca_cert_path.exists():
            ca_cert_path = BASE_DIR / "pki_demo/certs/root_ca_cert.pem"
            ca_key_path = BASE_DIR / "pki_demo/keys/root_ca_private.pem"

        ca_pwd = CFG.get_password("CA_KEY_PASSWORD")
        if not ca_pwd:
            return jsonify({"error": "CA_KEY_PASSWORD未设置"}), 500

        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=ca_pwd, backend=default_backend()
            )
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        now = datetime.now(timezone.utc)
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(ca_cert.subject)
        crl_builder = crl_builder.last_update(now)
        crl_builder = crl_builder.next_update(now + timedelta(days=7))

        for item in revoked_list:
            try:
                revoked_at_str = item.get("revoked_at", now.isoformat())
                try:
                    revoked_at = datetime.fromisoformat(revoked_at_str)
                except:
                    revoked_at = now
                revoked_cert = x509.RevokedCertificateBuilder() \
                    .serial_number(int(item["serial"])) \
                    .revocation_date(revoked_at.replace(tzinfo=timezone.utc)) \
                    .build(default_backend())
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
            except:
                pass

        crl_pem = sign_crl_with_hash(crl_builder, ca_key, get_signature_hash(), default_backend())
        crl_path = BASE_DIR / "pki_demo/crl/ca_crl.pem"
        with open(crl_path, "wb") as f:
            f.write(crl_pem)

        audit_logger.log("CRL_GEN", get_current_username(), "CREATE",
                         "ca_crl.pem", "SUCCESS",
                         f"生成CRL，含{len(revoked_list)}条记录", get_current_role())

        return jsonify({
            "message": f"CRL生成成功！含{len(revoked_list)}条吊销记录",
            "count": len(revoked_list),
            "path": str(crl_path)
        })
    except Exception as e:
        return jsonify({"error": f"CRL生成失败: {str(e)}"}), 500


@app.route("/api/revoked/verify", methods=["GET"])
def api_verify_crl():
    s = SecureRevokedList()
    is_valid, msg = s.verify_integrity()
    return jsonify({"valid": is_valid, "message": msg})


# ============================================================
# API - OCSP 在线证书状态协议（RFC 6960）
# ============================================================

@app.route("/api/ocsp/status/<serial>", methods=["GET"])
def api_ocsp_status(serial):
    """查询单张证书的OCSP状态"""
    result = ocsp_responder.check_certificate(serial)
    status_code = 200 if result["status"] != 2 else 404
    return jsonify(result), status_code


@app.route("/api/ocsp/check-file", methods=["POST"])
def api_ocsp_check_file():
    """通过证书文件路径查询OCSP状态"""
    data = request.get_json(force=True, silent=True) or {}
    cert_path = data.get("path", "")
    if not cert_path:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="证书路径不能为空", http_status=400)
    # 路径安全检查
    if not validate_safe_path(cert_path):
        return error(code=ErrorCode.PARAM_INVALID,
                     message="证书路径不合法", http_status=400)
    result = ocsp_responder.check_certificate_by_file(cert_path)
    status_code = 200 if result["status"] != 2 else 404
    return jsonify(result), status_code


@app.route("/api/ocsp/batch", methods=["POST"])
def api_ocsp_batch():
    """批量查询多张证书的OCSP状态"""
    data = request.get_json(force=True, silent=True) or {}
    serials = data.get("serials", [])
    if not serials or not isinstance(serials, list):
        return error(code=ErrorCode.PARAM_MISSING,
                     message="serials 参数必须是证书序列号列表", http_status=400)
    if len(serials) > 200:
        return error(code=ErrorCode.PARAM_OUT_OF_RANGE,
                     message="批量查询最多支持200张证书", http_status=400)
    result = ocsp_responder.check_certificates_batch(serials)
    return jsonify(result)


@app.route("/api/ocsp/stats", methods=["GET"])
def api_ocsp_stats():
    """获取OCSP响应器统计信息"""
    return jsonify(ocsp_responder.get_statistics())


@app.route("/api/ocsp/cache/clear", methods=["POST"])
def api_ocsp_clear_cache():
    """清空OCSP缓存"""
    try:
        require_permission_api(Permission.GENERATE_CRL)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)
    return jsonify(ocsp_responder.clear_cache())


@app.route("/api/ocsp/signed/<serial>", methods=["GET"])
def api_ocsp_signed(serial):
    """RFC 6960 合规签名 OCSP 响应（DER 编码）

    返回 application/ocsp-response 类型的 DER 编码 OCSP 响应，
    使用 OCSP Responder 证书进行签名，符合 OCSP 协议合规要求。
    """
    try:
        der_bytes = ocsp_responder.build_signed_response(serial)
        if der_bytes is None:
            return error(code=ErrorCode.INTERNAL_ERROR,
                         message="OCSP响应构建失败", http_status=500)
        return Response(der_bytes, mimetype=OCSP_CONTENT_TYPE)
    except Exception as e:
        return error(code=ErrorCode.INTERNAL_ERROR,
                     message=f"OCSP签名响应失败: {str(e)}", http_status=500)


@app.route("/api/ocsp/responder-cert", methods=["GET"])
def api_ocsp_responder_cert():
    """获取 OCSP Responder 证书（PEM 格式）"""
    try:
        pem_bytes = ocsp_responder.get_responder_cert_pem()
        return Response(pem_bytes, mimetype="application/x-pem-file")
    except Exception as e:
        return error(code=ErrorCode.INTERNAL_ERROR,
                     message=f"获取OCSP响应者证书失败: {str(e)}", http_status=500)


# ============================================================
# API - SCEP 自动注册协议（RFC 8894）
# ============================================================

@app.route("/api/scep/cacerts", methods=["GET"])
def api_scep_cacerts():
    """SCEP: 获取 CA 证书"""
    cert_pem = scep_handler.get_ca_cert_pem()
    if not cert_pem:
        return error(code=ErrorCode.RESOURCE_NOT_FOUND,
                     message="CA证书不存在", http_status=404)
    return Response(cert_pem, mimetype="application/x-pki-message")


@app.route("/api/scep/cacaps", methods=["GET"])
def api_scep_cacaps():
    """SCEP: 获取 CA 能力"""
    return jsonify({"caps": scep_handler.get_ca_caps()})


@app.route("/api/scep/pkcsreq", methods=["POST"])
def api_scep_pkcsreq():
    """SCEP: 提交 PKCS#10 CSR（设备自动注册）"""
    try:
        require_permission_api(Permission.APPLY_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    csr_pem = data.get("csr", "")
    challenge = data.get("challengePassword", "")
    transaction_id = data.get("transactionId", "")

    if not csr_pem:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="CSR 内容不能为空", http_status=400)

    result = scep_handler.handle_pkcs_req(csr_pem, challenge, transaction_id)
    if result["status"] == "fail":
        return error(code=ErrorCode.CERT_CSR_INVALID,
                     message=result["message"], http_status=400)
    return jsonify(result)


@app.route("/api/scep/token", methods=["POST"])
def api_scep_generate_token():
    """SCEP: 管理员生成设备注册令牌"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    device = data.get("device", "").strip()
    if not device:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="设备名称不能为空", http_status=400)
    valid_hours = int(data.get("validHours", 24))
    if valid_hours < 1 or valid_hours > 720:
        return error(code=ErrorCode.PARAM_OUT_OF_RANGE,
                     message="有效期范围: 1-720小时", http_status=400)

    token = scep_handler.generate_scep_token(device, valid_hours)
    audit_logger.log("SCEP_TOKEN", get_current_username(), "CREATE",
                     device, "SUCCESS",
                     f"SCEP设备注册令牌已生成: {device}", get_current_role())
    return success(token, message=f"令牌已生成，有效期{valid_hours}小时")


@app.route("/api/scep/verify-token", methods=["POST"])
def api_scep_verify_token():
    """SCEP: 验证设备注册令牌"""
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "").strip()
    device = data.get("device", "").strip()
    if not token:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="令牌不能为空", http_status=400)
    valid = scep_handler.verify_scep_token(token, device or None)
    return success({"valid": valid}, message="令牌有效" if valid else "令牌无效或已过期")


# ============================================================
# API - EST 自动注册协议（RFC 7030）
# ============================================================

@app.route("/api/est/cacerts", methods=["GET"])
def api_est_cacerts():
    """EST: 获取 CA 证书链"""
    certs = est_handler.get_ca_certs_pkcs7()
    return Response(certs, mimetype="application/pkcs7-mime")


@app.route("/api/est/csrattrs", methods=["GET"])
def api_est_csrattrs():
    """EST: 获取 CSR 属性建议"""
    return jsonify(est_handler.get_csr_attributes())


@app.route("/api/est/simpleenroll", methods=["POST"])
def api_est_simpleenroll():
    """EST: 简单注册（设备自动申请证书）"""
    try:
        require_permission_api(Permission.APPLY_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    csr_pem = data.get("csr", "")
    if not csr_pem:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="CSR 内容不能为空", http_status=400)

    # EST 注册走标准 RA 审批流程
    result = scep_handler.handle_pkcs_req(csr_pem, challenge_password="",
                                          transaction_id=f"est_{secrets.token_hex(8)}")
    if result["status"] == "fail":
        return error(code=ErrorCode.CERT_CSR_INVALID,
                     message=result["message"], http_status=400)
    return success(result, message="EST注册请求已提交")


# ============================================================
# API - ACME 自动证书管理协议（RFC 8555）
# ============================================================

@app.route("/api/acme/directory", methods=["GET"])
def api_acme_directory():
    """ACME: 目录端点（ACME 客户端入口）"""
    base_url = request.host_url.rstrip("/")
    return jsonify(acme_server.get_directory(base_url))


@app.route("/api/acme/new-nonce", methods=["GET", "HEAD"])
def api_acme_new_nonce():
    """ACME: 获取新 Nonce"""
    nonce = acme_server.nonce_mgr.generate()
    resp = success({"nonce": nonce}, message="新 nonce 已生成")
    resp.headers["Replay-Nonce"] = nonce
    return resp


@app.route("/api/acme/new-account", methods=["POST"])
def api_acme_new_account():
    """ACME: 创建新账户"""
    try:
        require_permission_api(Permission.APPLY_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    payload = request.get_json(force=True, silent=True) or {}
    account = acme_server.create_account(payload)
    return success(account, message="ACME账户创建成功")


@app.route("/api/acme/new-order", methods=["POST"])
def api_acme_new_order():
    """ACME: 创建新订单（域名申请）"""
    try:
        require_permission_api(Permission.APPLY_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    payload = request.get_json(force=True, silent=True) or {}
    account_kid = payload.get("kid", "anonymous")
    order, err = acme_server.create_order(payload, account_kid)
    if err:
        return error(code=ErrorCode.CERT_CSR_INVALID,
                     message=err, http_status=400)
    return success(order, message="ACME订单已创建")


@app.route("/api/acme/challenge/<challenge_id>", methods=["POST"])
def api_acme_verify_challenge(challenge_id):
    """ACME: 验证 HTTP-01 挑战"""
    try:
        require_permission_api(Permission.APPLY_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    ok, msg = acme_server.order_mgr.verify_challenge(challenge_id)
    if ok:
        # 生成验证文件内容供客户端部署
        info = acme_server.setup_http01_challenge_file(challenge_id)
        return success(info, message="挑战验证通过")
    return error(code=ErrorCode.SYS_INTERNAL_ERROR,
                 message=msg, http_status=400)


@app.route("/api/acme/challenge/<challenge_id>/setup", methods=["GET"])
def api_acme_challenge_setup(challenge_id):
    """ACME: 获取 HTTP-01 验证文件配置信息"""
    info = acme_server.setup_http01_challenge_file(challenge_id)
    if not info:
        return error(code=ErrorCode.RESOURCE_NOT_FOUND,
                     message="挑战不存在", http_status=404)
    return success(info, message="验证文件配置信息")


@app.route("/api/acme/order/<order_id>", methods=["GET"])
def api_acme_get_order(order_id):
    """ACME: 查询订单状态"""
    order = acme_server.order_mgr.get_order(order_id)
    if not order:
        return error(code=ErrorCode.RESOURCE_NOT_FOUND,
                     message="订单不存在", http_status=404)
    return success(order, message="订单信息获取成功")


@app.route("/api/acme/finalize/<order_id>", methods=["POST"])
def api_acme_finalize(order_id):
    """ACME: 完成订单（提交 CSR 并签发证书）"""
    try:
        require_permission_api(Permission.ISSUE_CERT)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    data = request.get_json(force=True, silent=True) or {}
    csr_pem = data.get("csr", "")
    if not csr_pem:
        return error(code=ErrorCode.PARAM_MISSING,
                     message="CSR 内容不能为空", http_status=400)

    success_flag, result = acme_server.verify_and_finalize(order_id, csr_pem)
    if success_flag:
        return success(result, message="证书签发成功")
    return error(code=ErrorCode.CERT_ISSUE_FAILED,
                 message=result.get("error", "签发失败"), http_status=400)


@app.route("/api/acme/certificate/<cert_id>", methods=["GET"])
def api_acme_get_certificate(cert_id):
    """ACME: 获取已签发的证书"""
    cert_info = acme_server.order_mgr.get_certificate(cert_id)
    if not cert_info:
        return error(code=ErrorCode.RESOURCE_NOT_FOUND,
                     message="证书不存在", http_status=404)

    from flask import Response as FlaskResponse
    return FlaskResponse(
        cert_info["pem"],
        mimetype="application/pem-certificate-chain",
        headers={"Content-Disposition": f"attachment; filename=cert_{cert_id}.pem"}
    )


@app.route("/api/acme/authorization/<auth_id>", methods=["GET"])
def api_acme_get_auth(auth_id):
    """ACME: 查询授权状态"""
    auth = acme_server.order_mgr.get_authorization(auth_id)
    if not auth:
        return error(code=ErrorCode.RESOURCE_NOT_FOUND,
                     message="授权不存在", http_status=404)
    return success(auth, message="授权信息获取成功")


# ============================================================
# API - 审计日志
# ============================================================

@app.route("/api/audit", methods=["GET"])
def api_audit():
    limit_str = request.args.get("limit", "50")
    event_type = request.args.get("eventType", "")
    username = request.args.get("username", "")
    try:
        limit = int(limit_str)
    except:
        limit = 50

    results = audit_logger.query(
        event_type=event_type if event_type else None,
        username=username if username else None,
        limit=limit
    )

    entries = []
    for entry in results:
        entries.append({
            "time": to_local_time(entry.get("timestamp", "")),
            "user": entry.get("username", ""),
            "action": entry.get("event_type", ""),
            "resource": entry.get("resource", ""),
            "result": entry.get("result", ""),
            "detail": entry.get("detail", "")
        })
    return jsonify(entries)


@app.route("/api/audit/verify", methods=["GET"])
def api_audit_verify():
    is_valid, count, errors = audit_logger.verify_integrity()
    return jsonify({
        "valid": is_valid,
        "count": count,
        "errors": errors
    })


# ============================================================
# API - 备份管理
# ============================================================

@app.route("/api/backups", methods=["GET"])
def api_backups():
    bm = BackupManager()
    backups = bm.list_backups()
    result = []
    for b in backups:
        size_kb = b["size"] / 1024
        result.append({
            "name": b["file"],
            "size": f"{size_kb:.1f}KB",
            "createdAt": b["modified"][:19],
            "type": "全量备份",
            "status": "正常"
        })
    return jsonify(result)


@app.route("/api/backups/create", methods=["POST"])
def api_backup_create():
    data = request.get_json() or {}
    label = data.get("label", "")
    try:
        bm = BackupManager()
        backup_name = bm.create_backup(label=label)
        audit_logger.log("BACKUP", get_current_username(), "CREATE",
                         backup_name, "SUCCESS", "创建系统备份", get_current_role())
        return jsonify({"message": "备份创建成功", "name": backup_name})
    except Exception as e:
        return jsonify({"error": f"备份失败: {str(e)}"}), 500


# ============================================================
# API - 证书导出与分发
# ============================================================

@app.route("/api/ca-certificate", methods=["GET"])
def api_ca_certificate():
    """下载根CA证书（客户端配置信任锚点，.crt格式Windows双击可安装）"""
    ca_path = PKI_DEMO_DIR / "certs" / "root_ca_cert.pem"
    if not ca_path.exists():
        return jsonify({"error": "根CA证书不存在"}), 404
    return send_file(str(ca_path), mimetype="application/x-x509-ca-cert",
                     as_attachment=True,
                     download_name="root_ca_cert.crt")


@app.route("/api/certificates/<serial>/export-p12", methods=["POST"])
def api_export_p12(serial):
    """导出PKCS#12证书包（私钥+用户证书+CA链，Nginx/IIS通用格式）"""
    try:
        try:
            require_permission_api(Permission.EXPORT_P12)(lambda: None)()
        except AuthorizationError as e:
            return jsonify({"error": str(e)}), 403

        data = request.get_json() or {}
        export_password = data.get("password", "")
        if not export_password or len(export_password) < 6:
            return jsonify({"error": "导出口令必须≥6位"}), 400

        # 查找匹配的证书文件
        cert_dir = PKI_DEMO_DIR / "certs"
        cert_path = None
        private_key_path = None
        for f in cert_dir.glob("user_*.pem"):
            with open(f, "rb") as fh:
                try:
                    cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
                    if str(cert.serial_number) == serial:
                        cert_path = f
                        # 对应的私钥文件（CSR ID中包含的safe_tag和ts与cert文件名一致）
                        stem = f.stem.replace("_cert", "_private")
                        for key_dir in [PKI_DEMO_DIR / "keys"]:
                            for kf in key_dir.glob(f"{stem}*"):
                                private_key_path = kf
                                break
                        break
                except Exception:
                    continue

        if not cert_path:
            return jsonify({"error": "未找到匹配的证书"}), 404

        # 加载证书
        with open(cert_path, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # 加载私钥
        user_key = None
        if private_key_path and private_key_path.exists():
            user_pwd = CFG.get_password("USER_KEY_PASSWORD")
            if user_pwd:
                try:
                    with open(private_key_path, "rb") as f:
                        user_key = serialization.load_pem_private_key(
                            f.read(), password=user_pwd, backend=default_backend()
                        )
                except Exception as e_key:
                    user_key = None
        else:
            return jsonify({"error": f"私钥文件不存在: {private_key_path}"}), 404

        if not user_key:
            return jsonify({"error": "私钥文件未找到或无法解密"}), 404

        # 加载CA证书链
        ca_certs = []
        for ca_name in ["inter_ca_cert.pem", "root_ca_cert.pem"]:
            ca_path = cert_dir / ca_name
            if ca_path.exists():
                with open(ca_path, "rb") as f:
                    ca_certs.append(x509.load_pem_x509_certificate(f.read(), default_backend()))

        # 导出PKCS#12
        try:
            p12_data = serialization.pkcs12.serialize_key_and_certificates(
                name=b"PKI Certificate",
                key=user_key,
                cert=user_cert,
                cas=ca_certs,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    export_password.encode("utf-8")
                )
            )
            from io import BytesIO
            bio = BytesIO(p12_data)
            audit_logger.log("CERT_EXPORT", get_current_username(), "EXPORT",
                             serial, "SUCCESS", "导出PKCS#12证书包", get_current_role())
            return send_file(bio, mimetype="application/x-pkcs12",
                             as_attachment=True,
                             download_name=f"cert_{serial[:16]}.p12")
        except Exception as e:
            return jsonify({"error": f"PKCS#12导出失败: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"导出异常: {str(e)}"}), 500


@app.route("/api/certificates/<serial>/export-pem", methods=["GET"])
def api_export_pem(serial):
    """导出PEM格式证书文件"""
    cert_dir = PKI_DEMO_DIR / "certs"
    for f in cert_dir.glob("*.pem"):
        try:
            with open(f, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
                if str(cert.serial_number) == serial:
                    return send_file(str(f), mimetype="application/x-pem-file",
                                     as_attachment=True,
                                     download_name=f"cert_{serial[:16]}.pem")
        except Exception:
            continue
    return jsonify({"error": "未找到匹配的证书"}), 404


@app.route("/api/certificates/<serial>/export-crt", methods=["GET"])
def api_export_crt(serial):
    """导出CRT格式证书文件（Windows可双击安装）"""
    cert_dir = PKI_DEMO_DIR / "certs"
    for f in cert_dir.glob("*.pem"):
        try:
            with open(f, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read(), default_backend())
                if str(cert.serial_number) == serial:
                    return send_file(
                        str(f), mimetype="application/x-x509-ca-cert",
                        as_attachment=True,
                        download_name=f"cert_{serial[:16]}.crt"
                    )
        except Exception:
            continue
    return jsonify({"error": "未找到匹配的证书"}), 404


# ============================================================
# API - 系统配置
# ============================================================

@app.route("/api/expiry-check", methods=["GET"])
def api_expiry_check():
    """检查证书到期状态"""
    checker = CertExpiryChecker()
    results = checker.scan_certificates()
    if "error" in results:
        return error(code=ErrorCode.SYS_INTERNAL_ERROR,
                     message=results["error"], http_status=500)
    return jsonify(results)


@app.route("/api/expiry-check/alert", methods=["POST"])
def api_expiry_alert():
    """扫描并发送告警通知"""
    try:
        require_permission_api(Permission.GENERATE_CRL)(lambda: None)()
    except AuthorizationError as e:
        return error(code=ErrorCode.AUTH_PERMISSION_DENIED,
                     message=str(e), http_status=403)

    checker = CertExpiryChecker()
    result = checker.scan_and_alert()

    notifier_status = checker.get_notifier_status()
    return jsonify({
        "scan": result["scan"],
        "alerts": result["alerts"],
        "notifier": notifier_status,
    })


@app.route("/api/expiry-check/notifier-status", methods=["GET"])
def api_expiry_notifier_status():
    """获取告警通知器配置状态"""
    checker = CertExpiryChecker()
    return jsonify(checker.get_notifier_status())


# ============================================================
# API - 系统配置
# ============================================================

@app.route("/api/config", methods=["GET"])
def api_config():
    algo = CFG.get_algorithm_config()
    policy = CFG.get_cert_policy()
    security = CFG.get_security_config()
    return jsonify({
        "algorithm": {
            "hashAlgorithms": list(get_hash_algorithm.__module__ if hasattr(get_hash_algorithm, "__module__") else "SHA256"),
            "rsaKeySizes": [2048, 3072, 4096],
            "currentHash": "SM3" if os.environ.get("PKI_HASH_ALGORITHM") == "SM3" else "SHA256"
        },
        "certPolicy": policy if policy else {},
        "security": security if security else {}
    })


# ============================================================
# API - TSA 时间戳服务（RFC 3161）
# ============================================================

# 延迟导入 TSA 模块
def _get_tsa():
    from pki_demo.tsa import get_tsa
    return get_tsa()


@app.route("/api/tsa/timestamp", methods=["POST"])
def api_tsa_timestamp():
    """
    生成 RFC 3161 时间戳
    请求体: {
        "hashValue": "hex-encoded hash",
        "hashAlgorithm": "sha256" (default),
        "nonce": 12345 (optional, anti-replay),
        "policy": "1.2.3.4" (optional),
        "requester": "user@example.com" (optional)
    }
    """
    try:
        require_permission_api(Permission.TSA_TIMESTAMP)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json(force=True, silent=True) or {}
    if not data:
        return jsonify({"error": "请求数据不能为空"}), 400

    hash_value_hex = data.get("hashValue", "")
    hash_algo = data.get("hashAlgorithm", "sha256")
    nonce = data.get("nonce")
    policy = data.get("policy")
    requester = data.get("requester", get_current_username())

    if not hash_value_hex:
        return jsonify({"error": "hashValue 不能为空"}), 400

    try:
        hash_value = bytes.fromhex(hash_value_hex)
    except (ValueError, TypeError):
        return jsonify({"error": "hashValue 格式错误：需要十六进制编码"}), 400

    client_ip = request.remote_addr or "unknown"

    tsa = _get_tsa()
    result = tsa.generate_timestamp(
        hash_value=hash_value,
        hash_algo=hash_algo,
        client_ip=client_ip,
        nonce=nonce,
        policy=policy,
        requester=requester,
    )

    # 记录审计日志
    if result["status"] == 0:  # granted
        audit_logger.log(
            "TSA_TIMESTAMP", get_current_username(), "CREATE",
            f"TST-{result.get('serialNumber', 'unknown')}", "SUCCESS",
            f"签发时间戳: 算法={hash_algo}, 序列号={result.get('serialNumber', 'N/A')}",
            get_current_role()
        )
        # 同时存入数据库
        try:
            from pki_demo.database import transaction
            now_iso = datetime.now(timezone.utc).isoformat()
            with transaction() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO tst_records
                       (serial_number, hash_algorithm, hash_value, gen_time,
                        policy_oid, nonce, tst_info_hex, tst_token_hex,
                        client_ip, requester, status, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        result.get("serialNumber", ""),
                        hash_algo,
                        hash_value_hex,
                        result.get("genTime", now_iso),
                        policy or "",
                        nonce,
                        result.get("tstInfo", ""),
                        result.get("tstToken", ""),
                        client_ip,
                        requester,
                        "granted",
                        now_iso,
                    )
                )
        except Exception:
            pass  # DB存储失败不影响主流程
        return jsonify({
            "status": "granted",
            "statusCode": 0,
            "statusString": result["statusString"],
            "serialNumber": result["serialNumber"],
            "genTime": result["genTime"],
            "hashAlgorithm": result["hashAlgorithm"],
            "hashValue": result["hashValue"],
            "tstToken": result["tstToken"],
            "tstInfo": result["tstInfo"],
            "driftSeconds": result.get("driftSeconds", 0),
            "ntpAvailable": result.get("ntpAvailable", False),
        })
    elif result["status"] == 2:  # rejected
        # 记录安全事件（如果超速或重放）
        try:
            from pki_demo.database import transaction
            now_iso = datetime.now(timezone.utc).isoformat()
            failure = result.get("failureInfo", "")
            event_type = "tsa_replay" if "重放" in failure else (
                "tsa_rate_limit" if "速率" in failure else "tsa_rejection"
            )
            with transaction() as conn:
                conn.execute(
                    """INSERT INTO tsa_security_events
                       (event_type, client_ip, detail, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (event_type, client_ip, failure, now_iso)
                )
        except Exception:
            pass
        return jsonify({
            "status": "rejected",
            "statusCode": 2,
            "statusString": result["statusString"],
            "failureInfo": result.get("failureInfo", "未知错误"),
        }), 400

    return jsonify(result)


@app.route("/api/tsa/timestamp/file", methods=["POST"])
def api_tsa_timestamp_file():
    """
    文件上传时间戳接口 - 上传文件自动计算哈希并签发时间戳
    请求: multipart/form-data
        - file: 要签发时间戳的文件
        - hashAlgorithm: sha256/sha384/sha512/sm3 (optional, default: sha256)
    返回:
        - 时间戳令牌 + 文件哈希 + 文件信息
    """
    try:
        require_permission_api(Permission.TSA_TIMESTAMP)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    if "file" not in request.files:
        return jsonify({"error": "请上传文件"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "文件名为空"}), 400

    hash_algo_name = request.form.get("hashAlgorithm", "sha256").lower()
    hash_algo_name = hash_algo_name.replace("-", "")

    # 读取文件内容并计算哈希
    file_data = file.read()
    algo_map = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
        "sm3": hashlib.new("sm3") if hasattr(hashlib, "new") else None,
    }
    if hash_algo_name == "sm3":
        try:
            from cryptography.hazmat.primitives import hashes as crypto_hashes
            digest = crypto_hashes.Hash(crypto_hashes.SM3())
            digest.update(file_data)
            hash_value = digest.finalize()
        except Exception:
            return jsonify({"error": "SM3 哈希计算失败，请使用其他算法或检查 cryptography 版本"}), 400
    else:
        hasher = algo_map.get(hash_algo_name)
        if hasher is None:
            return jsonify({"error": f"不支持的哈希算法: {hash_algo_name}"}), 400
        hasher.update(file_data)
        hash_value = hasher.digest()

    file_size = len(file_data)
    file_name = file.filename

    # 签发时间戳
    client_ip = request.remote_addr or "unknown"
    requester = get_current_username()

    tsa = _get_tsa()
    result = tsa.generate_timestamp(
        hash_value=hash_value,
        hash_algo=hash_algo_name,
        client_ip=client_ip,
        requester=requester,
    )

    if result["status"] != 0:
        return jsonify({
            "status": "rejected",
            "failureInfo": result.get("failureInfo", "时间戳生成失败"),
        }), 400

    # 记录审计日志
    audit_logger.log(
        "TSA_TIMESTAMP", requester, "CREATE",
        f"FILE-{file_name}", "SUCCESS",
        f"文件[{file_name}]时间戳签发: 算法={hash_algo_name}, 大小={file_size}字节",
        get_current_role()
    )

    return jsonify({
        "status": "granted",
        "statusString": "文件时间戳签发成功",
        "fileInfo": {
            "fileName": file_name,
            "fileSize": file_size,
            "fileSizeStr": _format_file_size(file_size),
        },
        "hashAlgorithm": hash_algo_name,
        "hashValue": hash_value.hex(),
        "serialNumber": result.get("serialNumber", ""),
        "genTime": result.get("genTime", ""),
        "tstToken": result.get("tstToken", ""),
        "tstInfo": result.get("tstInfo", ""),
        "driftSeconds": result.get("driftSeconds", 0),
        "ntpAvailable": result.get("ntpAvailable", False),
    })


@app.route("/api/tsa/timestamp/text", methods=["POST"])
def api_tsa_timestamp_text():
    """
    文本内容时间戳接口 - 提交文本自动计算哈希并签发时间戳
    请求体: {
        "content": "要加盖时间戳的文本内容",
        "hashAlgorithm": "sha256" (optional),
        "title": "内容标题 (optional)"
    }
    返回:
        - 时间戳令牌 + 内容哈希 + 内容预览
    """
    try:
        require_permission_api(Permission.TSA_TIMESTAMP)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    body = request.get_json(force=True, silent=True) or {}
    if not body or not body.get("content"):
        return jsonify({"error": "content 不能为空"}), 400

    content = body["content"]
    title = body.get("title", "").strip()
    hash_algo_name = body.get("hashAlgorithm", "sha256").lower().replace("-", "")

    # 计算内容哈希
    content_bytes = content.encode("utf-8")
    if hash_algo_name == "sm3":
        try:
            from cryptography.hazmat.primitives import hashes as crypto_hashes
            digest = crypto_hashes.Hash(crypto_hashes.SM3())
            digest.update(content_bytes)
            hash_value = digest.finalize()
        except Exception:
            return jsonify({"error": "SM3 哈希计算失败"}), 400
    else:
        import hashlib as hl
        algo_fn = getattr(hl, hash_algo_name, None)
        if algo_fn is None:
            return jsonify({"error": f"不支持的哈希算法: {hash_algo_name}"}), 400
        hash_value = algo_fn(content_bytes).digest()

    # 签发时间戳
    client_ip = request.remote_addr or "unknown"
    requester = get_current_username()

    tsa = _get_tsa()
    result = tsa.generate_timestamp(
        hash_value=hash_value,
        hash_algo=hash_algo_name,
        client_ip=client_ip,
        requester=requester,
    )

    if result["status"] != 0:
        return jsonify({
            "status": "rejected",
            "failureInfo": result.get("failureInfo", "时间戳生成失败"),
        }), 400

    # 记录审计日志
    content_preview = content[:100].replace("\n", " ")
    audit_logger.log(
        "TSA_TIMESTAMP", requester, "CREATE",
        f"TEXT-{title or 'untitled'}", "SUCCESS",
        f"文本时间戳签发: 算法={hash_algo_name}, 预览={content_preview}",
        get_current_role()
    )

    return jsonify({
        "status": "granted",
        "statusString": "文本时间戳签发成功",
        "contentInfo": {
            "title": title or "(无标题)",
            "contentLength": len(content),
            "preview": content[:80] + ("..." if len(content) > 80 else ""),
        },
        "hashAlgorithm": hash_algo_name,
        "hashValue": hash_value.hex(),
        "serialNumber": result.get("serialNumber", ""),
        "genTime": result.get("genTime", ""),
        "tstToken": result.get("tstToken", ""),
        "tstInfo": result.get("tstInfo", ""),
        "driftSeconds": result.get("driftSeconds", 0),
        "ntpAvailable": result.get("ntpAvailable", False),
    })


def _format_file_size(size_bytes):
    """格式化文件大小显示"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


@app.route("/api/tsa/verify", methods=["POST"])
def api_tsa_verify():
    """
    验证时间戳令牌
    请求体: {
        "tstToken": "hex-encoded PKCS7 signed data",
        "originalHash": "hex-encoded original hash (optional)",
        "hashAlgorithm": "sha256" (optional)
    }
    """
    try:
        require_permission_api(Permission.TSA_VERIFY)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json(force=True, silent=True) or {}
    if not data or not data.get("tstToken"):
        return jsonify({"error": "tstToken 不能为空"}), 400

    tst_token_hex = data["tstToken"]
    original_hash_hex = data.get("originalHash")
    hash_algo = data.get("hashAlgorithm")

    original_hash = None
    if original_hash_hex:
        try:
            original_hash = bytes.fromhex(original_hash_hex)
        except (ValueError, TypeError):
            return jsonify({"error": "originalHash 格式错误"}), 400

    tsa = _get_tsa()
    result = tsa.verify_timestamp(
        tst_token_hex=tst_token_hex,
        original_hash=original_hash,
        hash_algo=hash_algo,
    )

    audit_logger.log(
        "TSA_VERIFY", get_current_username(), "READ",
        "tst_token", "SUCCESS" if result.get("valid") else "FAILURE",
        f"验签{'通过' if result.get('valid') else '失败'}: {result.get('message', '')}",
        get_current_role()
    )

    return jsonify(result)


@app.route("/api/tsa/certificate", methods=["GET"])
def api_tsa_certificate():
    """获取 TSA 签名证书"""
    tsa = _get_tsa()
    cert_pem = tsa.get_tsa_certificate_pem()
    if not cert_pem:
        return jsonify({"error": "TSA 证书未配置"}), 404
    return Response(
        cert_pem.decode("utf-8") if isinstance(cert_pem, bytes) else cert_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=tsa_cert.pem"}
    )


@app.route("/api/tsa/status", methods=["GET"])
def api_tsa_status():
    """获取 TSA 服务状态"""
    tsa = _get_tsa()
    stats = tsa.get_stats()
    return jsonify(stats)


@app.route("/api/tsa/sync-time", methods=["POST"])
def api_tsa_sync_time():
    """强制同步 NTP 时间"""
    try:
        require_permission_api(Permission.TSA_MANAGE)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    tsa = _get_tsa()
    status = tsa.time_source.force_sync()
    return jsonify({"message": "NTP时间同步完成", "status": status})


@app.route("/api/tsa/reload-cert", methods=["POST"])
def api_tsa_reload_cert():
    """重新加载 TSA 证书（签发新证书后调用）"""
    try:
        require_permission_api(Permission.TSA_MANAGE)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    tsa = _get_tsa()
    success = tsa.reload_certificate()
    if success:
        return jsonify({"message": "TSA证书已重新加载"})
    return jsonify({"error": "TSA证书加载失败，请先签发TSA证书"}), 400


@app.route("/api/tsa/records", methods=["GET"])
def api_tsa_records():
    """获取时间戳签发记录"""
    try:
        require_permission_api(Permission.TSA_VERIFY)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    limit_str = request.args.get("limit", "100")
    try:
        limit = min(int(limit_str), 500)
    except:
        limit = 100

    try:
        from pki_demo.database import transaction
        with transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM tst_records ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        records = []
        for row in rows:
            records.append({
                "serialNumber": row["serial_number"],
                "hashAlgorithm": row["hash_algorithm"],
                "hashValue": row["hash_value"][:32] + "...",
                "genTime": to_local_time(row["gen_time"]),
                "requester": row["requester"] or "",
                "clientIp": row["client_ip"] or "",
                "status": row["status"],
                "createdAt": row["created_at"][:19] if row["created_at"] else "",
            })
        return jsonify(records)
    except Exception as e:
        return jsonify({"error": f"查询失败: {e}"}), 500


# ============================================================
# API - TSA 业务场景
# ============================================================

def _save_scenario_record(scenario_type, tst_serial, biz_id, biz_desc,
                          hash_value, created_by):
    """保存业务场景记录到数据库"""
    try:
        from pki_demo.database import transaction
        now_iso = datetime.now(timezone.utc).isoformat()
        with transaction() as conn:
            conn.execute(
                """INSERT INTO tsa_scenarios
                   (scenario_type, tst_serial, biz_id, biz_desc,
                    hash_value, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scenario_type, tst_serial, biz_id, biz_desc,
                 hash_value, created_by, now_iso)
            )
        return True
    except Exception:
        return False


@app.route("/api/tsa/scenario/contract-sign", methods=["POST"])
def api_tsa_scenario_contract():
    """
    电子合同签署场景 - 为合同数字签名附加时间戳
    请求体: {
        "contractId": "合同编号",
        "contractHash": "合同SHA-256哈希",
        "signatureValue": "数字签名值 (optional)",
        "signerId": "签署人标识",
        "hashAlgorithm": "sha256" (default)
    }
    """
    try:
        require_permission_api(Permission.TSA_TIMESTAMP)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json(force=True, silent=True) or {}
    contract_id = sanitize_string(data.get("contractId", ""), 100)
    contract_hash = data.get("contractHash", "")
    signature = data.get("signatureValue", "")
    signer_id = sanitize_string(data.get("signerId", ""), 100)
    hash_algo = data.get("hashAlgorithm", "sha256")

    if not contract_id or not contract_hash:
        return jsonify({"error": "contractId 和 contractHash 不能为空"}), 400

    try:
        hash_value = bytes.fromhex(contract_hash)
    except (ValueError, TypeError):
        return jsonify({"error": "contractHash 格式错误"}), 400

    client_ip = request.remote_addr or "unknown"
    tsa = _get_tsa()

    result = tsa.generate_timestamp(
        hash_value=hash_value,
        hash_algo=hash_algo,
        client_ip=client_ip,
        requester=f"contract:{contract_id}",
    )

    if result["status"] == 0:
        # 记录业务场景
        biz_desc = f"电子合同签署: {contract_id}, 签署人: {signer_id}"
        if signature:
            biz_desc += f", 签名值: {signature[:32]}..."
        _save_scenario_record(
            "contract_sign", result.get("serialNumber", ""),
            contract_id, biz_desc, contract_hash,
            get_current_username()
        )
        audit_logger.log(
            "TSA_SCENARIO", get_current_username(), "CREATE",
            contract_id, "SUCCESS",
            f"电子合同[{contract_id}]时间戳附加完成，TST序列号: {result.get('serialNumber', '')}",
            get_current_role()
        )
        return jsonify({
            "message": f"合同 {contract_id} 时间戳附加成功",
            "contractId": contract_id,
            "signerId": signer_id,
            "timestamp": result,
        })

    return jsonify({"error": result.get("failureInfo", "时间戳生成失败")}), 400


@app.route("/api/tsa/scenario/code-release", methods=["POST"])
def api_tsa_scenario_code_release():
    """
    源代码版本发布场景 - 为代码仓库提交哈希生成时间戳
    请求体: {
        "repoName": "代码仓库名称",
        "commitHash": "Git提交哈希",
        "branch": "分支名称",
        "tag": "发布标签 (optional)",
        "committer": "提交者",
        "hashAlgorithm": "sha256" (default)
    }
    """
    try:
        require_permission_api(Permission.TSA_TIMESTAMP)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json(force=True, silent=True) or {}
    repo_name = sanitize_string(data.get("repoName", ""), 100)
    commit_hash = sanitize_string(data.get("commitHash", ""), 100)
    branch = sanitize_string(data.get("branch", "main"), 50)
    tag = sanitize_string(data.get("tag", ""), 50)
    committer = sanitize_string(data.get("committer", ""), 100)
    hash_algo = data.get("hashAlgorithm", "sha256")

    if not repo_name or not commit_hash:
        return jsonify({"error": "repoName 和 commitHash 不能为空"}), 400

    # 对 commit hash 进行哈希（时间戳需要定长哈希值）
    import hashlib as _hl
    h = _hl.sha256(commit_hash.encode("utf-8"))
    hash_value = h.digest()

    client_ip = request.remote_addr or "unknown"
    tsa = _get_tsa()

    result = tsa.generate_timestamp(
        hash_value=hash_value,
        hash_algo="sha256",
        client_ip=client_ip,
        requester=f"code:{repo_name}:{commit_hash[:12]}",
    )

    if result["status"] == 0:
        biz_id = f"{repo_name}::{commit_hash[:16]}"
        biz_desc = (f"代码版本发布: 仓库={repo_name}, "
                    f"提交={commit_hash[:16]}, 分支={branch}")
        if tag:
            biz_desc += f", 标签={tag}"
        _save_scenario_record(
            "code_release", result.get("serialNumber", ""),
            biz_id, biz_desc, hash_value.hex(),
            get_current_username()
        )
        audit_logger.log(
            "TSA_SCENARIO", get_current_username(), "CREATE",
            biz_id, "SUCCESS",
            f"代码发布[{repo_name}:{commit_hash[:12]}]时间戳完成，TST: {result.get('serialNumber', '')}",
            get_current_role()
        )
        return jsonify({
            "message": f"代码提交 {commit_hash[:16]} 时间戳固化成功",
            "repoName": repo_name,
            "commitHash": commit_hash,
            "branch": branch,
            "tag": tag,
            "committer": committer,
            "timestamp": result,
        })

    return jsonify({"error": result.get("failureInfo", "时间戳生成失败")}), 400


@app.route("/api/tsa/scenario/archive", methods=["POST"])
def api_tsa_scenario_archive():
    """
    电子档案归档场景 - 为档案入库生成时间戳
    请求体: {
        "archiveId": "档案编号",
        "archiveHash": "档案文件SHA-256哈希",
        "archiveName": "档案名称",
        "archiveType": "档案类型",
        "department": "归档部门",
        "hashAlgorithm": "sha256" (default)
    }
    """
    try:
        require_permission_api(Permission.TSA_TIMESTAMP)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json(force=True, silent=True) or {}
    archive_id = sanitize_string(data.get("archiveId", ""), 100)
    archive_hash = data.get("archiveHash", "")
    archive_name = sanitize_string(data.get("archiveName", ""), 200)
    archive_type = sanitize_string(data.get("archiveType", ""), 50)
    department = sanitize_string(data.get("department", ""), 100)
    hash_algo = data.get("hashAlgorithm", "sha256")

    if not archive_id or not archive_hash:
        return jsonify({"error": "archiveId 和 archiveHash 不能为空"}), 400

    try:
        hash_value = bytes.fromhex(archive_hash)
    except (ValueError, TypeError):
        return jsonify({"error": "archiveHash 格式错误"}), 400

    client_ip = request.remote_addr or "unknown"
    tsa = _get_tsa()

    result = tsa.generate_timestamp(
        hash_value=hash_value,
        hash_algo=hash_algo,
        client_ip=client_ip,
        requester=f"archive:{archive_id}",
    )

    if result["status"] == 0:
        biz_desc = (f"电子档案归档: {archive_name or archive_id}, "
                    f"类型={archive_type}, 部门={department}")
        _save_scenario_record(
            "archive", result.get("serialNumber", ""),
            archive_id, biz_desc, archive_hash,
            get_current_username()
        )
        audit_logger.log(
            "TSA_SCENARIO", get_current_username(), "CREATE",
            archive_id, "SUCCESS",
            f"档案[{archive_id}]归档时间戳完成，TST序列号: {result.get('serialNumber', '')}",
            get_current_role()
        )
        return jsonify({
            "message": f"档案 {archive_id} 归档时间戳固化成功",
            "archiveId": archive_id,
            "archiveName": archive_name,
            "archiveType": archive_type,
            "department": department,
            "timestamp": result,
        })

    return jsonify({"error": result.get("failureInfo", "时间戳生成失败")}), 400


@app.route("/api/tsa/scenario/records", methods=["GET"])
def api_tsa_scenario_records():
    """获取业务场景使用记录"""
    try:
        require_permission_api(Permission.TSA_VERIFY)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    scenario_type = request.args.get("scenarioType", "")
    limit_str = request.args.get("limit", "100")
    try:
        limit = min(int(limit_str), 500)
    except:
        limit = 100

    try:
        from pki_demo.database import transaction
        query = "SELECT * FROM tsa_scenarios"
        params = []
        if scenario_type:
            query += " WHERE scenario_type = ?"
            params.append(scenario_type)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with transaction() as conn:
            rows = conn.execute(query, params).fetchall()

        records = []
        for row in rows:
            records.append({
                "id": row["id"],
                "scenarioType": row["scenario_type"],
                "tstSerial": row["tst_serial"],
                "bizId": row["biz_id"],
                "bizDesc": row["biz_desc"],
                "createdBy": row["created_by"],
                "createdAt": to_local_time(row["created_at"]),
            })
        return jsonify(records)
    except Exception as e:
        return jsonify({"error": f"查询失败: {e}"}), 500


# ============================================================
# 静态文件服务（前端UI）
# ============================================================

@app.route("/")
def serve_index():
    return send_from_directory(str(BASE_DIR / "pki_ui"), "index.html")


@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def serve_static(path):
    # API路径直接404（应已被上方API路由匹配）
    if path.startswith("api/"):
        return jsonify({"error": "API route not found"}), 404
    file_path = BASE_DIR / "pki_ui" / path
    if file_path.exists() and file_path.is_file():
        return send_from_directory(str(BASE_DIR / "pki_ui"), path)
    # SPA路由：返回index.html
    return send_from_directory(str(BASE_DIR / "pki_ui"), "index.html")


# ============================================================
# 启动入口
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PKI API Server")
    parser.add_argument("--https", action="store_true",
                        help="启用 HTTPS（原生 Flask SSL，无需 Nginx）")
    parser.add_argument("--gen-ssl", action="store_true",
                        help="自动生成 SSL 证书并启用 HTTPS")
    parser.add_argument("--port", type=int, default=None,
                        help="指定端口号（默认 HTTP:8080, HTTPS:8443）")
    args = parser.parse_args()

    # 初始化：创建目录
    for d in ["certs", "keys", "csr", "crl", "export", "data", "backups"]:
        (PKI_DEMO_DIR / d).mkdir(exist_ok=True)

    # 初始化数据库（建表 + 迁移旧JSON数据）
    init_database()

    # 检查关键环境变量
    missing = []
    for name in ["CA_KEY_PASSWORD", "USER_KEY_PASSWORD", "CRL_HMAC_KEY",
                  "AUDIT_HMAC_KEY", "P12_EXPORT_PASSWORD"]:
        if not CFG.get_password(name):
            missing.append(f"PKI_{name}")

    if missing:
        print(f"[WARN] 环境变量未设置: {', '.join(missing)}")
        print("       建议运行 pki_demo/setup_env.bat 配置")

    use_https = args.https or os.environ.get("PKI_USE_HTTPS", "").lower() in ("1", "true", "yes")
    gen_ssl = args.gen_ssl or os.environ.get("PKI_GEN_SSL", "").lower() in ("1", "true", "yes")

    # 端口
    if args.port:
        port = args.port
    else:
        port = int(os.environ.get("PKI_API_PORT", 8443 if use_https else 8080))

    if gen_ssl:
        print("[PKI API Server] 正在生成 SSL 证书...")
        import subprocess
        subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "gen_flask_ssl_cert.py")],
                       cwd=str(BASE_DIR))
        use_https = True

    ssl_cert = PKI_DEMO_DIR / "certs" / "flask_ssl_cert.pem"
    ssl_key = PKI_DEMO_DIR / "certs" / "flask_ssl_key.pem"

    if use_https:
        if not ssl_cert.exists() or not ssl_key.exists():
            print(f"[WARN] SSL 证书不存在，正在自动生成...")
            import subprocess
            subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "gen_flask_ssl_cert.py")],
                           cwd=str(BASE_DIR))

        if ssl_cert.exists() and ssl_key.exists():
            protocol = "https"
            url_prefix = "https"
            print(f"[PKI API Server] HTTPS 模式已启用")
            print(f"[PKI API Server] 证书: {ssl_cert}")
        else:
            protocol = "http"
            url_prefix = "http"
            use_https = False
            print(f"[WARN] SSL 证书生成失败，回退到 HTTP 模式")
    else:
        protocol = "http"
        url_prefix = "http"

    print(f"[PKI API Server] 启动中...")
    print(f"[PKI API Server] {url_prefix}://localhost:{port}")
    print(f"[PKI API Server] 前端界面: {url_prefix}://localhost:{port}/")

    if use_https and ssl_cert.exists() and ssl_key.exists():
        context = (str(ssl_cert), str(ssl_key))
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False,
                ssl_context=context)
    else:
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
