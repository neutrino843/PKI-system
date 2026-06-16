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
sys.path.insert(0, str(PKI_DEMO_DIR))

from flask import Flask, request, jsonify, send_from_directory, send_file, session, Response
from flask_cors import CORS

# 导入PKI后端模块
from config import CFG
from auth import (_session_manager as auth_sm, Permission, Role,
                  ROLE_PERMISSIONS, UserManager, require_permission,
                  AuthorizationError)
from audit import audit_logger
from ra import ra_manager
from security_crl import SecureRevokedList
from security_crypto import get_hash_algorithm, get_rsa_key_size, FileIntegrityChecker
from backup import BackupManager
from cert_expiry import CertExpiryChecker
from database import init_database, transaction

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import SubjectAlternativeName, DNSName, RFC822Name, IPAddress
from ipaddress import ip_address

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("PKI_FLASK_SECRET", "pki_system_secret_key_change_in_production")
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
                return jsonify({"error": "未登录", "code": 401}), 401
            if not auth_sm.check_permission(perm):
                return jsonify({"error": "权限不足", "code": 403}), 403
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
        return jsonify({"error": "请求数据不能为空"}), 400
    username = sanitize_string(data.get("username", ""), MAX_NAME_LENGTH)
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    if len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({"error": "密码长度超限"}), 400

    success, msg = auth_sm.login(username, password)
    if success:
        user = auth_sm.get_current_user()
        # 将会话ID存入Flask session cookie（自动加密签名）
        session["session_id"] = auth_sm._current_sid
        session["username"] = username
        audit_logger.log("LOGIN", username, "LOGIN", "system", "SUCCESS",
                         f"用户{user['name']}登录系统", user["role"])
        role_map = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                     "auditor": "审计员", "end_user": "终端用户"}
        return jsonify({
            "message": msg,
            "user": {
                "id": user["username"],
                "name": user["name"],
                "role": user["role"],
                "roleName": role_map.get(user["role"], user["role"])
            }
        })
    else:
        audit_logger.log("AUTH_FAIL", username, "LOGIN", "system", "FAILURE",
                         f"登录失败", "")
        return jsonify({"error": msg}), 401


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
        return jsonify({"error": "未登录"}), 401
    role_map = {"ca_admin": "CA管理员", "ra_operator": "RA操作员",
                 "auditor": "审计员", "end_user": "终端用户"}
    return jsonify({
        "id": user["username"],
        "name": user["name"],
        "role": user["role"],
        "roleName": role_map.get(user["role"], user["role"])
    })


@app.route("/api/auth/cert-login", methods=["POST"])
def api_cert_login():
    """
    客户端证书自动登录（mTLS）
    从 Nginx 传递的 X-Client-Cert-* 头中提取客户端证书信息，
    自动创建登录会话（无需密码）。
    """
    verify = request.headers.get("X-Client-Cert-Verify", "")
    if verify != "SUCCESS":
        audit_logger.log("CERT_LOGIN_FAIL", "anonymous", "LOGIN", "system", "FAILURE",
                         f"客户端证书验证失败: verify={verify}", "")
        return jsonify({"error": "缺少有效客户端证书"}), 401

    subject_dn = request.headers.get("X-Client-Cert-Subject", "")

    if not subject_dn:
        audit_logger.log("CERT_LOGIN_FAIL", "anonymous", "LOGIN", "system", "FAILURE",
                         "请求头中无 X-Client-Cert-Subject", "")
        return jsonify({"error": "请求中无客户端证书信息"}), 401

    # 解析 Subject DN，提取 CN 字段
    # Nginx $ssl_client_s_dn 格式为 RFC 2253: CN=admin,O=Org,C=CN
    # 或者 OpenSSL 格式: /C=CN/O=Org/CN=admin
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
        return jsonify({"error": "无法从客户端证书中提取用户标识"}), 401

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
        return jsonify({"error": f"证书CN({cn})未匹配到系统用户"}), 401

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
        return jsonify({"error": f"会话创建失败: {e}"}), 500

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

    return jsonify({
        "message": f"客户端证书登录成功！欢迎 {user_info['name']}",
        "user": {
            "id": user_info["username"],
            "name": user_info["name"],
            "role": user_info["role"],
            "roleName": role_map.get(user_info["role"], user_info["role"])
        }
    })


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
        return jsonify({"error": "用户名、密码和显示名称不能为空"}), 400
    if len(username) < 3 or len(username) > MAX_NAME_LENGTH:
        return jsonify({"error": "用户名长度需在3-50个字符之间"}), 400
    if len(password) < 6:
        return jsonify({"error": "密码长度至少6位"}), 400
    if len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({"error": "密码长度不能超过128位"}), 400
    if len(name) < 1 or len(name) > MAX_NAME_LENGTH:
        return jsonify({"error": "显示名称长度超限"}), 400
    # 用户名只允许字母数字和下划线
    if not ALLOWED_USERNAME_PATTERN.match(username):
        return jsonify({"error": "用户名只能包含字母、数字和下划线"}), 400

    um = UserManager()
    success = um.add_user(username, password, name, "end_user")
    if success:
        audit_logger.log("USER_CREATE", get_current_username() if get_current_user() else "anonymous",
                         "CREATE", username, "SUCCESS", f"注册新用户:{name}({username})", "end_user")
        return jsonify({"message": "注册成功，请登录", "username": username})
    else:
        return jsonify({"error": "用户名已存在"}), 409


@app.route("/api/auth/promote-reviewer", methods=["POST"])
def api_promote_reviewer():
    """管理员将普通用户提升为权限审核员"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json()
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "用户名不能为空"}), 400
    if username == get_current_username():
        return jsonify({"error": "不能操作自己的账号"}), 400

    um = UserManager()
    success, msg = um.update_user_role(username, "ra_operator")
    if success:
        audit_logger.log("ROLE_CHANGE", get_current_username(), "UPDATE",
                         username, "SUCCESS",
                         f"将用户{username}提升为权限审核员", get_current_role())
        return jsonify({"message": msg})
    return jsonify({"error": msg}), 400


@app.route("/api/auth/demote-user", methods=["POST"])
def api_demote_user():
    """管理员将审核员降级为普通用户"""
    try:
        require_permission_api(Permission.MANAGE_USERS)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json()
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "用户名不能为空"}), 400
    if username == get_current_username():
        return jsonify({"error": "不能操作自己的账号"}), 400

    um = UserManager()
    success, msg = um.update_user_role(username, "end_user")
    if success:
        audit_logger.log("ROLE_CHANGE", get_current_username(), "UPDATE",
                         username, "SUCCESS",
                         f"将用户{username}降级为普通用户", get_current_role())
        return jsonify({"message": msg})
    return jsonify({"error": msg}), 400


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

        # 生成密钥对
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=get_rsa_key_size(), backend=default_backend()
        )
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
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, get_hash_algorithm(), default_backend())
        )
        csr_path = PKI_DEMO_DIR / "csr" / f"user_{safe_tag}_{ts}_csr.pem"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

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
        return jsonify({"message": msg})
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
            "issued": item.get("issued", False)
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

    # 从approved中查询
    approved_list = ra_manager.get_approved_list()
    my_approved = [item for item in approved_list if item.get("applicant") == username]

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
        issued = item.get("issued", False)
        status_text = "已签发" if issued else "已批准待签发"
        result.append({
            "id": item["csr_id"],
            "cn": item["username"],
            "org": item["org"],
            "submittedAt": item.get("submitted_at", "")[:19],
            "status": "issued" if issued else item["status"],
            "statusText": status_text,
        })

    # 按提交时间倒序
    result.sort(key=lambda x: x.get("submittedAt", ""), reverse=True)
    return jsonify(result)


@app.route("/api/certificates/issue/<csr_id>", methods=["POST"])
def api_issue_cert(csr_id):
    try:
        require_permission_api(Permission.ISSUE_CERT)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    data = request.get_json(force=True, silent=True) or {}
    extra_sans = data.get("extraSans", [])
    extra_ips = data.get("extraIps", [])

    try:
        _issue_single_cert(csr_id, san_dns=extra_sans, san_ip=extra_ips)
        return jsonify({"message": f"证书已签发: {csr_id}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _issue_single_cert(csr_id, san_dns=None, san_ip=None):
    """签发单一证书
    Args:
        csr_id: 已批准的CSR ID
        san_dns: 额外的DNS名称列表（如多域名证书）
        san_ip:  额外的IP地址列表（如无域名的内部服务器）
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

    user_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
        .sign(ca_key, get_hash_algorithm(), default_backend())
    )

    # 从CSR ID提取标识(tag+ts)，与密钥文件命名一致
    csr_parts = csr_id.split('-')  # CSR-{safe_tag}-{ts}
    safe_tag = csr_parts[1] if len(csr_parts) >= 2 else hashlib.sha256(item['username'].encode('utf-8')).hexdigest()[:12]
    csr_ts = csr_parts[2] if len(csr_parts) >= 3 else datetime.now().strftime('%Y%m%d%H%M%S')
    cert_filename = f"user_{safe_tag}_{csr_ts}_cert.pem"
    cert_path = BASE_DIR / "pki_demo/certs" / cert_filename
    with open(cert_path, "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))

    ra_manager.mark_issued(item["csr_id"])
    audit_logger.log("CERT_ISSUE", get_current_username(), "CREATE",
                     cert_filename, "SUCCESS",
                     f"为用户{item['username']}签发证书", get_current_role())

    return user_cert


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

        crl = crl_builder.sign(ca_key, get_hash_algorithm(), default_backend())
        crl_path = BASE_DIR / "pki_demo/crl/ca_crl.pem"
        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

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
    checker = CertExpiryChecker()
    results = checker.scan_certificates()
    if "error" in results:
        return jsonify({"error": results["error"]}), 500
    return jsonify(results)


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
    from tsa import get_tsa
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
            from database import transaction
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
            from database import transaction
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
        from database import transaction
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
        from database import transaction
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
        from database import transaction
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

    port = int(os.environ.get("PKI_API_PORT", 8080))
    print(f"[PKI API Server] 启动中...")
    print(f"[PKI API Server] http://localhost:{port}")
    print(f"[PKI API Server] 前端界面: http://localhost:{port}/")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
