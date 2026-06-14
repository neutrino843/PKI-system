"""
PKI系统 - REST API 后端服务
基于Flask封装现有pki_demo模块，为前端提供HTTP API接口
"""
import os
import sys
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

# 确保能导入pki_demo模块
BASE_DIR = Path(__file__).parent.resolve()
PKI_DEMO_DIR = BASE_DIR / "pki_demo"
sys.path.insert(0, str(PKI_DEMO_DIR))

from flask import Flask, request, jsonify, send_from_directory
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

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, static_folder=None)
CORS(app, supports_credentials=True)

# ============================================================
# 辅助函数
# ============================================================

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
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    success, msg = auth_sm.login(username, password)
    if success:
        user = auth_sm.get_current_user()
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
    data = request.get_json()
    cn = data.get("cn", "").strip()
    org = data.get("org", "").strip()
    if not cn or not org:
        return jsonify({"error": "通用名称和所属组织不能为空"}), 400

    try:
        # 生成密钥对
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=get_rsa_key_size(), backend=default_backend()
        )
        # 保存私钥
        user_pwd = CFG.get_password("USER_KEY_PASSWORD")
        if not user_pwd:
            return jsonify({"error": "PKI_USER_KEY_PASSWORD未设置"}), 500
        key_path = PKI_DEMO_DIR / "keys" / f"user_{cn}_private.pem"
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
        csr_path = PKI_DEMO_DIR / "csr" / f"user_{cn}_csr.pem"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        # 提交RA
        csr_id = f"CSR-{cn}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
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


@app.route("/api/csr/pending", methods=["GET"])
def api_csr_pending():
    """获取待审核CSR列表"""
    pending = ra_manager.get_pending_list()
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
        # 签发证书
        try:
            _issue_single_cert(csr_id)
        except Exception as e:
            pass  # 签发失败不影响审批结果
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


@app.route("/api/certificates/issue/<csr_id>", methods=["POST"])
def api_issue_cert(csr_id):
    try:
        require_permission_api(Permission.ISSUE_CERT)(lambda: None)()
    except AuthorizationError as e:
        return jsonify({"error": str(e)}), 403

    try:
        _issue_single_cert(csr_id)
        return jsonify({"message": f"证书已签发: {csr_id}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _issue_single_cert(csr_id):
    """签发单一证书"""
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
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, get_hash_algorithm(), default_backend())
    )

    cert_path = BASE_DIR / "pki_demo/certs" / f"user_{item['username']}_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))

    ra_manager.mark_issued(item["csr_id"])
    audit_logger.log("CERT_ISSUE", get_current_username(), "CREATE",
                     f"user_{item['username']}_cert.pem", "SUCCESS",
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
            "revokedAt": item.get("revoked_at", "")[:19],
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
            "time": entry.get("timestamp", "")[:19],
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
# API - 证书到期检查
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
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
