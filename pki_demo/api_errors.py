"""
================================================================
  标准化 API 错误码与响应格式
  功能：统一API错误响应结构，便于客户端错误处理
================================================================
"""

from flask import jsonify


# ============================================================
# 错误码定义
# ============================================================
class ErrorCode:
    """标准 API 错误码常量"""

    # 认证相关 (AUTH-xxx)
    AUTH_UNAUTHORIZED = "AUTH_UNAUTHORIZED"           # 未登录
    AUTH_PERMISSION_DENIED = "AUTH_PERMISSION_DENIED"  # 权限不足
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED"            # 登录失败
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"  # 凭据无效
    AUTH_USER_EXISTS = "AUTH_USER_EXISTS"              # 用户已存在
    AUTH_CERT_LOGIN_FAILED = "AUTH_CERT_LOGIN_FAILED"  # 证书登录失败
    AUTH_INVALID_INPUT = "AUTH_INVALID_INPUT"          # 输入校验失败

    # 请求参数相关 (PARAM-xxx)
    PARAM_MISSING = "PARAM_MISSING"                    # 缺少必要参数
    PARAM_INVALID = "PARAM_INVALID"                    # 参数格式错误
    PARAM_TOO_LONG = "PARAM_TOO_LONG"                  # 参数超长
    PARAM_OUT_OF_RANGE = "PARAM_OUT_OF_RANGE"          # 参数超出范围

    # 资源相关 (RESOURCE-xxx)
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"          # 资源不存在
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"            # 资源冲突
    RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS"  # 资源已存在
    RESOURCE_EXPIRED = "RESOURCE_EXPIRED"              # 资源已过期

    # 证书相关 (CERT-xxx)
    CERT_ISSUE_FAILED = "CERT_ISSUE_FAILED"            # 签发失败
    CERT_REVOKE_FAILED = "CERT_REVOKE_FAILED"          # 吊销失败
    CERT_EXPORT_FAILED = "CERT_EXPORT_FAILED"          # 导出失败
    CERT_ALREADY_REVOKED = "CERT_ALREADY_REVOKED"      # 已吊销
    CERT_NOT_FOUND = "CERT_NOT_FOUND"                  # 证书未找到
    CERT_CSR_NOT_FOUND = "CERT_CSR_NOT_FOUND"          # CSR未找到
    CERT_CSR_INVALID = "CERT_CSR_INVALID"              # CSR无效
    CERT_CA_KEY_MISSING = "CERT_CA_KEY_MISSING"        # CA密钥未配置

    # TSA 时间戳相关 (TSA-xxx)
    TSA_REJECTED = "TSA_REJECTED"                      # 时间戳请求被拒
    TSA_RATE_LIMITED = "TSA_RATE_LIMITED"              # 速率限制
    TSA_REPLAY_DETECTED = "TSA_REPLAY_DETECTED"        # 重放攻击检测
    TSA_CERT_MISSING = "TSA_CERT_MISSING"              # TSA证书未配置

    # 系统相关 (SYS-xxx)
    SYS_INTERNAL_ERROR = "SYS_INTERNAL_ERROR"          # 服务器内部错误
    SYS_CONFIG_ERROR = "SYS_CONFIG_ERROR"              # 配置错误
    SYS_DB_ERROR = "SYS_DB_ERROR"                      # 数据库错误
    SYS_CRYPTO_ERROR = "SYS_CRYPTO_ERROR"              # 密码学运算错误
    SYS_NOT_IMPLEMENTED = "SYS_NOT_IMPLEMENTED"        # 功能未实现

    # CRL相关 (CRL-xxx)
    CRL_GENERATION_FAILED = "CRL_GENERATION_FAILED"    # CRL生成失败
    CRL_EMPTY = "CRL_EMPTY"                            # 无吊销记录

    # 备份相关 (BACKUP-xxx)
    BACKUP_FAILED = "BACKUP_FAILED"                    # 备份失败
    BACKUP_NOT_FOUND = "BACKUP_NOT_FOUND"              # 备份不存在


# ============================================================
# HTTP 状态码与错误码映射
# ============================================================
ERROR_HTTP_STATUS = {
    # 400 Bad Request
    ErrorCode.PARAM_MISSING: 400,
    ErrorCode.PARAM_INVALID: 400,
    ErrorCode.PARAM_TOO_LONG: 400,
    ErrorCode.PARAM_OUT_OF_RANGE: 400,
    ErrorCode.CERT_CSR_INVALID: 400,
    ErrorCode.TSA_REJECTED: 400,
    ErrorCode.TSA_RATE_LIMITED: 429,
    ErrorCode.TSA_REPLAY_DETECTED: 400,
    ErrorCode.CERT_ALREADY_REVOKED: 400,

    # 401 Unauthorized
    ErrorCode.AUTH_UNAUTHORIZED: 401,
    ErrorCode.AUTH_LOGIN_FAILED: 401,
    ErrorCode.AUTH_INVALID_CREDENTIALS: 401,
    ErrorCode.AUTH_CERT_LOGIN_FAILED: 401,

    # 403 Forbidden
    ErrorCode.AUTH_PERMISSION_DENIED: 403,

    # 404 Not Found
    ErrorCode.RESOURCE_NOT_FOUND: 404,
    ErrorCode.CERT_NOT_FOUND: 404,
    ErrorCode.CERT_CSR_NOT_FOUND: 404,
    ErrorCode.BACKUP_NOT_FOUND: 404,

    # 409 Conflict
    ErrorCode.RESOURCE_CONFLICT: 409,
    ErrorCode.RESOURCE_ALREADY_EXISTS: 409,
    ErrorCode.AUTH_USER_EXISTS: 409,

    # 500 Internal Server Error
    ErrorCode.SYS_INTERNAL_ERROR: 500,
    ErrorCode.SYS_CONFIG_ERROR: 500,
    ErrorCode.SYS_DB_ERROR: 500,
    ErrorCode.SYS_CRYPTO_ERROR: 500,
    ErrorCode.CERT_ISSUE_FAILED: 500,
    ErrorCode.CERT_EXPORT_FAILED: 500,
    ErrorCode.CRL_GENERATION_FAILED: 500,
    ErrorCode.BACKUP_FAILED: 500,
    ErrorCode.CERT_CA_KEY_MISSING: 500,
    ErrorCode.TSA_CERT_MISSING: 500,
}


# ============================================================
# 标准响应构建
# ============================================================

def success(data=None, message="操作成功"):
    """
    构建标准成功响应

    返回格式：
    {
        "success": true,
        "message": "操作成功",
        "data": { ... }
    }
    """
    resp = {
        "success": True,
        "message": message,
    }
    if data is not None:
        resp["data"] = data
    return jsonify(resp)


def error(code=ErrorCode.SYS_INTERNAL_ERROR, message="服务器内部错误",
          details=None, http_status=None):
    """
    构建标准错误响应

    返回格式：
    {
        "success": false,
        "error": {
            "code": "ERROR_CODE",
            "message": "人类可读的错误描述",
            "details": { ... }
        }
    }

    参数：
        code: 错误码（ErrorCode 常量）
        message: 人类可读的错误描述
        details: 附加错误详情（可选）
        http_status: HTTP 状态码，默认根据错误码自动映射
    """
    if http_status is None:
        http_status = ERROR_HTTP_STATUS.get(code, 500)

    error_body = {
        "code": code,
        "message": message,
    }
    if details is not None:
        error_body["details"] = details

    return jsonify({
        "success": False,
        "error": error_body,
    }), http_status


def validation_error(field, message):
    """
    构建字段校验错误响应

    参数：
        field: 字段名
        message: 校验错误描述
    """
    return error(
        code=ErrorCode.AUTH_INVALID_INPUT,
        message=f"字段 '{field}' 校验失败",
        details={"field": field, "reason": message},
        http_status=400
    )


def paginated_result(items, total=None, page=1, page_size=20):
    """
    构建分页结果响应

    返回格式：
    {
        "success": true,
        "data": [ ... ],
        "pagination": {
            "total": 100,
            "page": 1,
            "pageSize": 20,
            "totalPages": 5
        }
    }
    """
    resp = {
        "success": True,
        "data": items,
    }
    if total is not None:
        resp["pagination"] = {
            "total": total,
            "page": page,
            "pageSize": page_size,
            "totalPages": max(1, (total + page_size - 1) // page_size),
        }
    return jsonify(resp)


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    print("=== API 错误码模块测试 ===\n")

    # 测试错误码映射
    print("测试错误码映射：")
    for code_name in dir(ErrorCode):
        if code_name.startswith("_"):
            continue
        code_value = getattr(ErrorCode, code_name)
        if isinstance(code_value, str) and code_value.count("_") >= 1:
            http_status = ERROR_HTTP_STATUS.get(code_value, 500)
            print(f"  {code_name}: {code_value} -> HTTP {http_status}")

    print(f"\n共定义 {len([x for x in dir(ErrorCode) if not x.startswith('_') and isinstance(getattr(ErrorCode, x), str)])} 个错误码")
    print(f"[OK] 模块初始化正常")
