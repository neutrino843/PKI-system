"""
================================================================
  证书模板引擎（cert_template.py）
  功能：可配置的证书模板，支持自定义EKU/SAN/有效期/密钥用途
================================================================
"""

from enum import Enum
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization


# ============================================================
# 证书模板定义
# ============================================================

class CertTemplateType(Enum):
    """证书模板类型枚举"""
    TLS_SERVER = "tls_server"           # TLS服务端证书
    TLS_CLIENT = "tls_client"           # TLS客户端证书
    CODE_SIGNING = "code_signing"       # 代码签名证书
    SMIME = "smime"                     # 邮件签名/加密证书
    VPN_CLIENT = "vpn_client"           # VPN客户端证书
    DOCUMENT_SIGNING = "document_signing"  # 文档签名证书
    TIMESTAMPING = "timestamping"       # 时间戳证书
    CUSTOM = "custom"                   # 自定义证书


TEMPLATE_LABELS = {
    CertTemplateType.TLS_SERVER: "TLS 服务端证书",
    CertTemplateType.TLS_CLIENT: "TLS 客户端证书",
    CertTemplateType.CODE_SIGNING: "代码签名证书",
    CertTemplateType.SMIME: "邮件安全证书 (S/MIME)",
    CertTemplateType.VPN_CLIENT: "VPN 客户端证书",
    CertTemplateType.DOCUMENT_SIGNING: "文档签名证书",
    CertTemplateType.TIMESTAMPING: "时间戳证书",
    CertTemplateType.CUSTOM: "自定义证书",
}


# ============================================================
# 证书模板定义
# ============================================================

# 模板配置：{模板类型: {EKU列表, KeyUsage配置, 默认有效期}}
CERT_TEMPLATES = {
    CertTemplateType.TLS_SERVER: {
        "label": "TLS 服务端证书",
        "description": "用于Web服务器HTTPS加密",
        "eku": [
            ExtendedKeyUsageOID.SERVER_AUTH,
        ],
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 730,  # 2年
        "require_san": True,
        "san_hint": "域名或IP地址",
    },
    CertTemplateType.TLS_CLIENT: {
        "label": "TLS 客户端证书",
        "description": "用于客户端身份认证（mTLS）",
        "eku": [
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ],
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 730,
        "require_san": False,
        "san_hint": "用户名或邮箱",
    },
    CertTemplateType.CODE_SIGNING: {
        "label": "代码签名证书",
        "description": "用于签名可执行文件/脚本",
        "eku": [
            ExtendedKeyUsageOID.CODE_SIGNING,
        ],
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 1095,  # 3年
        "require_san": False,
        "san_hint": "发布者URL（可选）",
    },
    CertTemplateType.SMIME: {
        "label": "邮件安全证书 (S/MIME)",
        "description": "用于邮件签名和加密",
        "eku": [
            ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ],
        "key_usage": {
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 730,
        "require_san": True,
        "san_hint": "邮箱地址 (RFC822Name)",
    },
    CertTemplateType.VPN_CLIENT: {
        "label": "VPN 客户端证书",
        "description": "用于VPN客户端认证（OpenVPN/WireGuard）",
        "eku": [
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ],
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 1095,
        "require_san": False,
        "san_hint": "VPN用户名",
    },
    CertTemplateType.DOCUMENT_SIGNING: {
        "label": "文档签名证书",
        "description": "用于PDF/Office文档数字签名",
        "eku": [
            ExtendedKeyUsageOID.CLIENT_AUTH,  # 文档签名复用clientAuth作为默认
            # 注意：cryptography库中无DOCUMENT_SIGNING OID常量，
            # 实际使用时应使用 OID 1.3.6.1.4.1.311.10.3.12
        ],
        "extra_eku_oids": ["1.3.6.1.4.1.311.10.3.12"],  # Document Signing
        "key_usage": {
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 1095,
        "require_san": False,
        "san_hint": "签署者名称",
    },
    CertTemplateType.CUSTOM: {
        "label": "自定义证书",
        "description": "完全自定义证书属性（高级用户）",
        "eku": [],
        "key_usage": {
            "digital_signature": True,
            "content_commitment": False,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        },
        "default_validity_days": 365,
        "min_validity_days": 1,
        "max_validity_days": 1825,  # 5年
        "require_san": False,
        "san_hint": "根据需求填写",
    },
}


# ============================================================
# 证书构建辅助函数
# ============================================================

def get_template(template_type):
    """
    获取指定类型的模板配置

    参数：
        template_type: CertTemplateType 枚举值 或 字符串

    返回：模板配置字典，或 None（如果不存在）
    """
    if isinstance(template_type, str):
        try:
            template_type = CertTemplateType(template_type)
        except ValueError:
            return None
    return CERT_TEMPLATES.get(template_type)


def list_templates():
    """
    获取所有可用模板的简要信息

    返回：模板列表 [{type, label, description, defaultValidityDays, ...}]
    """
    result = []
    for ttype, config in CERT_TEMPLATES.items():
        result.append({
            "type": ttype.value,
            "label": config["label"],
            "description": config["description"],
            "defaultValidityDays": config["default_validity_days"],
            "minValidityDays": config["min_validity_days"],
            "maxValidityDays": config["max_validity_days"],
            "requireSan": config["require_san"],
            "sanHint": config["san_hint"],
        })
    return result


def apply_template_to_builder(cert_builder, template_type, extra_eku_oids=None):
    """
    将证书模板应用到 CertificateBuilder

    参数：
        cert_builder: x509.CertificateBuilder 实例
        template_type: CertTemplateType 枚举值
        extra_eku_oids: 额外的OID列表（用于自定义模板）

    返回：应用了模板扩展的 CertificateBuilder
    """
    template = get_template(template_type)
    if template is None:
        raise ValueError(f"不支持的模板类型: {template_type}")

    # 添加 KeyUsage
    ku = template["key_usage"]
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=ku["digital_signature"],
            content_commitment=ku["content_commitment"],
            key_encipherment=ku["key_encipherment"],
            data_encipherment=ku["data_encipherment"],
            key_agreement=ku["key_agreement"],
            key_cert_sign=ku["key_cert_sign"],
            crl_sign=ku["crl_sign"],
            encipher_only=ku["encipher_only"],
            decipher_only=ku["decipher_only"],
        ),
        critical=True,
    )

    # 构建 EKU 列表
    eku_list = list(template.get("eku", []))

    # 添加额外的 EKU OID
    extra_oids = extra_eku_oids or template.get("extra_eku_oids", [])
    for oid_str in extra_oids:
        eku_list.append(x509.oid.ExtendedKeyUsageOID(oid_str))

    # 添加 ExtendedKeyUsage
    if eku_list:
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage(eku_list),
            critical=False,
        )

    return cert_builder


def get_default_validity(template_type):
    """
    获取模板的默认有效期（天）

    参数：
        template_type: CertTemplateType 枚举值 或 字符串

    返回：默认有效期（天）
    """
    template = get_template(template_type)
    if template:
        return template["default_validity_days"]
    return 365


def validate_template_params(template_type, validity_days=None):
    """
    验证模板参数有效性

    参数：
        template_type: 模板类型
        validity_days: 有效期（天）

    返回：(is_valid, error_message)
    """
    template = get_template(template_type)
    if template is None:
        return False, f"不支持的模板类型: {template_type}"

    if validity_days is not None:
        if validity_days < template["min_validity_days"]:
            return False, (f"证书有效期不能少于{template['min_validity_days']}天")
        if validity_days > template["max_validity_days"]:
            return False, (f"证书有效期不能超过{template['max_validity_days']}天")

    return True, ""


# ============================================================
# 兼容性：旧版统一证书模板
# ============================================================

class CertTemplate:
    """
    旧版兼容接口（供命令行模块使用）

    现在所有模板配置统一由 CERT_TEMPLATES 管理
    """
    TLS_SERVER = CertTemplateType.TLS_SERVER.value
    TLS_CLIENT = CertTemplateType.TLS_CLIENT.value
    CODE_SIGNING = CertTemplateType.CODE_SIGNING.value
    SMIME = CertTemplateType.SMIME.value
    VPN_CLIENT = CertTemplateType.VPN_CLIENT.value
    DOCUMENT_SIGNING = CertTemplateType.DOCUMENT_SIGNING.value
    TIMESTAMPING = CertTemplateType.TIMESTAMPING.value
    CUSTOM = CertTemplateType.CUSTOM.value


# ============================================================
# 独立测试
# ============================================================
if __name__ == "__main__":
    print("=== 证书模板引擎测试 ===\n")

    # 1. 列出所有模板
    print("可用模板：")
    for t in list_templates():
        print(f"  [{t['type']:20s}] {t['label']:20s} | "
              f"有效期: {t['defaultValidityDays']}天 | "
              f"SAN: {'必需' if t['requireSan'] else '可选'}")

    # 2. 验证参数
    print("\n参数验证测试：")
    for ttype in [CertTemplateType.TLS_SERVER, CertTemplateType.CODE_SIGNING]:
        valid, msg = validate_template_params(ttype, validity_days=365)
        print(f"  {ttype.value}: {'[OK]' if valid else '[FAIL]'} {msg}")
        valid, msg = validate_template_params(ttype, validity_days=9999)
        print(f"  {ttype.value}(9999天): {'[OK]' if valid else '[FAIL]'} {msg}")

    print(f"\n共 {len(CERT_TEMPLATES)} 个模板定义")
    print("[OK] 模块初始化正常")
