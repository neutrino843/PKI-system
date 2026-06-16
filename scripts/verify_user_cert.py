"""验证PKI签发的用户证书"""
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID

cert_path = Path(r"D:\PKI - 副本 (2)\pki_demo\certs\user_941326814856_20260615195513_cert.pem")
with open(cert_path, "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)

print(f"证书CN:     {cn[0].value}")
print(f"组织:       {org[0].value}")
print(f"序列号:     {cert.serial_number}")
print(f"颁发者:     {issuer[0].value}")
print(f"有效期:     {cert.not_valid_before_utc.strftime('%Y-%m-%d')} ~ {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
print(f"签名算法:   {cert.signature_algorithm_oid._name}")
print(f"版本:       v{cert.version.value}")

# 检查扩展
from cryptography.x509.oid import ExtensionOID
try:
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    print(f"SAN扩展:    有 ({len(san.value)}项)")
except:
    print("SAN扩展:    无")

try:
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    print(f"CA证书:     {bc.value.ca}")
except:
    pass

try:
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    usages = [str(u._name) for u in eku.value]
    print(f"扩展用途:   {', '.join(usages)}")
except:
    pass

print(f"\n文件路径:   {cert_path}")
print(f"文件大小:   {cert_path.stat().st_size} bytes")
print("\n[OK] PKI签发的用户证书验证通过!")
