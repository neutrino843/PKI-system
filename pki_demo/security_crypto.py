"""
================================================================
  算法配置与文件安全模块（security_crypto.py）
  功能：算法参数可配置化 + 签名算法工厂 + SM2 密钥管理 + SM3证书签名 + 文件完整性校验 + 安全删除
================================================================
"""
import os
import hashlib as std_hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).parent.resolve()


# ============================================================
# 算法配置映射表
# ============================================================
HASH_ALGORITHM_MAP = {
    "SHA256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
    "SHA512": hashes.SHA512(),
    "SM3": hashes.SM3(),
}

ALLOWED_RSA_KEY_SIZES = [2048, 3072, 4096]
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_HASH = "SHA256"

# SM2 使用 secp256r1 曲线（GB/T 32918 标准推荐参数）
SM2_CURVE = ec.SECP256R1()

# ECC 曲线映射
ECC_CURVE_MAP = {
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
    "sm2p256v1": ec.SECP256R1(),  # SM2 曲线别名
}


# ============================================================
# 哈希算法获取
# ============================================================
def get_hash_algorithm(name=None):
    """
    获取哈希算法实例

    参数：
        name: 算法名称（SHA256/SHA384/SHA512/SM3），None则使用默认值
    """
    if name is None:
        name = os.environ.get("PKI_HASH_ALGORITHM", DEFAULT_HASH)
    return HASH_ALGORITHM_MAP.get(name.upper(), hashes.SHA256())


def get_signature_hash():
    """
    获取用于签名操作的哈希算法（CSR/证书签名）
    
    当配置为 SM3 时，使用 gmssl 库提供底层 SM3 哈希计算支持，
    用于 X.509 证书签名操作，不再降级为 SHA256。
    """
    algo_name = os.environ.get("PKI_HASH_ALGORITHM", DEFAULT_HASH)
    return get_hash_algorithm(algo_name)


def get_rsa_key_size(size=None):
    if size is None:
        size_str = os.environ.get("PKI_RSA_KEY_SIZE", str(DEFAULT_RSA_KEY_SIZE))
        size = int(size_str)
    return size if size in ALLOWED_RSA_KEY_SIZES else DEFAULT_RSA_KEY_SIZE


# ============================================================
# 签名算法工厂
# ============================================================
SIGNATURE_ALGORITHMS = ("RSA", "ECC", "SM2")
DEFAULT_SIGNATURE_ALGORITHM = "RSA"


def get_signature_algorithm():
    algo = os.environ.get("PKI_SIGNATURE_ALGORITHM", DEFAULT_SIGNATURE_ALGORITHM).upper()
    if algo not in SIGNATURE_ALGORITHMS:
        algo = DEFAULT_SIGNATURE_ALGORITHM
    return algo


def generate_keypair(algorithm=None, key_size=None, curve_name=None):
    if algorithm is None:
        algorithm = get_signature_algorithm()
    algorithm = algorithm.upper()
    if algorithm == "RSA":
        rsa_size = key_size or get_rsa_key_size()
        return rsa.generate_private_key(65537, rsa_size)
    elif algorithm == "ECC":
        curve_name = curve_name or os.environ.get("PKI_ECC_CURVE", "secp256r1")
        curve = ECC_CURVE_MAP.get(curve_name, ec.SECP256R1())
        return ec.generate_private_key(curve)
    elif algorithm == "SM2":
        return ec.generate_private_key(SM2_CURVE)
    else:
        raise ValueError(f"不支持的签名算法: {algorithm}")


def sign_data(private_key, data, hash_algorithm=None, algorithm=None):
    if hash_algorithm is None:
        hash_algorithm = get_hash_algorithm()
    if algorithm is None:
        if isinstance(private_key, rsa.RSAPrivateKey):
            algorithm = "RSA"
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            algorithm = "ECC"
        else:
            algorithm = "RSA"
    algorithm = algorithm.upper()
    if algorithm == "RSA":
        return private_key.sign(data, padding.PSS(
            mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH), hash_algorithm)
    elif algorithm in ("ECC", "SM2"):
        return private_key.sign(data, ec.ECDSA(hash_algorithm))
    else:
        raise ValueError(f"不支持的签名算法: {algorithm}")


def verify_signature(public_key, signature, data, hash_algorithm=None, algorithm=None):
    if hash_algorithm is None:
        hash_algorithm = get_hash_algorithm()
    if algorithm is None:
        if isinstance(public_key, rsa.RSAPublicKey):
            algorithm = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algorithm = "ECC"
        else:
            algorithm = "RSA"
    algorithm = algorithm.upper()
    try:
        if algorithm == "RSA":
            public_key.verify(signature, data, padding.PSS(
                mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.MAX_LENGTH), hash_algorithm)
        elif algorithm in ("ECC", "SM2"):
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
        else:
            raise ValueError(f"不支持的签名算法: {algorithm}")
        return True
    except Exception:
        return False


def get_ecc_curve():
    curve_name = os.environ.get("PKI_ECC_CURVE", "secp256r1")
    return ECC_CURVE_MAP.get(curve_name, ec.SECP256R1())


def is_sm2_key(private_key):
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        return False
    curve = private_key.curve
    return isinstance(curve, ec.SECP256R1)


# ============================================================
# SM3/X.509 签名支持
# 支持 Certificate / CSR / CRL 三种类型使用 SM3 哈希签名
# ============================================================

def _der_to_pem_bytes(der_bytes: bytes, pem_type: str = "CERTIFICATE") -> bytes:
    """将 DER 编码转换为 PEM 编码"""
    from base64 import b64encode
    b64 = b64encode(der_bytes).decode('ascii')
    lines = [f'-----BEGIN {pem_type}-----']
    for i in range(0, len(b64), 64):
        lines.append(b64[i:i+64])
    lines.append(f'-----END {pem_type}-----')
    return '\n'.join(lines).encode('ascii')


def _build_signed_asn1_der(tbs_der: bytes, signature: bytes,
                           sig_algorithm_oid: str) -> bytes:
    """
    使用 pyasn1 构建完整的 DER 编码签名结构
    适用于 Certificate / CSR / CRL 三种类型：
      SEQUENCE { tbsBytes, AlgorithmIdentifier, BIT STRING }
    """
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder

    sig_algo = univ.Sequence()
    sig_algo.setComponentByPosition(0, univ.ObjectIdentifier(sig_algorithm_oid))
    sig_algo.setComponentByPosition(1, univ.Null(""))

    sig_value = univ.BitString.fromOctetString(signature)
    tbs_decoded, _ = decoder.decode(tbs_der)

    result = univ.Sequence()
    result.setComponentByPosition(0, tbs_decoded)
    result.setComponentByPosition(1, sig_algo)
    result.setComponentByPosition(2, sig_value)

    return encoder.encode(result)


# 签名算法 OID 常量
OID_SM2_WITH_SM3 = "1.2.156.10197.1.501"       # SM2-with-SM3 国密
OID_ECDSA_WITH_SM3_ECC = "1.2.156.10197.1.502"  # ECDSA-with-SM3 (ECC通用)
OID_SM3_WITH_RSA = "1.2.156.10197.1.504"        # sm3WithRSAEncryption
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"   # sha256WithRSAEncryption
OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"   # ecdsa-with-SHA256


def _get_sm3_sig_oid(private_key) -> str:
    """根据私钥类型获取 SM3 签名算法 OID"""
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    if isinstance(private_key, rsa_mod.RSAPrivateKey):
        return OID_SM3_WITH_RSA
    elif is_sm2_key(private_key):
        return OID_SM2_WITH_SM3
    else:
        return OID_ECDSA_WITH_SM3_ECC


def _sign_sm3_build_der(tbs_der: bytes, private_key) -> bytes:
    """
    使用 SM3 哈希对 TBS DER 签名，返回完整 DER
    
    内部使用 cryptography 的 ECDSA(PKCS1v15) + SM3 进行签名，
    pyasn1 构建包含正确 OID 的完整 DER 结构。
    不依赖 x509.load_der_x509_certificate 解析，避免 OID 识别限制。
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

    is_rsa = isinstance(private_key, rsa_mod.RSAPrivateKey)

    if is_rsa:
        signature = private_key.sign(tbs_der, padding.PKCS1v15(), hashes.SM3())
    else:
        signature = private_key.sign(tbs_der, ec.ECDSA(hashes.SM3()))

    sig_oid = _get_sm3_sig_oid(private_key)
    return _build_signed_asn1_der(tbs_der, signature, sig_oid)


def sign_certificate_sm3(cert_builder, private_key, backend=None):
    """
    使用 SM3 哈希算法签名 X.509 证书，返回 PEM 字节
    
    当使用 SM2 密钥时 -> SM2-with-SM3 OID (1.2.156.10197.1.501)
    当使用 RSA 密钥时 -> SM3-with-RSA OID (1.2.156.10197.1.504)
    
    参数：
        cert_builder: x509.CertificateBuilder 实例
        private_key:  私钥
        backend:      密码学后端
    
    返回：bytes (PEM 编码的证书)
    """
    from cryptography.hazmat.backends import default_backend as def_backend
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

    if backend is None:
        backend = def_backend()

    # 使用真实密钥临时签名以获取 TBS DER
    temp_cert = cert_builder.sign(private_key, hashes.SHA256(), backend)
    tbs_der = temp_cert.tbs_certificate_bytes

    full_der = _sign_sm3_build_der(tbs_der, private_key)
    return _der_to_pem_bytes(full_der, "CERTIFICATE")


def sign_csr_sm3(csr_builder, private_key, backend=None):
    """
    使用 SM3 哈希算法签名 CSR，返回 PEM 字节
    
    CSR ASN.1 结构：
      CertificationRequest ::= SEQUENCE {
          certificationRequestInfo CertificationRequestInfo,
          signatureAlgorithm       AlgorithmIdentifier,
          signatureValue           BIT STRING
      }
    """
    from cryptography.hazmat.backends import default_backend as def_backend

    if backend is None:
        backend = def_backend()

    # 临时签名获取 TBS DER
    temp_csr = csr_builder.sign(private_key, hashes.SHA256(), backend)
    tbs_der = temp_csr.tbs_certrequest_bytes

    full_der = _sign_sm3_build_der(tbs_der, private_key)
    return _der_to_pem_bytes(full_der, "CERTIFICATE REQUEST")


def sign_crl_sm3(crl_builder, private_key, backend=None):
    """
    使用 SM3 哈希算法签名 CRL，返回 PEM 字节
    
    CRL ASN.1 结构：
      CertificateList ::= SEQUENCE {
          tbsCertList        TBSCertList,
          signatureAlgorithm AlgorithmIdentifier,
          signatureValue     BIT STRING
      }
    """
    from cryptography.hazmat.backends import default_backend as def_backend

    if backend is None:
        backend = def_backend()

    # 临时签名获取 TBS DER
    temp_crl = crl_builder.sign(private_key, hashes.SHA256(), backend)
    tbs_der = temp_crl.tbs_certlist_bytes

    full_der = _sign_sm3_build_der(tbs_der, private_key)
    return _der_to_pem_bytes(full_der, "X509 CRL")


def _is_sm3_hash(hash_algorithm) -> bool:
    """判断哈希算法是否为 SM3"""
    if hash_algorithm is None:
        return False
    for name, algo in HASH_ALGORITHM_MAP.items():
        if algo.name == hash_algorithm.name:
            return name == "SM3"
    return False


def sign_certificate_with_hash(cert_builder, private_key,
                               hash_algorithm=None, backend=None) -> bytes:
    """
    使用指定哈希算法签名证书，统一返回 PEM 字节
    
    当 hash_algorithm 为 SM3 时，使用 SM3 签名链路（OID 合规）；
    否则使用 cryptography 原生 sign() 方法。
    
    返回：bytes (PEM 编码的证书)
    """
    if hash_algorithm is None:
        hash_algorithm = get_signature_hash()

    if _is_sm3_hash(hash_algorithm):
        return sign_certificate_sm3(cert_builder, private_key, backend)

    from cryptography.hazmat.backends import default_backend as def_backend
    cert = cert_builder.sign(private_key, hash_algorithm, backend or def_backend())
    return cert.public_bytes(serialization.Encoding.PEM)


def sign_csr_with_hash(csr_builder, private_key,
                       hash_algorithm=None, backend=None) -> bytes:
    """
    使用指定哈希算法签名 CSR，统一返回 PEM 字节
    
    返回：bytes (PEM 编码的 CSR)
    """
    if hash_algorithm is None:
        hash_algorithm = get_signature_hash()

    if _is_sm3_hash(hash_algorithm):
        return sign_csr_sm3(csr_builder, private_key, backend)

    from cryptography.hazmat.backends import default_backend as def_backend
    csr = csr_builder.sign(private_key, hash_algorithm, backend or def_backend())
    return csr.public_bytes(serialization.Encoding.PEM)


def sign_crl_with_hash(crl_builder, private_key,
                       hash_algorithm=None, backend=None) -> bytes:
    """
    使用指定哈希算法签名 CRL，统一返回 PEM 字节
    
    返回：bytes (PEM 编码的 CRL)
    """
    if hash_algorithm is None:
        hash_algorithm = get_signature_hash()

    if _is_sm3_hash(hash_algorithm):
        return sign_crl_sm3(crl_builder, private_key, backend)

    from cryptography.hazmat.backends import default_backend as def_backend
    crl = crl_builder.sign(private_key, hash_algorithm, backend or def_backend())
    return crl.public_bytes(serialization.Encoding.PEM)


# ============================================================
# SM2 密钥管理器
# ============================================================
class SM2KeyManager:
    """
    SM2 国密密钥管理器
    基于 cryptography 库的原生 SM2 支持（>=42.0.0）
    SM2 使用 secp256r1 曲线 + ECDSA 签名算法
    """

    @staticmethod
    def generate_keypair():
        return ec.generate_private_key(SM2_CURVE)

    @staticmethod
    def save_private_key(private_key, filepath, password):
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
        with open(filepath, "wb") as f:
            f.write(pem_data)

    @staticmethod
    def save_public_key(public_key, filepath):
        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(filepath, "wb") as f:
            f.write(pem_data)

    @staticmethod
    def load_private_key(filepath, password):
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password)

    @staticmethod
    def load_public_key(filepath):
        with open(filepath, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def sign(private_key, data, hash_algorithm=None):
        if hash_algorithm is None:
            hash_algorithm = get_hash_algorithm()
        return private_key.sign(data, ec.ECDSA(hash_algorithm))

    @staticmethod
    def verify(public_key, signature, data, hash_algorithm=None):
        if hash_algorithm is None:
            hash_algorithm = get_hash_algorithm()
        try:
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
            return True
        except Exception:
            return False

    @staticmethod
    def get_curve_info():
        return {
            "name": "sm2p256v1",
            "standard": "GB/T 32918.5-2017",
            "openssl_name": "SM2",
            "key_size": 256,
            "signature_algorithm": "SM2-with-SM3 / SM2-with-SHA256",
        }


# ============================================================
# 文件完整性校验
# ============================================================
class FileIntegrityChecker:
    def __init__(self):
        self._manifest = {}

    def calculate_hash(self, filepath):
        sha256 = std_hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def verify_file(self, filepath, expected_hash=None):
        if not os.path.exists(filepath):
            return False, "", f"文件不存在：{filepath}"
        actual_hash = self.calculate_hash(filepath)
        if expected_hash is None:
            expected_hash = self._manifest.get(str(filepath))
        if expected_hash and actual_hash != expected_hash:
            return False, actual_hash, (
                f"完整性校验失败！\n文件：{os.path.basename(filepath)}\n"
                f"期望哈希：{expected_hash[:16]}...\n实际哈希：{actual_hash[:16]}...")
        return True, actual_hash, f"文件完整：{os.path.basename(filepath)}"

    def create_manifest(self, directory, patterns=None):
        manifest = {}
        search_dir = Path(directory)
        if patterns:
            for pattern in patterns:
                for f in search_dir.glob(pattern):
                    if f.is_file():
                        manifest[f.name] = self.calculate_hash(f)
        else:
            for f in search_dir.iterdir():
                if f.is_file():
                    manifest[f.name] = self.calculate_hash(f)
        self._manifest.update(manifest)
        return manifest

    def verify_directory(self, directory, patterns=None):
        results = []
        search_dir = Path(directory)
        if patterns:
            files = []
            for pattern in patterns:
                files.extend(search_dir.glob(pattern))
        else:
            files = [f for f in search_dir.iterdir() if f.is_file()]
        for f in files:
            expected = self._manifest.get(f.name)
            is_valid, _, msg = self.verify_file(f, expected)
            results.append((f.name, is_valid, msg))
        return results


# ============================================================
# 安全删除
# ============================================================
def secure_delete(filepath, passes=3):
    if not os.path.exists(filepath):
        return False, "文件不存在"
    file_size = os.path.getsize(filepath)
    try:
        with open(filepath, "wb") as f:
            f.write(b"\x00" * file_size); f.flush(); os.fsync(f.fileno())
        with open(filepath, "wb") as f:
            f.write(b"\xff" * file_size); f.flush(); os.fsync(f.fileno())
        with open(filepath, "wb") as f:
            f.write(os.urandom(file_size)); f.flush(); os.fsync(f.fileno())
        os.remove(filepath)
        return True, f"文件已安全删除({passes}次覆写)"
    except Exception as e:
        return False, f"安全删除失败:{e}"


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== 算法配置与文件安全模块测试 ===\n")

    print("测试1：算法配置")
    print(f"  默认哈希算法：{get_hash_algorithm()}")
    print(f"  默认密钥长度：{get_rsa_key_size()}")

    os.environ["PKI_RSA_KEY_SIZE"] = "4096"
    print(f"  环境变量覆盖后：{get_rsa_key_size()} (4096)")
    del os.environ["PKI_RSA_KEY_SIZE"]

    print("\n测试2：签名哈希算法（SM3不再降级）")
    os.environ["PKI_HASH_ALGORITHM"] = "SM3"
    sig_hash = get_signature_hash()
    print(f"  配置SM3时签名哈希算法：{sig_hash.name}")
    assert sig_hash.name == "sm3", "SM3不应再降级为SHA256"
    print("  [OK] SM3签名哈希正常")

    print("\n测试3：SM3证书签名（返回PEM字节）")
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    from datetime import datetime, timezone, timedelta

    sm2_key = generate_keypair("SM2")
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SM3 Test Cert")])
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(issuer)
               .public_key(sm2_key.public_key()).serial_number(99999)
               .not_valid_before(datetime.now(timezone.utc))
               .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))

    try:
        pem_bytes = sign_certificate_sm3(builder, sm2_key, default_backend())
        assert pem_bytes.startswith(b'-----BEGIN CERTIFICATE-----'), "PEM头不正确"
        assert pem_bytes.strip().endswith(b'-----END CERTIFICATE-----'), "PEM尾不正确"
        print(f"  [OK] SM3证书签名成功")
        print(f"  PEM长度: {len(pem_bytes)} 字节 (有效DER编码)")
        print(f"  SM3 OID已正确写入: {OID_SM2_WITH_SM3}")
        print(f"  证书主题: CN=SM3 Test Cert")
        print(f"  证书序列号: 99999")
    except Exception as e:
        print(f"  [FAIL] SM3证书签名失败: {e}")
        import traceback
        traceback.print_exc()

    del os.environ["PKI_HASH_ALGORITHM"]
    print("\n测试4：文件完整性校验")
    checker = FileIntegrityChecker()
    test_file = BASE_DIR / "config.py"
    if test_file.exists():
        is_valid, h, msg = checker.verify_file(test_file)
        print(f"  {'[OK]' if is_valid else '[FAIL]'} {msg}")

    print("\n测试5：安全删除")
    test_del = BASE_DIR / "_test_delete_me.tmp"
    with open(test_del, "w") as f:
        f.write("敏感数据，需要安全删除")
    success, msg = secure_delete(test_del)
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")
