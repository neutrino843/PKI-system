"""
================================================================
  算法配置与文件安全模块（security_crypto.py）
  功能：算法参数可配置化 + 签名算法工厂 + SM2 密钥管理 + 文件完整性校验 + 安全删除
================================================================
"""

import os
import hashlib
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

    使用方式：
        from .security_crypto import get_hash_algorithm
        algo = get_hash_algorithm("SHA384")
        cert_builder.sign(private_key, algo, backend)
    """
    if name is None:
        name = os.environ.get("PKI_HASH_ALGORITHM", DEFAULT_HASH)
    return HASH_ALGORITHM_MAP.get(name.upper(), hashes.SHA256())


def get_signature_hash():
    """
    获取用于签名操作的哈希算法（CSR/证书签名）
    
    注意：cryptography 库不支持 SM3 用于 CSR/证书签名，
    当配置为 SM3 时自动降级为 SHA256。
    文档/业务数据的哈希不受影响（TSA 等仍可使用 SM3）。
    """
    algo_name = os.environ.get("PKI_HASH_ALGORITHM", DEFAULT_HASH)
    if algo_name.upper() == "SM3":
        return hashes.SHA256()
    return get_hash_algorithm(algo_name)


def get_rsa_key_size(size=None):
    """
    获取RSA密钥长度
    """
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
    """
    从环境变量或配置获取签名算法类型

    环境变量: PKI_SIGNATURE_ALGORITHM (RSA/ECC/SM2)
    默认值: RSA
    """
    algo = os.environ.get("PKI_SIGNATURE_ALGORITHM", DEFAULT_SIGNATURE_ALGORITHM).upper()
    if algo not in SIGNATURE_ALGORITHMS:
        algo = DEFAULT_SIGNATURE_ALGORITHM
    return algo


def generate_keypair(algorithm=None, key_size=None, curve_name=None):
    """
    根据签名算法生成密钥对（工厂方法）

    参数：
        algorithm: RSA / ECC / SM2，None 则从环境变量读取
        key_size: RSA 密钥长度（仅 RSA 算法有效）
        curve_name: EC 曲线名称（仅 ECC/SM2 算法有效）

    返回：private_key 对象
    """
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
        # SM2 使用固定的 secp256r1 曲线（国密标准）
        return ec.generate_private_key(SM2_CURVE)

    else:
        raise ValueError(f"不支持的签名算法: {algorithm}")


def sign_data(private_key, data, hash_algorithm=None, algorithm=None):
    """
    使用私钥对数据进行签名（算法无关）

    参数：
        private_key: 私钥对象
        data: 要签名的数据（bytes）
        hash_algorithm: 哈希算法实例，None 则使用默认
        algorithm: RSA/ECC/SM2，None 则自动推断

    返回：签名值（bytes）
    """
    if hash_algorithm is None:
        hash_algorithm = get_hash_algorithm()

    # 自动推断算法类型
    if algorithm is None:
        if isinstance(private_key, rsa.RSAPrivateKey):
            algorithm = "RSA"
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            algorithm = "ECC"  # SM2 也是 ECC 子类
        else:
            algorithm = "RSA"

    algorithm = algorithm.upper()

    if algorithm == "RSA":
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hash_algorithm,
        )
    elif algorithm in ("ECC", "SM2"):
        return private_key.sign(data, ec.ECDSA(hash_algorithm))
    else:
        raise ValueError(f"不支持的签名算法: {algorithm}")


def verify_signature(public_key, signature, data, hash_algorithm=None, algorithm=None):
    """
    使用公钥验证签名（算法无关）

    参数：
        public_key: 公钥对象
        signature: 签名值
        data: 原始数据
        hash_algorithm: 哈希算法实例
        algorithm: RSA/ECC/SM2，None 则自动推断

    返回：True/False
    """
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
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hash_algorithm,
            )
        elif algorithm in ("ECC", "SM2"):
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
        else:
            raise ValueError(f"不支持的签名算法: {algorithm}")
        return True
    except Exception:
        return False


def get_ecc_curve():
    """获取 ECC 曲线配置"""
    curve_name = os.environ.get("PKI_ECC_CURVE", "secp256r1")
    return ECC_CURVE_MAP.get(curve_name, ec.SECP256R1())


def is_sm2_key(private_key):
    """判断私钥是否是 SM2 密钥"""
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        return False
    curve = private_key.curve
    # SM2 使用 secp256r1 曲线
    return isinstance(curve, ec.SECP256R1)


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
        """生成 SM2 密钥对"""
        return ec.generate_private_key(SM2_CURVE)

    @staticmethod
    def save_private_key(private_key, filepath, password):
        """
        加密保存 SM2 私钥（PKCS#8 格式）

        参数：
            private_key: 私钥对象
            filepath: 保存路径
            password: 加密密码（bytes）
        """
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
        with open(filepath, "wb") as f:
            f.write(pem_data)

    @staticmethod
    def save_public_key(public_key, filepath):
        """
        保存 SM2 公钥（SubjectPublicKeyInfo 格式）
        """
        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(filepath, "wb") as f:
            f.write(pem_data)

    @staticmethod
    def load_private_key(filepath, password):
        """
        加载加密的 SM2 私钥
        """
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password)

    @staticmethod
    def load_public_key(filepath):
        """
        加载 SM2 公钥
        """
        with open(filepath, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def sign(private_key, data, hash_algorithm=None):
        """
        SM2 签名（使用 ECDSA + 指定哈希算法）
        """
        if hash_algorithm is None:
            hash_algorithm = get_hash_algorithm()
        return private_key.sign(data, ec.ECDSA(hash_algorithm))

    @staticmethod
    def verify(public_key, signature, data, hash_algorithm=None):
        """
        SM2 验签
        """
        if hash_algorithm is None:
            hash_algorithm = get_hash_algorithm()
        try:
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
            return True
        except Exception:
            return False

    @staticmethod
    def get_curve_info():
        """获取 SM2 曲线信息"""
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
    """
    文件完整性校验器
    """

    def __init__(self):
        self._manifest = {}

    def calculate_hash(self, filepath):
        """
        计算文件的SHA-256哈希值

        返回：十六进制哈希字符串
        """
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def verify_file(self, filepath, expected_hash=None):
        """
        验证单个文件的完整性

        参数：
            filepath: 文件路径
            expected_hash: 预期的哈希值，None则从清单中查找

        返回：(is_valid, actual_hash, message)
        """
        if not os.path.exists(filepath):
            return False, "", f"文件不存在：{filepath}"

        actual_hash = self.calculate_hash(filepath)

        if expected_hash is None:
            expected_hash = self._manifest.get(str(filepath))

        if expected_hash and actual_hash != expected_hash:
            return False, actual_hash, (
                f"完整性校验失败！\n"
                f"  文件：{os.path.basename(filepath)}\n"
                f"  期望哈希：{expected_hash[:16]}...\n"
                f"  实际哈希：{actual_hash[:16]}..."
            )

        return True, actual_hash, f"文件完整：{os.path.basename(filepath)}"

    def create_manifest(self, directory, patterns=None):
        """
        为目录中的文件创建完整性清单

        参数：
            directory: 目录路径
            patterns: 文件匹配模式列表

        返回：{文件名: 哈希值} 字典
        """
        import glob as glob_module

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
        """
        验证目录中所有文件的完整性

        返回：[(文件名, 是否完整, 信息)]
        """
        results = []
        search_dir = Path(directory)

        if patterns:
            import glob as glob_module
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
    """
    安全删除文件——覆写后删除，防止数据恢复

    参数：
        filepath: 要删除的文件路径
        passes: 覆写次数（默认3次，满足大多数安全要求）

    使用方式：
        from .security_crypto import secure_delete
        secure_delete("sensitive_file.pem")
    """
    if not os.path.exists(filepath):
        return False, "文件不存在"

    file_size = os.path.getsize(filepath)

    try:
        # 第1次：全0覆写
        with open(filepath, "wb") as f:
            f.write(b"\x00" * file_size)
            f.flush()
            os.fsync(f.fileno())

        # 第2次：全1覆写
        with open(filepath, "wb") as f:
            f.write(b"\xff" * file_size)
            f.flush()
            os.fsync(f.fileno())

        # 第3次：随机数据覆写
        with open(filepath, "wb") as f:
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())

        # 最后删除文件
        os.remove(filepath)
        return True, f"文件已安全删除({passes}次覆写)"

    except Exception as e:
        return False, f"安全删除失败:{e}"


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== 算法配置与文件安全模块测试 ===\n")

    # 测试1：算法配置
    print("测试1：算法配置")
    print(f"  默认哈希算法：{get_hash_algorithm()}")
    print(f"  默认密钥长度：{get_rsa_key_size()}")

    # 测试环境变量覆盖
    os.environ["PKI_RSA_KEY_SIZE"] = "4096"
    print(f"  环境变量覆盖后：{get_rsa_key_size()} (4096)")
    del os.environ["PKI_RSA_KEY_SIZE"]

    # 测试2：文件完整性
    print("\n测试2：文件完整性校验")
    checker = FileIntegrityChecker()

    test_file = BASE_DIR / "config.py"
    if test_file.exists():
        is_valid, h, msg = checker.verify_file(test_file)
        print(f"  {'[OK]' if is_valid else '[FAIL]'} {msg}")

    # 测试3：安全删除（创建临时文件测试）
    print("\n测试3：安全删除（创建临时文件测试）")
    test_del = BASE_DIR / "_test_delete_me.tmp"
    with open(test_del, "w") as f:
        f.write("这是一份敏感数据，需要安全删除")
    success, msg = secure_delete(test_del)
    print(f"  {'[OK]' if success else '[FAIL]'} {msg}")
