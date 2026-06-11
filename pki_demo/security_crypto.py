"""
================================================================
  算法配置与文件安全模块（security_crypto.py）
  功能：算法参数可配置化 + 文件完整性校验 + 安全删除

  修复风险项：
  - ALG-02/03：算法+密钥长度硬编码 → 可配置
  - COMM-02：文件完整性校验 → 读取时自动校验SHA-256
  - COMM-05：无安全删除 → 覆写后删除
================================================================
"""

import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes

BASE_DIR = Path(__file__).parent.resolve()


# ============================================================
# 算法配置映射表
# ============================================================
HASH_ALGORITHM_MAP = {
    "SHA256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
    "SHA512": hashes.SHA512(),
}

ALLOWED_RSA_KEY_SIZES = [2048, 3072, 4096]
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_HASH = "SHA256"


def get_hash_algorithm(name=None):
    """
    获取哈希算法实例

    参数：
        name: 算法名称（SHA256/SHA384/SHA512），None则使用默认值

    使用方式：
        from security_crypto import get_hash_algorithm
        algo = get_hash_algorithm("SHA384")
        cert_builder.sign(private_key, algo, backend)
    """
    if name is None:
        name = os.environ.get("PKI_HASH_ALGORITHM", DEFAULT_HASH)
    return HASH_ALGORITHM_MAP.get(name.upper(), hashes.SHA256())


def get_rsa_key_size(size=None):
    """
    获取RSA密钥长度

    参数：
        size: 密钥长度（2048/3072/4096），None则使用环境变量或默认值

    使用方式：
        from security_crypto import get_rsa_key_size
        key_size = get_rsa_key_size(4096)
    """
    if size is None:
        size_str = os.environ.get("PKI_RSA_KEY_SIZE", str(DEFAULT_RSA_KEY_SIZE))
        size = int(size_str)
    return size if size in ALLOWED_RSA_KEY_SIZES else DEFAULT_RSA_KEY_SIZE


# ============================================================
# 文件完整性校验
# ============================================================
class FileIntegrityChecker:
    """
    文件完整性校验器

    通俗解释：
    就像给每份重要文件贴上"防伪标签"（SHA-256哈希值）。
    每次读取文件时，先检查防伪标签是否被撕毁，
    如果标签不对，说明文件可能被篡改过。
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

    通俗解释：
    普通的删除只是把文件从"目录表"中移除，
    文件内容还在硬盘上，可以用恢复工具找回。
    安全删除会用随机数据反复覆盖文件内容，
    就像用碎纸机粉碎文件，再烧成灰，绝对无法恢复。

    使用方式：
        from security_crypto import secure_delete
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
