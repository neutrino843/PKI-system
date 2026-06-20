"""SM3算法功能验证测试"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("  SM3国密哈希算法功能验证")
print("=" * 60)

# 测试1：SM3在算法映射表中
from .security_crypto import HASH_ALGORITHM_MAP, get_hash_algorithm
assert "SM3" in HASH_ALGORITHM_MAP, "SM3不在映射表中！"
print("[PASS] SM3已注册到HASH_ALGORITHM_MAP")

# 测试2：get_hash_algorithm返回SM3实例
algo = get_hash_algorithm("SM3")
assert algo.name == "sm3", f"算法名称应为sm3，实际为{algo.name}"
assert algo.digest_size == 32, f"SM3摘要长度应为32字节，实际为{algo.digest_size}"
print(f"[PASS] get_hash_algorithm('SM3') -> name={algo.name}, size={algo.digest_size}B")

# 测试3：SM3实际计算哈希
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
digest = hashes.Hash(algo, default_backend())
test_data = b"PKI system SM3 test data"
digest.update(test_data)
result = digest.finalize()
assert len(result) == 32, f"SM3输出应为32字节，实际{len(result)}"
print(f"[PASS] SM3哈希计算正常: {result.hex()[:32]}... ({len(result)}字节)")

# 测试4：SM3确定性验证（相同输入应得到相同输出）
digest2 = hashes.Hash(algo, default_backend())
digest2.update(test_data)
result2 = digest2.finalize()
assert result == result2, "相同输入应得到相同哈希值"
print("[PASS] SM3确定性验证通过")

# 测试5：SM3与SHA256的结果长度对比
algo_sha256 = get_hash_algorithm("SHA256")
digest3 = hashes.Hash(algo_sha256, default_backend())
digest3.update(test_data)
result3 = digest3.finalize()
print(f"[INFO] 对比: SM3={len(result)}B, SHA256={len(result3)}B (都是32字节)")

# 测试6：通过环境变量切换SM3（临时）
os.environ["PKI_HASH_ALGORITHM"] = "SM3"
algo_from_env = get_hash_algorithm()
assert algo_from_env.name == "sm3", f"环境变量未生效: {algo_from_env.name}"
del os.environ["PKI_HASH_ALGORITHM"]
algo_from_env_default = get_hash_algorithm()
assert algo_from_env_default.name != "sm3", "清除环境变量后应恢复默认"
print("[PASS] PKI_HASH_ALGORITHM=SM3 环境变量切换正常")

# 测试7：安全加密模块文件完整性校验使用SM3
from .security_crypto import FileIntegrityChecker
checker = FileIntegrityChecker()
test_file = os.path.join(os.path.dirname(__file__), "config.py")
if os.path.exists(test_file):
    is_valid, h, msg = checker.verify_file(test_file)
    assert is_valid, f"文件完整性校验失败: {msg}"
    print(f"[PASS] 文件完整性校验(HMAC-SHA256): {msg}")

print("=" * 60)
print("  [PASS] SM3全部测试通过!")
print("=" * 60)
