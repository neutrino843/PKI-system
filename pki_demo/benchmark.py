"""
PKI系统性能基准测试
测量密钥生成、证书签名/验证、HMAC、哈希性能指标
"""
import time
import statistics
import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute,
    BasicConstraints,
)
from datetime import datetime, timedelta, timezone


def bench_keygen(key_size, iterations):
    """测量RSA密钥生成时间"""
    times = []
    for i in range(iterations):
        t0 = time.perf_counter()
        key = rsa.generate_private_key(65537, key_size, default_backend())
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return times


def bench_sign_cert(iterations):
    """测量证书签名时间"""
    # 准备CA密钥和证书
    ca_key = rsa.generate_private_key(65537, 2048, default_backend())
    ca_subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo CA"),
        NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # 用户密钥
    user_key = rsa.generate_private_key(65537, 2048, default_backend())

    times = []
    for i in range(iterations):
        user_subject = Name([
            NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo User"),
            NameAttribute(NameOID.COMMON_NAME, f"User {i}"),
        ])
        t0 = time.perf_counter()
        cert = (
            CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(ca_subject)
            .public_key(user_key.public_key())
            .serial_number(100 + i)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return times


def bench_verify_cert(iterations):
    """测量证书验证时间"""
    # 准备CA密钥和证书
    ca_key = rsa.generate_private_key(65537, 2048, default_backend())
    ca_subject = issuer = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo CA"),
        NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # 生成一个用户证书
    user_key = rsa.generate_private_key(65537, 2048, default_backend())
    user_subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo User"),
        NameAttribute(NameOID.COMMON_NAME, "Bench User"),
    ])
    user_cert = (
        CertificateBuilder()
        .subject_name(user_subject)
        .issuer_name(ca_subject)
        .public_key(user_key.public_key())
        .serial_number(100)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    ca_pub_key = ca_key.public_key()

    times = []
    for i in range(iterations):
        t0 = time.perf_counter()
        ca_pub_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm,
        )
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return times


def bench_hmac(iterations):
    """测量HMAC计算时间"""
    key = b"benchmark_hmac_key_32bytes!"
    data = b"A" * 1024  # 1KB数据

    times = []
    for i in range(iterations):
        h = hmac.HMAC(key, hashes.SHA256(), default_backend())
        t0 = time.perf_counter()
        h.update(data)
        h.finalize()
        t1 = time.perf_counter()
        times.append(t1 - t0)
    return times


def bench_hash(iterations):
    """测量SHA256 vs SHA512哈希性能"""
    data = b"A" * 1024 * 1024  # 1MB数据

    # SHA256
    sha256_times = []
    dig = hashes.Hash(hashes.SHA256(), default_backend())
    for i in range(iterations):
        dig = hashes.Hash(hashes.SHA256(), default_backend())
        t0 = time.perf_counter()
        dig.update(data)
        dig.finalize()
        t1 = time.perf_counter()
        sha256_times.append(t1 - t0)

    # SHA512
    sha512_times = []
    for i in range(iterations):
        dig = hashes.Hash(hashes.SHA512(), default_backend())
        t0 = time.perf_counter()
        dig.update(data)
        dig.finalize()
        t1 = time.perf_counter()
        sha512_times.append(t1 - t0)

    return sha256_times, sha512_times


def fmt_stats(times, label, unit="ms", scale=1000):
    """格式化统计输出"""
    avg = statistics.mean(times) * scale
    med = statistics.median(times) * scale
    mn = min(times) * scale
    mx = max(times) * scale
    stdev = statistics.stdev(times) * scale if len(times) > 1 else 0
    return (
        f"  {label}: 平均={avg:.3f}{unit}, 中位数={med:.3f}{unit}, "
        f"最小={mn:.3f}{unit}, 最大={mx:.3f}{unit}, "
        f"标准差={stdev:.3f}{unit}"
    )


def main():
    lines = []
    def echo(text=""):
        print(text)
        lines.append(text)

    echo("=" * 70)
    echo("  PKI 系统性能基准测试报告")
    echo("  Python " + sys.version.split()[0] + " | cryptography " +
          __import__('cryptography').__version__)
    echo("=" * 70)
    echo()

    # === 1. RSA 2048 密钥生成 ===
    echo("[1] RSA 2048位密钥生成 (重复10次)")
    t = bench_keygen(2048, 10)
    echo(fmt_stats(t, "RSA-2048"))
    echo()

    # === 2. RSA 4096 密钥生成 ===
    echo("[2] RSA 4096位密钥生成 (重复5次)")
    t = bench_keygen(4096, 5)
    echo(fmt_stats(t, "RSA-4096"))
    echo()

    # === 3. 证书签名 ===
    echo("[3] 证书签名 (重复10次)")
    t = bench_sign_cert(10)
    echo(fmt_stats(t, "证书签名"))
    echo()

    # === 4. 证书验证 ===
    echo("[4] 证书验证 (重复10次)")
    t = bench_verify_cert(10)
    echo(fmt_stats(t, "证书验证"))
    echo()

    # === 5. HMAC计算 ===
    echo("[5] HMAC-SHA256 计算 (重复1000次, 1KB数据)")
    t = bench_hmac(1000)
    echo(fmt_stats(t, "HMAC-SHA256"))
    echo()

    # === 6. SHA256 vs SHA512 ===
    echo("[6] SHA256 vs SHA512 哈希性能对比 (重复1000次, 1MB数据)")
    sha256_t, sha512_t = bench_hash(1000)
    echo(fmt_stats(sha256_t, "SHA256", unit="ms", scale=1000))
    echo(fmt_stats(sha512_t, "SHA512", unit="ms", scale=1000))
    # 比率
    ratio = statistics.mean(sha512_t) / statistics.mean(sha256_t)
    echo(f"  SHA512/SHA256 耗时比: {ratio:.3f}x")
    echo()

    echo("=" * 70)
    echo("  测试完成。所有测试均在内存中完成，无文件系统写入。")
    echo("=" * 70)

    # 写入结果文件
    result_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "benchmark_results.txt")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n结果已保存至: {result_path}")


if __name__ == "__main__":
    main()
