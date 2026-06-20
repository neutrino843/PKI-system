#!/usr/bin/env python
"""
================================================================
  PKI 管理系统 - 一键开发启动脚本
  功能：检查环境、安装依赖、验证证书、启动服务
================================================================

使用方法：
  python start_dev.py

首次使用（含依赖安装）：
  python start_dev.py --install

跳过证书校验（仅开发调试）：
  python start_dev.py --skip-check

生成内部访问证书（需要已初始化 CA）：
  python start_dev.py --gen-cert

完整重置 + 初始化 + 启动：
  python start_dev.py --init
================================================================
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
PKI_DEMO_DIR = BASE_DIR / "pki_demo"

# 颜色输出
class Color:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"

def print_step(msg):
    print(f"\n{Color.CYAN}{'='*60}{Color.END}")
    print(f"{Color.BOLD}{msg}{Color.END}")
    print(f"{Color.CYAN}{'='*60}{Color.END}")

def run_cmd(cmd, cwd=None):
    print(f"{Color.YELLOW}$ {cmd}{Color.END}")
    result = subprocess.run(cmd, shell=True, cwd=cwd or str(BASE_DIR))
    return result.returncode == 0

def check_python():
    """检查 Python 版本"""
    print_step("[1/5] 检查 Python 环境")
    v = sys.version_info
    if v.major < 3 or (v.major == 3 and v.minor < 8):
        print(f"{Color.RED}❌ Python 3.8+ 是必需的，当前版本: {v.major}.{v.minor}{Color.END}")
        return False
    print(f"{Color.GREEN}✅ Python {v.major}.{v.minor}.{v.micro}{Color.END}")
    return True

def install_deps():
    """安装依赖"""
    print_step("[2/5] 安装 Python 依赖")
    if not run_cmd(f"{sys.executable} -m pip install -r requirements.txt"):
        print(f"{Color.RED}❌ 依赖安装失败{Color.END}")
        return False
    print(f"{Color.GREEN}✅ 依赖安装完成{Color.END}")
    return True

def check_ca():
    """检查 CA 是否已初始化"""
    inter_ca_cert = PKI_DEMO_DIR / "certs" / "inter_ca_cert.pem"
    inter_ca_key = PKI_DEMO_DIR / "keys" / "inter_ca_private.pem"
    return inter_ca_cert.exists() and inter_ca_key.exists()

def init_ca():
    """初始化 CA 体系"""
    print_step("[*] 初始化 CA 体系")
    if not run_cmd(f"{sys.executable} -m pki_demo.main"):
        print(f"{Color.RED}❌ CA 初始化失败{Color.END}")
        return False
    print(f"{Color.GREEN}✅ CA 初始化完成{Color.END}")
    return True

def gen_tsa_cert():
    """生成 TSA 时间戳签名证书"""
    print_step("[*] 生成 TSA 时间戳签名证书")
    if not check_ca():
        print(f"{Color.YELLOW}⚠   CA 尚未初始化，正在初始化...{Color.END}")
        if not init_ca():
            return False
    if not run_cmd(f"{sys.executable} scripts/setup_tsa_certificate.py"):
        print(f"{Color.RED}❌ TSA 证书生成失败{Color.END}")
        return False
    print(f"{Color.GREEN}✅ TSA 证书已生成{Color.END}")
    return True

def check_tsa_cert():
    """检查 TSA 证书是否已生成"""
    tsa_cert = PKI_DEMO_DIR / "certs" / "tsa_cert.pem"
    tsa_key = PKI_DEMO_DIR / "keys" / "tsa_private.pem"
    return tsa_cert.exists() and tsa_key.exists()

def gen_access_cert():
    """生成内部访问证书"""
    print_step("[*] 生成内部访问证书")
    if not check_ca():
        print(f"{Color.YELLOW}⚠   CA 尚未初始化，正在初始化...{Color.END}")
        if not init_ca():
            return False
    if not run_cmd(f"{sys.executable} scripts/gen_internal_access_cert.py"):
        print(f"{Color.RED}❌ 证书生成失败{Color.END}")
        return False
    print(f"{Color.GREEN}✅ 内部访问证书已生成，存放在 pki_demo/certs/access_cert.pem{Color.END}")
    return True

def check_access_cert():
    """检查访问证书"""
    cert_path = PKI_DEMO_DIR / "certs" / "access_cert.pem"
    if not cert_path.exists():
        print(f"{Color.YELLOW}⚠   未找到内部访问证书: {cert_path}{Color.END}")
        print(f"    请运行: python start_dev.py --gen-cert")
        print(f"    或通过管理员获取 access_cert.pem")
        return False
    return True

def start_server(skip_check=False, use_https=False, gen_ssl=False, port=None):
    """启动 Flask 服务"""
    print_step("[3/5] 启动 PKI API 服务")
    env = os.environ.copy()

    # === 开发环境默认值（仅用于本地演示！）===
    # 生产部署前请通过环境变量设置强密码
    env.setdefault("PKI_FLASK_SECRET", "DEV_ONLY_pki_demo_secret")
    env.setdefault("PKI_CA_KEY_PASSWORD", "DEV_ONLY_pki_demo_pwd")
    env.setdefault("PKI_USER_KEY_PASSWORD", "DEV_ONLY_pki_demo_pwd")
    env.setdefault("PKI_CRL_HMAC_KEY", "DEV_ONLY_change_me_in_production_32bytes!")
    env.setdefault("PKI_AUDIT_HMAC_KEY", "DEV_ONLY_change_me_in_production_32bytes!")
    env.setdefault("PKI_P12_EXPORT_PASSWORD", "DEV_ONLY_pki_demo_p12")

    if skip_check:
        env["PKI_SKIP_ACCESS_CHECK"] = "1"
        print(f"{Color.YELLOW}⚠   已跳过证书校验（--skip-check）{Color.END}")

    if port:
        env["PKI_API_PORT"] = str(port)
    elif use_https:
        env.setdefault("PKI_API_PORT", "8443")

    if use_https:
        env["PKI_USE_HTTPS"] = "1"
    if gen_ssl:
        env["PKI_GEN_SSL"] = "1"

    scheme = "https" if use_https else "http"
    display_port = port or (8443 if use_https else 8080)

    print(f"{Color.GREEN}🌐 服务地址: {scheme}://localhost:{display_port}{Color.END}")
    print(f"{Color.GREEN}🌐 前端界面: {scheme}://localhost:{display_port}/{Color.END}")
    print(f"{Color.YELLOW}按 Ctrl+C 停止服务{Color.END}")

    result = subprocess.run(
        [sys.executable, "api_server.py"],
        cwd=str(BASE_DIR),
        env=env,
    )
    return result.returncode == 0

def main():
    parser = argparse.ArgumentParser(
        description="PKI 管理系统 - 一键启动脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python start_dev.py                    # 直接启动（需已有访问证书）
  python start_dev.py --install           # 安装依赖后启动
  python start_dev.py --gen-cert          # 生成访问证书后启动
  python start_dev.py --init              # 完整初始化 + 启动
  python start_dev.py --skip-check        # 跳过证书校验（调试用）
        """,
    )
    parser.add_argument("--install", action="store_true", help="安装依赖")
    parser.add_argument("--gen-cert", action="store_true", help="生成内部访问证书")
    parser.add_argument("--init", action="store_true", help="完整初始化（含CA初始化和证书生成）")
    parser.add_argument("--skip-check", action="store_true", help="跳过证书校验（仅开发调试）")
    parser.add_argument("--no-server", action="store_true", help="不启动服务器，仅执行前置操作")
    parser.add_argument("--https", action="store_true", help="启用 HTTPS（Flask 原生 SSL）")
    parser.add_argument("--gen-ssl", action="store_true", help="重新生成 SSL 证书")
    parser.add_argument("--port", type=int, default=None, help="指定端口号")

    args = parser.parse_args()

    print(f"{Color.BOLD}{'='*60}{Color.END}")
    print(f"{Color.BOLD}  PKI 管理系统 - 启动程序{Color.END}")
    print(f"{Color.BOLD}{'='*60}{Color.END}")

    # 1. 检查 Python 版本
    if not check_python():
        sys.exit(1)

    # 2. 安装依赖
    if args.install:
        if not install_deps():
            sys.exit(1)

    # 3. 完整初始化
    if args.init:
        print_step("[*] 完整初始化模式")
        if not init_ca():
            sys.exit(1)
        if not gen_tsa_cert():
            print(f"{Color.YELLOW}⚠   TSA 证书生成警告（可稍后手动生成）{Color.END}")
        if not gen_access_cert():
            sys.exit(1)
    elif args.gen_cert:
        if not gen_access_cert():
            sys.exit(1)

    # 4. 检查访问证书
    if not args.skip_check and not args.init and not args.gen_cert:
        if not check_access_cert():
            print(f"\n{Color.YELLOW}提示: 可运行以下命令生成证书或跳过校验{Color.END}")
            print(f"  python start_dev.py --gen-cert      # 生成证书")
            print(f"  python start_dev.py --skip-check     # 跳过校验")
            if not args.no_server:
                print(f"\n尝试跳过证书校验启动...")
                args.skip_check = True

    # 5. 启动服务器
    if args.no_server:
        print(f"\n{Color.GREEN}✅ 前置操作已完成{Color.END}")
        return

    print_step("[*] 准备启动服务")
    
    # 初始化数据库
    sys.path.insert(0, str(PKI_DEMO_DIR))
    try:
        from pki_demo.database import init_database
        # 创建必要的目录
        for d in ["certs", "keys", "csr", "crl", "export", "data", "backups"]:
            (PKI_DEMO_DIR / d).mkdir(exist_ok=True)
        init_database()
        print(f"{Color.GREEN}✅ 数据库初始化完成{Color.END}")
    except Exception as e:
        print(f"{Color.YELLOW}⚠   数据库初始化警告: {e}{Color.END}")

    # 自动生成 TSA 证书（如果缺失）
    if not check_tsa_cert():
        print(f"{Color.YELLOW}⚠   未检测到 TSA 证书，自动生成中...{Color.END}")
        if check_ca():
            if not gen_tsa_cert():
                print(f"{Color.YELLOW}⚠   TSA 证书生成失败，时间戳服务暂时不可用{Color.END}")
                print(f"    可稍后运行: python scripts/setup_tsa_certificate.py")
        else:
            print(f"{Color.YELLOW}⚠   CA 未初始化，跳过 TSA 证书生成{Color.END}")
            print(f"    请先运行: python start_dev.py --init")
    else:
        print(f"{Color.GREEN}✅ TSA 证书已就绪{Color.END}")

    start_server(skip_check=args.skip_check, use_https=args.https,
                 gen_ssl=args.gen_ssl, port=args.port)


if __name__ == "__main__":
    main()
