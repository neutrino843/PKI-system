#!/bin/bash
# 根CA信任安装脚本 — Linux
# 用途：将PKI系统的根CA证书安装到Linux系统的信任存储
# 适用发行版：Debian/Ubuntu/CentOS/RHEL
# 调度：新服务器部署时执行一次
# 用法：sudo ./trust_root_ca.sh [PKI_URL]

set -e

PKI_URL="${1:-http://pki.internal:8080}"
CA_CERT_DIR="/usr/local/share/ca-certificates"
CA_FILE="${CA_CERT_DIR}/pki-root-ca.crt"

echo "=== PKI根CA证书信任安装 ==="

# 步骤1：下载根CA证书
echo "[1/3] 下载根CA证书..."
curl -sS -o "${CA_FILE}" "${PKI_URL}/api/ca-certificate"
if [ ! -s "${CA_FILE}" ]; then
    echo "[FAIL] 下载失败"
    exit 1
fi
echo "      完成"

# 步骤2：验证证书格式
echo "[2/3] 验证证书格式..."
if ! openssl x509 -in "${CA_FILE}" -noout -subject > /dev/null 2>&1; then
    echo "[FAIL] 证书格式无效"
    rm -f "${CA_FILE}"
    exit 1
fi
SUBJECT=$(openssl x509 -in "${CA_FILE}" -noout -subject)
echo "      证书主题: ${SUBJECT}"

# 步骤3：更新系统信任存储
echo "[3/3] 更新系统信任存储..."
if command -v update-ca-certificates &> /dev/null; then
    # Debian/Ubuntu
    update-ca-certificates
elif command -v update-ca-trust &> /dev/null; then
    # CentOS/RHEL 7+
    update-ca-trust extract
else
    echo "[FAIL] 不支持的Linux发行版"
    exit 1
fi

echo ""
echo "=== 安装成功! ==="
echo "根CA证书已安装到系统信任存储。"
echo ""
echo "验证方法:"
echo "  openssl verify -CAfile ${CA_FILE} /path/to/server_cert.pem"
