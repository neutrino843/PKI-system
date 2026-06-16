import os
import shutil
import tarfile
import json
import secrets
import io
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BASE_DIR = Path(__file__).parent.resolve()
BACKUP_DIR = BASE_DIR / "backups"

# 需要备份的目录和文件列表
BACKUP_ITEMS = [
    "certs",
    "keys",
    "csr",
    "crl",
    "data",
    "config.py",
]


def _safe_extract(tar, target_path):
    """
    安全解压tar文件，防止路径穿越攻击
    """
    target_path = Path(target_path).resolve()
    for member in tar.getmembers():
        # 规范化路径
        member_path = target_path / member.name
        # 验证路径是否在目标目录内（防止路径穿越）
        try:
            member_path.relative_to(target_path)
        except ValueError:
            raise SecurityError(
                f"安全错误：备份文件包含危险的路径 '{member.name}'，已拒绝提取"
            )
        # 拒绝包含 .. 的路径
        if ".." in member.name.split("/"):
            raise SecurityError(
                f"安全错误：备份文件包含路径穿越 '{member.name}'，已拒绝提取"
            )
    tar.extractall(path=target_path)


class SecurityError(Exception):
    """安全错误异常"""
    pass

class BackupManager:
    """备份管理器（含AES-GCM加密）"""

    ENCRYPT_KEY_ENV = "PKI_BACKUP_KEY"

    def __init__(self):
        BACKUP_DIR.mkdir(exist_ok=True)

    def _get_encryption_key(self):
        """获取备份加密密钥"""
        key_hex = os.environ.get(self.ENCRYPT_KEY_ENV)
        if not key_hex:
            raise RuntimeError(
                f"备份加密密钥未设置，请设置环境变量 {self.ENCRYPT_KEY_ENV}\n"
                f"可通过命令生成: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            raise RuntimeError(f"备份加密密钥必须为64位十六进制字符串(32字节)，当前长度: {len(key)}")
        return key

    def _encrypt_data(self, data):
        """使用AES-256-GCM加密数据"""
        key = self._get_encryption_key()
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        # 返回 nonce + tag + ciphertext
        return nonce + encryptor.tag + ciphertext

    def _decrypt_data(self, encrypted_data):
        """解密AES-256-GCM加密的数据"""
        key = self._get_encryption_key()
        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def create_backup(self, label=""):
        """创建完整备份（AES-256-GCM加密）"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = f"_{label}" if label else ""
        backup_name = f"pki_backup_{timestamp}{suffix}.enc"
        backup_path = BACKUP_DIR / backup_name

        # 先将备份内容打包到内存中的tar.gz
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for item in BACKUP_ITEMS:
                src = BASE_DIR / item
                if src.exists():
                    tar.add(src, arcname=item)
        raw_data = buf.getvalue()

        # AES-256-GCM加密
        encrypted_data = self._encrypt_data(raw_data)
        with open(backup_path, "wb") as f:
            f.write(encrypted_data)

        # 保存备份清单
        manifest = {
            "backup_file": backup_name,
            "created_at": timestamp,
            "label": label,
            "items": BACKUP_ITEMS,
            "encryption": "AES-256-GCM",
            "size_bytes": len(encrypted_data),
            "size_raw_bytes": len(raw_data),
        }
        manifest_path = BACKUP_DIR / f"manifest_{timestamp}.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        return backup_name

    def list_backups(self):
        """列出所有备份"""
        if not BACKUP_DIR.exists():
            return []

        backups = []
        for f in sorted(BACKUP_DIR.glob("pki_backup_*.enc"), reverse=True):
            backups.append({
                "file": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return backups

    def restore_backup(self, backup_name):
        """恢复备份（解密 + 安全路径校验）"""
        backup_path = BACKUP_DIR / backup_name
        if not backup_path.exists():
            return False, f"备份文件不存在: {backup_name}"

        try:
            # 读取并解密
            with open(backup_path, "rb") as f:
                encrypted_data = f.read()
            raw_data = self._decrypt_data(encrypted_data)

            # 解压到临时内存tar
            buf = io.BytesIO(raw_data)
            with tarfile.open(fileobj=buf, mode="r:gz") as tar:
                _safe_extract(tar, BASE_DIR)

            return True, f"已从 {backup_name} 解密恢复"
        except Exception as e:
            return False, f"恢复失败: {e}"
