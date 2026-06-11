"""
备份恢复模块 (backup.py)
功能：备份PKI系统的证书、密钥、配置数据，支持定时打包和恢复

优化项：FIX-05（无数据备份 -> 自动备份）
"""

import os
import shutil
import tarfile
import json
from datetime import datetime, timedelta
from pathlib import Path

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

class BackupManager:
    """备份管理器"""

    def __init__(self):
        BACKUP_DIR.mkdir(exist_ok=True)

    def create_backup(self, label=""):
        """创建完整备份"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = f"_{label}" if label else ""
        backup_name = f"pki_backup_{timestamp}{suffix}.tar.gz"
        backup_path = BACKUP_DIR / backup_name

        with tarfile.open(backup_path, "w:gz") as tar:
            for item in BACKUP_ITEMS:
                src = BASE_DIR / item
                if src.exists():
                    tar.add(src, arcname=item)

        # 保存备份清单
        manifest = {
            "backup_file": backup_name,
            "created_at": timestamp,
            "label": label,
            "items": BACKUP_ITEMS,
            "size_bytes": backup_path.stat().st_size,
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
        for f in sorted(BACKUP_DIR.glob("pki_backup_*.tar.gz"), reverse=True):
            backups.append({
                "file": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return backups

    def restore_backup(self, backup_name):
        """恢复备份"""
        backup_path = BACKUP_DIR / backup_name
        if not backup_path.exists():
            return False, f"备份文件不存在: {backup_name}"

        with tarfile.open(backup_path, "r:gz") as tar:
            tar.extractall(path=BASE_DIR)

        return True, f"已从 {backup_name} 恢复"
