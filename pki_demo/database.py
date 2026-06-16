"""
================================================================
  数据库持久化层（database.py）
  功能：使用SQLite替换JSON文件存储，提供事务保护和并发安全
  修复：P0-1 JSON文件存储 → 关系型数据库（解决并发写丢失、数据损坏问题）
================================================================
"""

import os
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "data" / "pki.db"

# 线程本地存储（每个线程独立连接）
_local = threading.local()


def get_connection():
    """获取当前线程的数据库连接（自动创建若不存在）"""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = _create_connection()
    return _local.conn


def _create_connection():
    """创建数据库连接（启用WAL模式 + 外键约束）"""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def transaction():
    """事务上下文管理器（自动提交/回滚）"""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def close_connection():
    """关闭当前线程的数据库连接"""
    if hasattr(_local, "conn") and _local.conn:
        _local.conn.close()
        _local.conn = None


# ============================================================
# 数据库初始化与迁移
# ============================================================

def init_database():
    """初始化数据库：创建表结构并迁移旧数据"""
    with transaction() as conn:
        _create_tables(conn)
    _migrate_from_json()


def _create_tables(conn):
    """创建所有数据库表"""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username    TEXT PRIMARY KEY,
            password    TEXT NOT NULL,
            name        TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'end_user',
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL,
            updated_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL UNIQUE,
            username        TEXT NOT NULL,
            user_info_json  TEXT NOT NULL,
            login_time      REAL NOT NULL,
            last_access     REAL NOT NULL,
            created_at      TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(session_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

        CREATE TABLE IF NOT EXISTS pending_csr (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            csr_id          TEXT NOT NULL UNIQUE,
            username        TEXT NOT NULL,
            org             TEXT NOT NULL,
            csr_filepath    TEXT NOT NULL,
            applicant       TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            submitted_at    TEXT NOT NULL,
            reviewer_1      TEXT,
            reviewed_at_1   TEXT,
            approved_by     TEXT,
            approved_at     TEXT,
            rejected_by     TEXT,
            rejected_at     TEXT,
            reject_reason   TEXT,
            audit_history   TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_csr(status);
        CREATE INDEX IF NOT EXISTS idx_pending_applicant ON pending_csr(applicant);

        CREATE TABLE IF NOT EXISTS approved_csr (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            csr_id          TEXT NOT NULL UNIQUE,
            username        TEXT NOT NULL,
            org             TEXT NOT NULL,
            csr_filepath    TEXT NOT NULL,
            applicant       TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'approved',
            submitted_at    TEXT NOT NULL,
            reviewer_1      TEXT,
            reviewed_at_1   TEXT,
            approved_by     TEXT,
            approved_at     TEXT,
            issued_at       TEXT,
            audit_history   TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_approved_status ON approved_csr(status);

        CREATE TABLE IF NOT EXISTS crl_revoked (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            serial          TEXT NOT NULL,
            name            TEXT NOT NULL,
            reason          TEXT NOT NULL DEFAULT 'unspecified',
            reason_desc     TEXT NOT NULL DEFAULT '',
            revoked_at      TEXT NOT NULL,
            created_at      TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_serial ON crl_revoked(serial);

        -- TSA 时间戳记录表
        CREATE TABLE IF NOT EXISTS tst_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number   TEXT NOT NULL UNIQUE,
            hash_algorithm  TEXT NOT NULL,
            hash_value      TEXT NOT NULL,
            gen_time        TEXT NOT NULL,
            policy_oid      TEXT,
            nonce           INTEGER,
            tst_info_hex    TEXT NOT NULL,
            tst_token_hex   TEXT NOT NULL,
            client_ip       TEXT,
            requester       TEXT,
            status          TEXT NOT NULL DEFAULT 'granted',
            created_at      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_tst_serial ON tst_records(serial_number);
        CREATE INDEX IF NOT EXISTS idx_tst_gen_time ON tst_records(gen_time);
        CREATE INDEX IF NOT EXISTS idx_tst_requester ON tst_records(requester);

        -- TSA 业务场景记录表
        CREATE TABLE IF NOT EXISTS tsa_scenarios (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_type   TEXT NOT NULL,
            tst_serial      TEXT NOT NULL,
            biz_id          TEXT NOT NULL,
            biz_desc        TEXT,
            hash_value      TEXT,
            created_by      TEXT,
            created_at      TEXT NOT NULL,
            FOREIGN KEY (tst_serial) REFERENCES tst_records(serial_number)
        );

        CREATE INDEX IF NOT EXISTS idx_scenario_type ON tsa_scenarios(scenario_type);
        CREATE INDEX IF NOT EXISTS idx_scenario_biz ON tsa_scenarios(biz_id);

        -- TSA 速率限制与安全日志表
        CREATE TABLE IF NOT EXISTS tsa_security_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type      TEXT NOT NULL,
            client_ip       TEXT,
            detail          TEXT,
            created_at      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_tsa_security_time ON tsa_security_events(created_at);
    """)


def _migrate_from_json():
    """从旧JSON文件迁移数据到数据库（幂等：已迁移则跳过）"""
    from config import CFG

    # 检查是否已有数据
    with transaction() as conn:
        row = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
        if row["cnt"] > 0:
            return  # 已迁移，跳过

    # === 迁移 users.json ===
    users_file = BASE_DIR / "data" / "users.json"
    if users_file.exists():
        try:
            with open(users_file, "r", encoding="utf-8") as f:
                users_data = json.load(f)
            with transaction() as conn:
                for username, info in users_data.items():
                    conn.execute(
                        """INSERT OR IGNORE INTO users
                           (username, password, name, role, is_active, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            username,
                            info.get("password", ""),
                            info.get("name", username),
                            info.get("role", "end_user"),
                            1 if info.get("is_active", True) else 0,
                            info.get("created_at", datetime.now(timezone.utc).isoformat()),
                            info.get("updated_at"),
                        )
                    )
            print("[迁移] users.json → 数据库 (完成)")
        except Exception as e:
            print(f"[迁移] users.json 迁移失败: {e}")

    # === 迁移 pending_csr.json ===
    pending_file = BASE_DIR / "data" / "pending_csr.json"
    if pending_file.exists():
        try:
            with open(pending_file, "r", encoding="utf-8") as f:
                pending_data = json.load(f)
            with transaction() as conn:
                for item in pending_data:
                    conn.execute(
                        """INSERT OR IGNORE INTO pending_csr
                           (csr_id, username, org, csr_filepath, applicant, status,
                            submitted_at, reviewer_1, reviewed_at_1,
                            approved_by, approved_at,
                            rejected_by, rejected_at, reject_reason, audit_history)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            item["csr_id"],
                            item.get("username", ""),
                            item.get("org", ""),
                            item.get("csr_filepath", ""),
                            item.get("applicant", ""),
                            item.get("status", "pending"),
                            item.get("submitted_at", ""),
                            item.get("reviewer_1"),
                            item.get("reviewed_at_1"),
                            item.get("approved_by"),
                            item.get("approved_at"),
                            item.get("rejected_by"),
                            item.get("rejected_at"),
                            item.get("reject_reason"),
                            json.dumps(item.get("audit_history", []), ensure_ascii=False),
                        )
                    )
            print("[迁移] pending_csr.json → 数据库 (完成)")
        except Exception as e:
            print(f"[迁移] pending_csr.json 迁移失败: {e}")

    # === 迁移 approved_csr.json ===
    approved_file = BASE_DIR / "data" / "approved_csr.json"
    if approved_file.exists():
        try:
            with open(approved_file, "r", encoding="utf-8") as f:
                approved_data = json.load(f)
            with transaction() as conn:
                for item in approved_data:
                    conn.execute(
                        """INSERT OR IGNORE INTO approved_csr
                           (csr_id, username, org, csr_filepath, applicant, status,
                            submitted_at, reviewer_1, reviewed_at_1,
                            approved_by, approved_at, issued_at, audit_history)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            item["csr_id"],
                            item.get("username", ""),
                            item.get("org", ""),
                            item.get("csr_filepath", ""),
                            item.get("applicant", ""),
                            item.get("status", "approved"),
                            item.get("submitted_at", ""),
                            item.get("reviewer_1"),
                            item.get("reviewed_at_1"),
                            item.get("approved_by"),
                            item.get("approved_at"),
                            item.get("issued_at"),
                            json.dumps(item.get("audit_history", []), ensure_ascii=False),
                        )
                    )
            print("[迁移] approved_csr.json → 数据库 (完成)")
        except Exception as e:
            print(f"[迁移] approved_csr.json 迁移失败: {e}")

    # === 迁移 CRL 数据 ===
    crl_file = BASE_DIR / "crl" / "revoked_certs_secure.json"
    if crl_file.exists():
        try:
            with open(crl_file, "r", encoding="utf-8") as f:
                container = json.load(f)
            revoked_list = container.get("data", [])
            with transaction() as conn:
                for item in revoked_list:
                    conn.execute(
                        """INSERT OR IGNORE INTO crl_revoked
                           (serial, name, reason, reason_desc, revoked_at, created_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            item.get("serial", ""),
                            item.get("name", ""),
                            item.get("reason", "unspecified"),
                            item.get("reason_desc", ""),
                            item.get("revoked_at", ""),
                            datetime.now(timezone.utc).isoformat(),
                        )
                    )
            print(f"[迁移] revoked_certs_secure.json → 数据库 ({len(revoked_list)}条)")
        except Exception as e:
            print(f"[迁移] CRL数据迁移失败: {e}")


# ============================================================
# 数据库健康检查
# ============================================================

def verify_database():
    """验证数据库完整性"""
    try:
        with transaction() as conn:
            conn.execute("PRAGMA integrity_check;")
        return True, "数据库完整性校验通过"
    except Exception as e:
        return False, f"数据库异常: {e}"


# ============================================================
# 独立运行测试
# ============================================================
if __name__ == "__main__":
    print("=== 数据库持久化层测试 ===\n")
    init_database()
    valid, msg = verify_database()
    print(f"  数据库初始化: {'[OK]' if valid else '[FAIL]'} {msg}")

    with transaction() as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        print(f"\n  已创建的表:")
        for t in tables:
            count = conn.execute(f"SELECT COUNT(*) as cnt FROM [{t['name']}]").fetchone()
            print(f"    - {t['name']}: {count['cnt']} 条记录")
