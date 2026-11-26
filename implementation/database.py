"""
Innovative Hybrid Cryptographic File Protection and Integrity Verification
Database Layer: SQLite Database for Users, Secure Transfers, and Audit Logs
"""

import os
import sqlite3
import hashlib
import binascii
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import crypto_engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
DB_PATH = os.path.join(STORAGE_DIR, "crypto_vault.db")
FILES_DIR = os.path.join(STORAGE_DIR, "files")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dict-like row factory and WAL mode for concurrency."""
    os.makedirs(STORAGE_DIR, exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def hash_password_sha256(password: str, salt_bytes: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Hashes password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (hex_hash, hex_salt).
    """
    if salt_bytes is None:
        salt_bytes = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        100000
    )
    return binascii.hexlify(pwd_hash).decode('utf-8'), binascii.hexlify(salt_bytes).decode('utf-8')


def verify_password_sha256(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    """Verifies provided password against stored PBKDF2-HMAC-SHA256 hash."""
    salt_bytes = binascii.unhexlify(stored_salt.encode('utf-8'))
    computed_hash, _ = hash_password_sha256(provided_password, salt_bytes)
    return computed_hash == stored_hash


def init_db():
    """
    Initializes SQLite database schema, performs automatic column migrations,
    and seeds initial demo users if empty.
    """
    os.makedirs(STORAGE_DIR, exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Table 1: Users (Authentication & Key Management)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                rsa_public_key TEXT NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Table 2: User Stored Files (Personal Vault)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                encryption_status TEXT DEFAULT 'Plaintext',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Table 3: Secure Transfers
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                original_filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                package_json TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)

        # Table 4: Audit Logs (Security Monitoring)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                module TEXT DEFAULT 'Security',
                details TEXT,
                status TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # --- Automatic Schema Migrations (Fixes Missing Columns in Existing DBs) ---
        # 1. Ensure 'updated_at' exists in transfers
        cursor.execute("PRAGMA table_info(transfers)")
        t_cols = [r[1] for r in cursor.fetchall()]
        if "updated_at" not in t_cols:
            cursor.execute("ALTER TABLE transfers ADD COLUMN updated_at TIMESTAMP")
            cursor.execute("UPDATE transfers SET updated_at = created_at WHERE updated_at IS NULL")

        # 2. Ensure 'module' exists in audit_logs
        cursor.execute("PRAGMA table_info(audit_logs)")
        a_cols = [r[1] for r in cursor.fetchall()]
        if "module" not in a_cols:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN module TEXT DEFAULT 'Security'")

        conn.commit()

        # Seed sample demo accounts if users table is empty
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count == 0:
            demo_users = [
                ("alice", "Alice Smith (Sender)", "alice@cybervault.org", "Alice@123"),
                ("bob", "Bob Jones (Recipient)", "bob@cybervault.org", "Bob@123"),
                ("charlie", "Charlie Davis (Security Auditor)", "charlie@cybervault.org", "Charlie@123")
            ]
            for u_name, full_name, email, pwd in demo_users:
                priv_pem, pub_pem = crypto_engine.generate_rsa_keypair(key_size=2048)
                pwd_hash, salt_hex = hash_password_sha256(pwd)
                salt_bytes = binascii.unhexlify(salt_hex.encode('utf-8'))
                enc_priv_key = crypto_engine.encrypt_private_key(priv_pem, pwd, salt_bytes)

                cursor.execute("""
                    INSERT INTO users (username, fullname, email, password_hash, salt, rsa_public_key, encrypted_private_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (u_name, full_name, email, pwd_hash, salt_hex, pub_pem, enc_priv_key))

                cursor.execute("""
                    INSERT INTO audit_logs (user_id, username, action, module, details, status)
                    VALUES (last_insert_rowid(), ?, 'USER_PROVISIONED', 'Authentication', 'Initial account provisioned with 2048-bit RSA keypair', 'SUCCESS')
                """, (u_name,))

            conn.commit()


def register_user(username: str, fullname: str, email: str, password: str) -> Tuple[bool, str, Optional[str]]:
    """
    Registers a new user:
    - Hashes password with PBKDF2-HMAC-SHA256
    - Generates 2048-bit RSA Keypair
    - Encrypts private key with password
    - Stores in SQLite
    Returns (success, message, private_key_pem)
    """
    username = username.strip().lower()
    if not username or not password or not fullname:
        return False, "Username, Full Name, and Password are required.", None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return False, f"Username '{username}' already exists. Please choose another.", None

        # 1. Generate RSA keypair
        private_pem, public_pem = crypto_engine.generate_rsa_keypair(key_size=2048)

        # 2. Hash Password
        pwd_hash, salt_hex = hash_password_sha256(password)
        salt_bytes = binascii.unhexlify(salt_hex.encode('utf-8'))

        # 3. Encrypt Private Key with derived password key
        enc_priv_key = crypto_engine.encrypt_private_key(private_pem, password, salt_bytes)

        cursor.execute("""
            INSERT INTO users (username, fullname, email, password_hash, salt, rsa_public_key, encrypted_private_key)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, fullname, email, pwd_hash, salt_hex, public_pem, enc_priv_key))

        user_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO audit_logs (user_id, username, action, module, details, status)
            VALUES (?, ?, 'USER_REGISTRATION', 'Authentication', 'User registered with 2048-bit RSA identity', 'SUCCESS')
        """, (user_id, username))
        conn.commit()

        return True, "User registered successfully!", private_pem


def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Authenticates user and retrieves their profile and unlocked private key.
    Returns (success, user_dict, message).
    """
    username = username.strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()

        if not row:
            log_audit(None, username, "LOGIN_FAILED", "Username not found", "FAILED", module="Authentication")
            return False, None, "Invalid username or password."

        stored_hash = row["password_hash"]
        stored_salt = row["salt"]

        if not verify_password_sha256(stored_hash, stored_salt, password):
            log_audit(row["id"], username, "LOGIN_FAILED", "Password mismatch", "FAILED", module="Authentication")
            return False, None, "Invalid username or password."

        salt_bytes = binascii.unhexlify(stored_salt.encode('utf-8'))
        try:
            private_pem = crypto_engine.decrypt_private_key(row["encrypted_private_key"], password, salt_bytes)
        except Exception as e:
            return False, None, f"Failed to decrypt user private key: {str(e)}"

        user_data = {
            "id": row["id"],
            "username": row["username"],
            "fullname": row["fullname"],
            "email": row["email"],
            "public_key": row["rsa_public_key"],
            "private_key": private_pem,
            "created_at": row["created_at"]
        }

        log_audit(row["id"], username, "LOGIN_SUCCESS", "User logged in securely", "SUCCESS", module="Authentication")
        return True, user_data, "Login successful!"


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves public user data by username."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, fullname, email, rsa_public_key, created_at FROM users WHERE username = ?", (username.strip().lower(),))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def get_all_users() -> List[Dict[str, Any]]:
    """Retrieves list of all registered users (excluding sensitive password/private key data)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, fullname, email, rsa_public_key, created_at FROM users ORDER BY username ASC")
        return [dict(r) for r in cursor.fetchall()]


def store_user_file(user_id: int, username: str, filename: str, file_bytes: bytes, encryption_status: str = "Plaintext") -> int:
    """Stores a file in filesystem and registers record in user_files table."""
    sha256_hash = crypto_engine.compute_sha256(file_bytes)
    user_file_dir = os.path.join(FILES_DIR, f"user_{user_id}")
    os.makedirs(user_file_dir, exist_ok=True)

    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored_filename = f"{timestamp_prefix}_{filename}"
    stored_path = os.path.join(user_file_dir, stored_filename)

    with open(stored_path, "wb") as f:
        f.write(file_bytes)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_files (user_id, filename, file_size, sha256_hash, stored_path, encryption_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, filename, len(file_bytes), sha256_hash, stored_path, encryption_status))
        file_id = cursor.lastrowid

        log_audit(user_id, username, "FILE_SAVED_TO_VAULT", f"Saved {filename} ({len(file_bytes)} bytes) [SHA-256: {sha256_hash[:16]}...]", "SUCCESS", module="File Vault")
        conn.commit()
        return file_id


def get_user_files(user_id: int) -> List[Dict[str, Any]]:
    """Fetches all files belonging to a user."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, filename, file_size, sha256_hash, stored_path, encryption_status, created_at
            FROM user_files
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (user_id,))
        return [dict(r) for r in cursor.fetchall()]


def delete_user_file(file_id: int, user_id: int, username: str) -> bool:
    """Deletes a file from disk and database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT stored_path, filename FROM user_files WHERE id = ? AND user_id = ?", (file_id, user_id))
        row = cursor.fetchone()
        if row:
            stored_path = row["stored_path"]
            filename = row["filename"]
            if os.path.exists(stored_path):
                try:
                    os.remove(stored_path)
                except Exception:
                    pass
            cursor.execute("DELETE FROM user_files WHERE id = ? AND user_id = ?", (file_id, user_id))
            conn.commit()
            log_audit(user_id, username, "FILE_DELETED", f"Deleted {filename} from vault", "SUCCESS", module="File Vault")
            return True
        return False


def create_transfer_record(
    sender_id: int,
    sender_username: str,
    recipient_id: int,
    recipient_username: str,
    original_filename: str,
    file_size: int,
    package_json: str,
    sha256_hash: str,
    initial_status: str = "PENDING"
) -> int:
    """Stores a secure file transfer package record."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO transfers (sender_id, recipient_id, original_filename, file_size, sha256_hash, package_json, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (sender_id, recipient_id, original_filename, file_size, sha256_hash, package_json, initial_status))
        transfer_id = cursor.lastrowid
        conn.commit()

        log_audit(
            sender_id,
            sender_username,
            "FILE_SENT",
            f"Dispatched {original_filename} to @{recipient_username} (Initial Status: {initial_status})",
            "SUCCESS" if initial_status == "PENDING" else "ATTACK_SIMULATED",
            module="File Transfer"
        )
        return transfer_id


def simulate_in_transit_attack(transfer_id: int, username: str) -> bool:
    """Simulates an in-transit attack by modifying ciphertext bytes in SQLite."""
    import json
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT package_json, original_filename FROM transfers WHERE id = ?", (transfer_id,))
        row = cursor.fetchone()
        if not row:
            return False

        pkg = json.loads(row["package_json"])
        tampered_pkg = crypto_engine.tamper_package_ciphertext(pkg)
        tampered_json = json.dumps(tampered_pkg)

        cursor.execute("""
            UPDATE transfers 
            SET package_json = ?, status = 'ATTACK DETECTED', updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (tampered_json, transfer_id))
        conn.commit()

        log_audit(
            None,
            username,
            "ATTACK_INJECTED_IN_TRANSIT",
            f"Man-in-the-Middle Attack Simulated: Ciphertext tampered for transfer #{transfer_id} ({row['original_filename']})",
            "ATTACK DETECTED",
            module="Security"
        )
        return True


def get_received_transfers(recipient_id: int) -> List[Dict[str, Any]]:
    """Retrieves all packages sent to recipient, safely resolving updated_at."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.sender_id, u.username as sender_username, u.fullname as sender_fullname,
                   u.rsa_public_key as sender_public_key, t.original_filename, t.file_size,
                   t.sha256_hash, t.package_json, t.status, t.created_at,
                   COALESCE(t.updated_at, t.created_at) as updated_at
            FROM transfers t
            JOIN users u ON t.sender_id = u.id
            WHERE t.recipient_id = ?
            ORDER BY t.created_at DESC
        """, (recipient_id,))
        return [dict(r) for r in cursor.fetchall()]


def get_sent_transfers(sender_id: int) -> List[Dict[str, Any]]:
    """Retrieves all packages sent by user, safely resolving updated_at."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.id, t.recipient_id, u.username as recipient_username, u.fullname as recipient_fullname,
                   t.original_filename, t.file_size, t.sha256_hash, t.status, t.created_at,
                   COALESCE(t.updated_at, t.created_at) as updated_at
            FROM transfers t
            JOIN users u ON t.recipient_id = u.id
            WHERE t.sender_id = ?
            ORDER BY t.created_at DESC
        """, (sender_id,))
        return [dict(r) for r in cursor.fetchall()]


def update_transfer_status(transfer_id: int, new_status: str, user_id: Optional[int] = None, username: str = "System", details: str = ""):
    """
    Updates the status of a transfer:
    Valid statuses: PENDING, RECEIVED, VERIFIED, ATTACK DETECTED
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE transfers 
            SET status = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (new_status, transfer_id))
        conn.commit()

        action_name = "INTEGRITY_VERIFIED" if new_status == "VERIFIED" else "INTEGRITY_FAILED"
        log_audit(user_id, username, action_name, details or f"Status changed to {new_status}", new_status, module="File Transfer")


def log_audit(user_id: Optional[int], username: str, action: str, details: str, status: str, module: str = "Security"):
    """Inserts a record into audit_logs table safely satisfying all column constraints."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (user_id, username, action, module, details, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, username, action, module, details, status))
            conn.commit()
    except Exception as e:
        print(f"Audit log error: {e}")


def get_audit_logs(limit: int = 150) -> List[Dict[str, Any]]:
    """Fetches system-wide security audit logs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, username, action, module, details, status, timestamp
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]


def get_system_stats() -> Dict[str, int]:
    """Returns top-level security metrics for the dashboard."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM transfers")
        total_transfers = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM transfers WHERE status = 'VERIFIED'")
        verified_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM transfers WHERE status = 'ATTACK DETECTED'")
        attacks_detected = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM transfers WHERE status = 'PENDING'")
        pending_count = cursor.fetchone()[0]

        return {
            "total_users": total_users,
            "total_transfers": total_transfers,
            "verified_count": verified_count,
            "attacks_detected": attacks_detected,
            "pending_count": pending_count
        }
