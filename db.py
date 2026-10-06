"""
db.py
-----
SQLite helpers: users, files, keys and the stego gallery records.
"""

import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            security_question TEXT,
            security_answer_hash TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            key_kind TEXT NOT NULL,
            algorithm TEXT,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            file_kind TEXT NOT NULL,
            file_path TEXT NOT NULL,
            meta TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stego_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL,
            message_filename TEXT NOT NULL,
            output_filename TEXT NOT NULL,
            start_bit INTEGER NOT NULL,
            period INTEGER NOT NULL,
            mode TEXT NOT NULL,
            cycle_values TEXT,
            preview_filename TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # Migration: older databases did not have stego_files.user_id.
    columns = [r["name"] for r in conn.execute("PRAGMA table_info(stego_files)")]
    if "user_id" not in columns:
        conn.execute("ALTER TABLE stego_files ADD COLUMN user_id INTEGER")
    # Migration: preview_filename holds an untouched copy of the carrier image
    # that the public gallery displays (the stego file itself is login-only).
    if "preview_filename" not in columns:
        conn.execute("ALTER TABLE stego_files ADD COLUMN preview_filename TEXT")

    conn.commit()
    conn.close()


def add_stego_file(user_id, original_filename, message_filename, output_filename,
                   start_bit, period, mode, cycle_values=None, preview_filename=None):
    conn = get_db()
    cursor = conn.execute(
        """
        INSERT INTO stego_files (
            user_id, original_filename, message_filename, output_filename,
            start_bit, period, mode, cycle_values, preview_filename
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, original_filename, message_filename, output_filename,
         start_bit, period, mode, cycle_values, preview_filename),
    )
    conn.commit()
    record_id = cursor.lastrowid
    conn.close()
    return record_id


_STEGO_SELECT = """
    SELECT s.*, u.username AS username
    FROM stego_files s
    LEFT JOIN users u ON u.id = s.user_id
"""


def get_all_stego_files():
    conn = get_db()
    rows = conn.execute(_STEGO_SELECT + " ORDER BY s.created_at DESC, s.id DESC").fetchall()
    conn.close()
    return rows


def get_stego_file(record_id):
    conn = get_db()
    row = conn.execute(_STEGO_SELECT + " WHERE s.id = ?", (record_id,)).fetchone()
    conn.close()
    return row


def get_stego_files_for_user(user_id):
    conn = get_db()
    rows = conn.execute(_STEGO_SELECT + " WHERE s.user_id = ?", (user_id,)).fetchall()
    conn.close()
    return rows


def delete_stego_file(record_id):
    conn = get_db()
    conn.execute("DELETE FROM stego_files WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()


def now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"
