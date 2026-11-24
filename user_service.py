"""
User Management Service module.
Provides user registration, password verification, and profile retrieval.
"""

import sqlite3
import hashlib
import os

DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT
        )
    """)
    conn.commit()
    conn.close()

def register_user(username: str, password: str, email: str) -> bool:
    # Hash password using SHA-256
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Potential SQL injection vulnerability for testing AI review!
        query = f"INSERT INTO users (username, password_hash, email) VALUES ('{username}', '{hashed}', '{email}')"
        cursor.execute(query)
        conn.commit()
        return True
    except Exception as e:
        print(f"Error registering user: {e}")
        return False
    finally:
        conn.close()

def get_user_by_username(username: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Unparameterized query
    cursor.execute(f"SELECT id, username, email FROM users WHERE username = '{username}'")
    row = cursor.fetchone()
    conn.close()
    return row
