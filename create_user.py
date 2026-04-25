"""
create_user.py — Add staff accounts to healthcare_db.
Usage: python create_user.py
"""
import bcrypt
import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "port": int(os.getenv("DB_PORT", 3306))
}

def main():
    print("\n── HealthSecure v3  —  Create User ──\n")
    username = input("Username : ").strip()
    password = input("Password : ").strip()
    print("Role:  1=Admin  2=Staff")
    role = "Admin" if input("Choice  : ").strip() == "1" else "Staff"

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = mysql.connector.connect(**DB_CONFIG)
    cur  = conn.cursor()
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                (username, hashed, role))
    conn.commit()
    print(f"\n✓ User '{username}' ({role}) created.")
    cur.close(); conn.close()


if __name__ == "__main__":
    main()
