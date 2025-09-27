import os
import sqlite3
import getpass
import random
import string
import hashlib
import hmac
import base64
from cryptography.fernet import Fernet

DB_PATH = "User_data.db"
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# --- Schema ---
cursor.execute("""
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash BLOB,
    salt BLOB
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS entries (
    url TEXT NOT NULL,
    enc_pass BLOB NOT NULL
)
""")
conn.commit()

# --- Helpers for key derivation ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from password + salt."""
    kdf = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return base64.urlsafe_b64encode(kdf)

def verify_and_get_fernet(password: str):
    """Verify the password and return a Fernet instance if correct, else None."""
    row = cursor.execute("SELECT password_hash, salt FROM user WHERE id = 1").fetchone()
    if not row:
        return None
    stored_hash, salt = row
    candidate_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    if not hmac.compare_digest(stored_hash, candidate_hash):
        return None
    return Fernet(derive_key(password, salt))

def initialize_master_if_needed():
    """Ask user to set master password if not already set."""
    row = cursor.execute("SELECT 1 FROM user WHERE id = 1").fetchone()
    if row:
        return
    print("No master password found — creating a new one.")
    while True:
        pw = getpass.getpass("Create master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Passwords do not match.")
            continue
        if len(pw) < 8:
            print("Password must be at least 8 characters.")
            continue
        break
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    cursor.execute("INSERT INTO user (id, password_hash, salt) VALUES (1, ?, ?)", (password_hash, salt))
    conn.commit()
    print("Master password created.\n")

# --- App ---
class App:
    def __init__(self):
        initialize_master_if_needed()
        self.fernet = self.login()
        if not self.fernet:
            print("Exiting.")
            conn.close()
            raise SystemExit
        self.main_menu()

    def login(self):
        for attempt in range(3):
            pwd = getpass.getpass("Enter master password: ")
            f = verify_and_get_fernet(pwd)
            if f:
                print("Login successful.\n")
                return f
            else:
                print("Incorrect password.")
        return None

    def main_menu(self):
        while True:
            choice = input("""\nA: Generate New Password
B: Display Passwords
C: Update Password (ID)
D: Delete Password (ID)
Any other key: Exit
Choose: """).upper()
            if choice == "A":
                self.generate_password()
            elif choice == "B":
                self.display_passwords()
            elif choice == "C":
                self.update_passwords()
            elif choice == "D":
                self.delete_passwords()
            else:
                print("Goodbye.")
                conn.close()
                break

    def generate_password(self):
        try:
            length = int(input("Enter Password Length (min 8): "))
            if length < 8:
                print("Must be at least 8 characters.")
                return
        except ValueError:
            print("Invalid number.")
            return

        chars = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choice(chars) for _ in range(length))
        print(f"Generated: {password}")

        url = input("Assign password to application (ID or name): ").strip() or "None"
        token = self.fernet.encrypt(password.encode())
        cursor.execute("INSERT INTO entries (url, enc_pass) VALUES (?, ?)", (url, token))
        conn.commit()
        print("Stored.")

    def display_passwords(self):
        rows = cursor.execute("SELECT url, enc_pass FROM entries").fetchall()
        if not rows:
            print("No entries.")
            return
        for url, enc in rows:
            try:
                plain = self.fernet.decrypt(enc).decode()
            except Exception as e:
                plain = f"<decryption error: {e}>"
            print(f"{url} -> {plain}")

    def delete_passwords(self):
        key = input("Enter ID to delete: ").strip()
        ask = input(f'Type: y to confirm delete of: {key}\n')
        if ask.upper() == 'Y':
            cursor.execute("DELETE FROM entries WHERE url = ?", (key,))
            conn.commit()
            if cursor.rowcount:
                print("Deleted.")
            else:
                print("Not found.")

    def update_passwords(self):
        old = input("Enter existing ID to update: ").strip()
        new = input("Enter new ID: ").strip()
        cursor.execute("UPDATE entries SET url = ? WHERE url = ?", (new, old))
        conn.commit()
        if cursor.rowcount:
            print("Updated.")
        else:
            print("Not found.")

# --- Run ---
if __name__ == "__main__":
    App()
