"""Create a police (admin) account.   Usage:  python create_police.py"""
import getpass
import re

from werkzeug.security import generate_password_hash

from app import now, users

name = input("Officer name: ").strip()
email = input("Email: ").strip().lower()
phone = input("Phone (10 digits): ").strip()
station = input("Police station / office: ").strip()
password = getpass.getpass("Password (min 8 chars): ")

if not name or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) or len(password) < 8:
    raise SystemExit("Invalid name, email or password.")
if users.find_one({"email": email}):
    raise SystemExit("An account with this email already exists.")

users.insert_one({
    "name": name, "email": email, "phone": phone or None, "station": station,
    "password_hash": generate_password_hash(password),
    "role": "police", "is_verified": True, "created_at": now(),
})
print(f"Police account created for {email}. You can log in now.")
