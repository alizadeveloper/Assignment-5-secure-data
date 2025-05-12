import streamlit as st

# ✅ This must be FIRST Streamlit command
st.set_page_config(page_title="Secure Data Vault", page_icon="🛡️", initial_sidebar_state="collapsed")

import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from datetime import datetime

# -----------------------------
# 📁 JSON File Handling
# -----------------------------
DATA_FILE = "data.json"
LOCK_FILE = "lock.json"
USERS_FILE = "users.json"

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def load_locks():
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_locks(data):
    with open(LOCK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)

# -----------------------------
# 🔐 Key and Cipher Setup
# -----------------------------
@st.cache_resource
def get_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = get_cipher()

# -----------------------------
# 📆 Load Data into Session State
# -----------------------------
stored_data = load_data()
locks = load_locks()
users_data = load_users()

if "stored_data" not in st.session_state:
    st.session_state.stored_data = stored_data
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "locks" not in st.session_state:
    st.session_state.locks = locks
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "page" not in st.session_state:
    st.session_state.page = "Login"

# -----------------------------
# 🔑 Utility Functions
# -----------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    current_time = time.time()
    lock_info = st.session_state.locks.get(encrypted_text)
    if lock_info:
        unlock_time = lock_info.get("unlock_time", 0)
        remaining_time = unlock_time - current_time
        if remaining_time > 0:
            st.warning(f"🔒 This data is temporarily locked. {int(remaining_time)} seconds remaining.")
            return None
        else:
            st.session_state.locks.pop(encrypted_text, None)
            save_locks(st.session_state.locks)
            st.info("🔓 The lock has expired. You can now access the data.")

    hashed = hash_passkey(passkey)
    entry = st.session_state.stored_data.get(encrypted_text)

    if entry and entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        if st.session_state.failed_attempts >= 3:
            st.session_state.locks[encrypted_text] = {
                "unlock_time": current_time + 300
            }
            save_locks(st.session_state.locks)
        return None

# -----------------------------
# 🔐 Auth System First
# -----------------------------
st.title("🛡️Secure Data Encryption System")
st.caption("Developed by Aliza Naeem")

if not st.session_state.is_logged_in:
    auth_tab = st.radio("Login or Register", ["Login", "Register"], horizontal=True)

    if auth_tab == "Login":
        st.subheader("🔐 Login to Your Vault")
        user_login = st.text_input("👤 Username")
        pass_login = st.text_input("🔑 Password", type="password")

        if st.button("🔓 Login"):
            hashed_input = hash_passkey(pass_login)
            if users_data.get(user_login) == hashed_input:
                st.session_state.is_logged_in = True
                st.session_state.current_user = user_login
                st.success(f"✅ Welcome, {user_login}!")
                st.balloons()
                time.sleep(2)
                st.session_state.page = "home"
                st.rerun()
            else:
                st.error("❌ Incorrect username or password.")

    elif auth_tab == "Register":
        st.subheader("💊 Create New Account")
        new_user = st.text_input("👤 Username")
        new_pass = st.text_input("🔑 Password", type="password")

        if st.button("🖍️ Register"):
            if new_user in users_data:
                st.error("❌ Username already exists.")
            elif new_user and new_pass:
                users_data[new_user] = hash_passkey(new_pass)
                save_users(users_data)
                st.success("✅ Registered successfully! You can now login.")
                st.balloons()
                st.session_state.page = "home"
                st.rerun()
            else:
                st.warning("⚠️ Please enter both username and password.")
    st.stop()

# -----------------------------
# 🌐 Main App Navigation
# -----------------------------
if st.session_state.is_logged_in:
    st.sidebar.markdown(f"👋 Logged in as: `{st.session_state.current_user}`")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.is_logged_in = False
        st.session_state.current_user = None
        st.success("✅ Logged out successfully.")
        st.balloons()
        time.sleep(2)
        st.session_state.page = "login"
        st.rerun()

    menu = ["Home", "Store Data", "Retrieve Data", "View Entries", "Change Password", "Delete Profile"]
    choice = st.sidebar.radio("🔍 Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome to Your Encrypted Vault")
        st.markdown("""
        ... (same markdown content) ...
        """)

    elif choice == "Store Data":
        st.subheader("📂 Store Encrypted Data")
        username = st.session_state.current_user
        user_data = st.text_area("🗒️ Enter Secret Data:")
        passkey = st.text_input("🔑 Create Passkey:", type="password")

        if st.button("🔐 Encrypt & Save"):
            if user_data and passkey:
                encrypted = encrypt_data(user_data, passkey)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.session_state.stored_data[encrypted] = {
                    "passkey": hash_passkey(passkey),
                    "user": username,
                    "timestamp": timestamp
                }
                save_data(st.session_state.stored_data)
                st.success("✅ Data encrypted and saved!")
                st.balloons()
                with st.expander("📆 Encrypted Text (click to view)"):
                    st.code(encrypted, language="text")
                st.text(f"Timestamp: {timestamp}")
            else:
                st.error("⚠️ All fields are required!")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        encrypted_input = st.text_area("🔐 Enter Encrypted Text:")
        passkey_input = st.text_input("🔑 Enter Passkey:", type="password")

        if st.button("🤩 Decrypt"):
            if encrypted_input and passkey_input:
                decrypted = decrypt_data(encrypted_input, passkey_input)
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                    st.balloons()
                else:
                    attempts_left = max(0, 3 - st.session_state.failed_attempts)
                    if encrypted_input in st.session_state.locks:
                        st.warning("🔒 Data is locked for 5 minutes or until admin login.")
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
            else:
                st.error("⚠️ Please provide both encrypted text and passkey.")

    elif choice == "View Entries":
        st.subheader("📁 Stored Entries")
        if st.session_state.stored_data:
            for i, (enc, details) in enumerate(st.session_state.stored_data.items(), 1):
                with st.expander(f"📜 Entry {i} — {details['user']} at {details['timestamp']}"):
                    st.text(f"Encrypted: {enc}")
                    st.text(f"User: {details['user']}")
                    st.text(f"Stored At: {details['timestamp']}")
        else:
            st.info("📬 No data stored yet.")

        if st.button("🗑️ Delete All Entries"):
            st.session_state.stored_data.clear()
            save_data(st.session_state.stored_data)
            st.success("✅ All entries have been deleted.")

    elif choice == "Delete Profile":
        st.subheader("🗑️ Delete Your Profile")
        if st.button("Delete Profile"):
            del users_data[st.session_state.current_user]
            save_users(users_data)
            st.session_state.is_logged_in = False
            st.session_state.current_user = None
            st.success("✅ Profile deleted successfully.")
            st.balloons()
            time.sleep(2)
            st.session_state.page = "login"
            st.rerun()

    elif choice == "Change Password":
        st.subheader("🔒 Change Your Password")

        current_pass = st.text_input("🔑 Current Password", type="password")
        new_pass = st.text_input("🆕 New Password", type="password")
        confirm_pass = st.text_input("✅ Confirm New Password", type="password")

        if st.button("🔁 Update Password"):
            user = st.session_state.current_user
            hashed_current = hash_passkey(current_pass)

            if users_data.get(user) != hashed_current:
                st.error("❌ Current password is incorrect.")
            elif new_pass != confirm_pass:
                st.warning("⚠️ New passwords do not match.")
            elif new_pass == current_pass:
                st.warning("⚠️ New password must be different from the current password.")
            elif len(new_pass) < 4:
                st.warning("⚠️ Password must be at least 4 characters long.")
            else:
                users_data[user] = hash_passkey(new_pass)
                save_users(users_data)
                st.success("✅ Password changed successfully!")
                st.balloons()


