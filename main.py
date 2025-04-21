import streamlit as st
import hashlib
import json
import os
import base64
from cryptography.fernet import Fernet

# ---------- Configuration ----------
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
MAX_TRIES = 3
MASTER_PASSWORD = "admin123"
PBKDF2_ITERATIONS = 100_000  # Strong security

# ---------- Load/Create Fernet Key ----------
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()
cipher = Fernet(key)

# ---------- Load or Initialize Storage ----------
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

def save_storage():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=2)

# ---------- Session State Initialization ----------
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"

# ---------- Helper: PBKDF2 Hashing ----------
def pbkdf2_hash_passkey(passkey: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        salt.encode(),
        PBKDF2_ITERATIONS
    )
    return base64.b64encode(dk).decode()

# ---------- Encryption/Decryption ----------
def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(token: str, passkey: str):
    for entry in stored_data.values():
        stored_token = entry["encrypted_text"]
        stored_salt = entry["salt"]
        stored_hashed = entry["passkey"]

        input_hashed = pbkdf2_hash_passkey(passkey, stored_salt)
        if stored_token == token and stored_hashed == input_hashed:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(token.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ---------- UI Pages ----------
def home_page():
    st.title("🔐 Secure Data Encryption App")

    st.markdown("""
    <div style="background-color: #f0f2f6; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        <h3 style="color: #6c39ec;">👋 Welcome!</h3>
        <p style="font-size: 16px;">This app allows you to:</p>
        <ul style="line-height: 1.7;">
            <li><b>Insert Data</b> 🔏 – Encrypt your sensitive information.</li>
            <li><b>Retrieve Data</b> 🔓 – Decrypt your data using your passkey.</li>
            <li><b>Login</b> 🔑 – Master access in case you’re locked out.</li>
        </ul>
        <p>⚠️ <i>You get only <b>3 attempts</b> to decrypt your data. After that, you'll be redirected to login.</i></p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🧭 Navigation Guide")
    st.info("Use the sidebar on the left to go to different sections: Insert, Retrieve or Login.")

    st.markdown("💡 **Tip:** Never share your encrypted token or passkey with others. It’s like the key to your vault!")

    st.markdown("---")
    st.caption("🚀 Created by Zija Yaseen | © 2025 All rights reserved.")


def insert_data_page():
    st.title("📂 Insert Data")
    text = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Choose a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            token = encrypt_data(text)
            salt = os.urandom(16).hex()  # Unique salt per entry
            hashed_passkey = pbkdf2_hash_passkey(passkey, salt)

            stored_data[token] = {
                "encrypted_text": token,
                "passkey": hashed_passkey,
                "salt": salt
            }
            save_storage()
            st.success("✅ Data encrypted and saved!")
            st.write("🔐 **Encrypted Token:**")
            st.code(token)
            st.info("Please copy and save this token. You'll need it to retrieve your data.")
        else:
            st.error("⚠️ Both fields are required!")

def retrieve_data_page():
    st.title("🔍 Retrieve Data")
    token = st.text_area("Paste the encrypted token:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Decrypt"):
        if token and passkey:
            plaintext = decrypt_data(token, passkey)
            if plaintext:
                st.success("✅ Decrypted text:")
                st.write(plaintext)
            else:
                rem = MAX_TRIES - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {rem}")
                if st.session_state.failed_attempts >= MAX_TRIES:
                    st.warning("🔒 Too many failed attempts—redirecting to Login.")
                    st.session_state.current_page = "Login"
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

def login_page():
    st.title("🔑 Login Required")
    pwd = st.text_input("Master password:", type="password")
    if st.button("Reauthorize"):
        if pwd == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized—please return to Retrieve Data.")
            st.session_state.current_page = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Wrong master password!")

# ---------- Navigation ----------
pages = {
    "Home": home_page,
    "Insert Data": insert_data_page,
    "Retrieve Data": retrieve_data_page,
    "Login": login_page
}

# Sidebar navigation
selected_page = st.sidebar.selectbox("Navigate", list(pages.keys()), index=list(pages.keys()).index(st.session_state.current_page))
st.session_state.current_page = selected_page

# Render the selected page
pages[st.session_state.current_page]()
