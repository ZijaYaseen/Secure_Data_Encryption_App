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
        data = json.load(f)
    # Migrate old format (flat entries) to new multi-user structure
    if "users" not in data or "entries" not in data:
        stored_data = {"users": {}, "entries": data}
    else:
        stored_data = data
else:
    stored_data = {"users": {}, "entries": {}}

# ---------- Helper Functions ----------

def save_storage():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=2)

def pbkdf2_hash_passkey(passkey: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        salt.encode(),
        PBKDF2_ITERATIONS
    )
    return base64.b64encode(dk).decode()

def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(token: str, passkey: str, user: str):
    user_entries = stored_data["entries"].get(user, {})
    for entry in user_entries.values():
        if entry["encrypted_text"] == token:
            input_hashed = pbkdf2_hash_passkey(passkey, entry["salt"])
            if entry["passkey"] == input_hashed:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(token.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ---------- Session State Initialization ----------
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"
if "username" not in st.session_state:
    st.session_state.username = None

# ---------- Custom CSS for Copy Button Positioning ----------
st.markdown("""
<style>
button[title="Copy to clipboard"] {
    top: 0px !important;  /* Pushes the copy icon slightly upward */
}
</style>
""", unsafe_allow_html=True)

# ---------- UI Pages ----------
def home_page():
    st.title("🔐 Secure Data Encryption App")
    if st.session_state.username:
        st.success(f"Logged in as: {st.session_state.username}")
    else:
        st.info("Please sign up or log in to manage your data.")

    st.markdown("""
    <div style="background-color: #f0f2f6; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        <h3 style="color: #6c39ec;">👋 Welcome!</h3>
        <p style="font-size: 16px;">This app allows you to:</p>
        <ul style="line-height: 1.7;">
            <li><b>Insert Data</b> 🔏 – Encrypt your sensitive information.</li>
            <li><b>Retrieve Data</b> 🔓 – Decrypt your data using your passkey.</li>
        </ul>
        <p>⚠️ <i>You get only <b>3 attempts</b> to decrypt your data.</i></p>
    </div>
    """, unsafe_allow_html=True)


def signup_page():
    st.title("👤 Create Account")
    username = st.text_input("Choose a username:")
    password = st.text_input("Choose a password:", type="password")
    if st.button("Sign Up"):
        if username in stored_data["users"]:
            st.error("Username already exists!")
        elif username and password:
            salt = os.urandom(16).hex()
            hashed = pbkdf2_hash_passkey(password, salt)
            stored_data["users"][username] = {"salt": salt, "password": hashed}
            save_storage()
            st.success("Account created! Please log in.")
        else:
            st.error("Both fields are required.")


def login_page():
    st.title("🔑 Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    if st.button("Log In"):
        user = stored_data["users"].get(username)
        if user:
            input_hashed = pbkdf2_hash_passkey(password, user["salt"])
            if input_hashed == user["password"]:
                st.session_state.username = username
                st.session_state.failed_attempts = 0
                st.success("Logged in successfully.")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("Incorrect password.")
        else:
            st.error("Username not found.")


def insert_data_page():
    st.title("📂 Insert Data")
    if not st.session_state.username:
        st.error("Please log in first.")
        return
    text = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Choose a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            token = encrypt_data(text)
            salt = os.urandom(16).hex()
            hashed_passkey = pbkdf2_hash_passkey(passkey, salt)
            user = st.session_state.username
            stored_data["entries"].setdefault(user, {})
            stored_data["entries"][user][token] = {
                "encrypted_text": token,
                "passkey": hashed_passkey,
                "salt": salt
            }
            save_storage()
            st.success("✅ Data encrypted and saved!")
            # Display token with heading and guidance
            st.write("🔐 **Encrypted Token:**")
            st.code(token)
            st.info(
                "**Keep this token safe!**\n"
                "- You'll need it to decrypt or retrieve your data later.\n"
                "- Store it in a secure place (e.g., password manager).\n"
                "- Do NOT share it with anyone, as it grants access to your encrypted information."
            )
        else:
            st.error("Both fields are required!")


def retrieve_data_page():
    st.title("🔍 Retrieve Data")
    if not st.session_state.username:
        st.error("Please log in first.")
        return
    token = st.text_area("Paste the encrypted token:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Decrypt"):
        if token and passkey:
            plaintext = decrypt_data(token, passkey, st.session_state.username)
            if plaintext:
                st.success("✅ Decrypted text:")
                st.write(plaintext)
            else:
                rem = MAX_TRIES - st.session_state.failed_attempts
                st.error(f"Incorrect passkey! Attempts left: {rem}")
                if st.session_state.failed_attempts >= MAX_TRIES:
                    st.warning("Too many failed attempts—please log in again.")
                    st.session_state.username = None
                    st.session_state.current_page = "Login"
                    st.rerun()
        else:
            st.error("Both fields are required!")

# ---------- Navigation ----------
pages = {
    "Home": home_page,
    "Sign Up": signup_page,
    "Login": login_page,
    "Insert Data": insert_data_page,
    "Retrieve Data": retrieve_data_page
}
selected_page = st.sidebar.selectbox("Navigate", list(pages.keys()),
                                  index=list(pages.keys()).index(st.session_state.current_page))

st.session_state.current_page = selected_page
pages[selected_page]()
