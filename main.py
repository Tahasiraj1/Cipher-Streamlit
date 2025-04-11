import streamlit as st
from cryptography.fernet import Fernet
import streamlit as st
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# In-memory data storage
stored_data = {}

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 3  # Default value

# Save data to a file
def save_data():
    with open("store_data.json", "w") as f:
        json.dump(stored_data, f, indent=4)

# Load data from a file
def load_data():
    global stored_data
    try:
        with open("store_data.json", "r") as f:
            stored_data = json.load(f)
    except FileNotFoundError:
        stored_data = {}
    except json.JSONDecodeError:
        stored_data = {}

# Function to derive a Fernet key from a passkey and salt
def derive_key(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt,
        iterations=390000,  # Number of iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key

# Function to encrypt data
def encrypt_data(text, passkey, salt):
    key = derive_key(passkey, salt)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, salt):
    global failed_attempts
    try:
        key = derive_key(passkey, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        print(f"❌ Decryption Error: {str(e)}")
        st.session_state["failed_attempts"] -= 1
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

tab1, tab2, tab3 = st.tabs(["Home", "Store Data", "Retrieve Data"])

if st.experimental_user.is_logged_in:
    load_data()  # Ensure data is loaded
    user_name = st.experimental_user.name
    if user_name not in stored_data:
        stored_data[user_name] = []

    with tab1:
        picture, greet = st.columns([0.2, 1])
        with picture:
            st.image(st.experimental_user.picture)
        with greet:
            st.write(f"🏠 Welcome **{st.experimental_user.name}** to the Secure Data System!")
            st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
        # Explanation of the app
        st.subheader("📝 Overview of the App")
        st.write("""
            Welcome to the **Secure Data Encryption System**! This app allows you to securely store and retrieve sensitive data using encryption techniques.
            
            ### Key Features:
            1. **Login System**: 
                - Users need to log in using their configured account (for demo, it's using Google login).
            
            2. **Store Data**: 
                - You can securely store data by entering text and a passkey. The text will be encrypted using the passkey and a unique salt, and stored securely.
            
            3. **Retrieve Data**: 
                - Retrieve your encrypted data by selecting the encrypted text and providing the correct passkey. The app will decrypt it and show the original data.
            
            4. **Failed Attempts Counter**: 
                - The app tracks the number of failed decryption attempts and warns you if you exceed the maximum allowed.

            5. **Security**: 
                - The app uses **Fernet encryption** (symmetric encryption) with **PBKDF2 key derivation** to securely encrypt and decrypt your data.

            ### Workflow:
            - **Home Tab**: Displays a welcome message once you're logged in.
            - **Store Data Tab**: Lets you input data and a passkey, encrypting and storing the data.
            - **Retrieve Data Tab**: Allows you to select data and input passkey to decrypt and retrieve your data.
            
            This app ensures that your sensitive data is kept private, safe, and secure using encryption.
        """)
        if st.button("Logout", use_container_width=True):
            st.logout()

    with tab2:
        st.subheader("📂 Store Data Securely")
        text = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save", use_container_width=True):
            if text and passkey:
                # Generate a unique salt for each data entry (important for security)
                salt = os.urandom(16)
                encrypted_text = encrypt_data(text, passkey, salt)
                if encrypted_text:
                    data_entry = {
                        "encrypted_text": encrypted_text,
                        "salt": base64.b64encode(salt).decode()
                    }
                    stored_data[user_name].append(data_entry)
                    save_data()  # Save data to file
                    st.success(f"✅ Data stored securely! {encrypted_text}")
                else:
                    st.error("⚠️ Encryption failed! Please try again.")
            else:
                st.error("⚠️ Both fields are required!")

    with tab3:
        st.subheader(f"Retrieve Data for {user_name}")

        if user_name in stored_data and stored_data[user_name]:
            if stored_data[user_name]:
                selected_data_index = st.selectbox(
                    "Select data to decrypt:",
                    range(len(stored_data[user_name])),
                    format_func=lambda i: f"Data Entry {i+1} (Encrypted)"  # Display options nicely
                )

                passkey_retrieve = st.text_input("Enter Passkey for the selected data:", type="password")

                if st.button("Decrypt Selected Data"):
                    if passkey_retrieve:
                        selected_item = stored_data[user_name][selected_data_index]
                        encrypted_text_to_decrypt = selected_item["encrypted_text"]
                        salt_bytes = base64.b64decode(selected_item["salt"])
                        decrypted_text = decrypt_data(encrypted_text_to_decrypt, passkey_retrieve, salt_bytes)
                        if decrypted_text:
                            st.success(f"🔓 Decrypted Data: {decrypted_text}")
                        else:
                            st.error(f"❌ Incorrect passkey for this data! {st.session_state['failed_attempts']}")
                    else:
                        st.error("⚠️ Passkey is required to decrypt!")
                    if st.session_state["failed_attempts"] <= 0:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.logout()
            else:
                st.info(f"No data stored yet for {user_name}.")
        else:
            st.info(f"No data stored yet for {user_name}.")

else:
    st.subheader("🔑 Login to Access the App")
    st.write("Please log in using your configured account.")
    if st.button("Login with Google", use_container_width=True):
        st.login("google")
        st.session_state["failed_attempts"] = 3