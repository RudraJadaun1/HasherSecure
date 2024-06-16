import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# Generate keys for encryption/decryption
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

aes_key = get_random_bytes(16)  # AES key size can be 16, 24, or 32 bytes

rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()
cipher_rsa_encrypt = PKCS1_OAEP.new(rsa_public_key)
cipher_rsa_decrypt = PKCS1_OAEP.new(rsa_key)

# Function to pad plaintext to be a multiple of 16 bytes
def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

# Function to encrypt the text with three layers of encryption
def encrypt(text):
    # First layer (Fernet)
    encrypted_text = cipher_suite.encrypt(text.encode())
    
    # Second layer (AES)
    cipher_aes = AES.new(aes_key, AES.MODE_ECB)
    encrypted_text = base64.b64encode(cipher_aes.encrypt(pad(encrypted_text.decode()).encode()))
    
    # Third layer (RSA)
    encrypted_text = cipher_rsa_encrypt.encrypt(encrypted_text)
    return base64.b64encode(encrypted_text).decode()

# Function to decrypt the text with three layers of decryption
def decrypt(encrypted_text):
    # Third layer (RSA)
    encrypted_text = base64.b64decode(encrypted_text.encode())
    decrypted_text = cipher_rsa_decrypt.decrypt(encrypted_text)
    
    # Second layer (AES)
    cipher_aes = AES.new(aes_key, AES.MODE_ECB)
    decrypted_text = cipher_aes.decrypt(base64.b64decode(decrypted_text)).decode().strip()
    
    # First layer (Fernet)
    decrypted_text = cipher_suite.decrypt(decrypted_text.encode()).decode()
    return decrypted_text

# Function to handle file selection and display content
def select_file_to_dehash():
    file_path = filedialog.askopenfilename(
        title="Select file to dehash",
        filetypes=[("HeLL Files", "*.HeLL"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, 'r', encoding='latin1') as file:
                encrypted_content = file.read()
                decrypted_content = decrypt(encrypted_content)
            # Display the file content in a new window
            display_window = tk.Toplevel(root)
            display_window.title("File Content")
            text_box = tk.Text(display_window, wrap='word')
            text_box.pack(expand=True, fill='both')
            text_box.insert('1.0', decrypted_content)
            text_box.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

# Function to handle text input and save it as a .HeLL file
def write_text_to_hash_file():
    user_input = simpledialog.askstring("Input", "Enter text to save in .HeLL file:")
    if user_input is not None:
        encrypted_content = encrypt(user_input)
        file_path = filedialog.asksaveasfilename(
            defaultextension=".HeLL",
            filetypes=[("HeLL Files", "*.HeLL"), ("All Files", "*.*")],
            title="Save file as"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='latin1') as file:
                    file.write(encrypted_content)
                messagebox.showinfo("Success", f"File saved as {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main application window
root = tk.Tk()
root.title("File Dehash and Hash")

# Create and place the buttons
button_dehash = tk.Button(root, text="Select file to dehash", command=select_file_to_dehash)
button_dehash.pack(pady=10)

button_hash = tk.Button(root, text="Write text to hash a file", command=write_text_to_hash_file)
button_hash.pack(pady=10)

# Start the GUI event loop
root.mainloop()
