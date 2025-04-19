import os
import secrets
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import re
import subprocess
import sys

# ========== 🔧 Auto-install 'cryptography' if missing ==========
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag

# Backend for cryptographic operations
backend = default_backend()

# =========================
# 🔑 Key Derivation
# =========================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=backend
    )
    return kdf.derive(password.encode())

# =========================
# 🔐 Encrypt File
# =========================
def encrypt_file():
    filepaths = filedialog.askopenfilenames(title="Select file(s) to encrypt")
    if not filepaths:
        return

    password = simpledialog.askstring("Password", "Enter a strong password:", show="*")
    if not password:
        return

    if not check_password_strength(password):
        proceed = messagebox.askyesno("Weak Password", "Password is weak. Proceed anyway?")
        if not proceed:
            return

    for filepath in filepaths:
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        key = derive_key(password, salt)

        with open(filepath, 'rb') as f:
            plaintext = f.read()

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=backend
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        encrypted_data = salt + iv + encryptor.tag + ciphertext

        # Create backup
        if messagebox.askyesno("Backup File", f"Create a backup of:\n{os.path.basename(filepath)}?"):
            backup_path = filepath + ".bak"
            with open(backup_path, 'wb') as b:
                b.write(plaintext)

        # Output path with extension
        ext = os.path.splitext(filepath)[-1]
        output_path = filepath + f".cheezlock{ext}"

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        if messagebox.askyesno("Delete Original?", f"Delete original file:\n{os.path.basename(filepath)}?"):
            os.remove(filepath)

        messagebox.showinfo("Encrypted", f"Saved: {os.path.basename(output_path)}")

# =========================
# 🔓 Decrypt File
# =========================
def decrypt_file():
    filepath = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted Files", "*.cheezlock*")])
    if not filepath:
        return

    password = simpledialog.askstring("Password", "Enter the password:", show="*")
    if not password:
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    ciphertext = data[44:]

    try:
        key = derive_key(password, salt)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=backend
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Save decrypted
        save_path = filedialog.asksaveasfilename(defaultextension=os.path.splitext(filepath)[-1])
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(plaintext)

            messagebox.showinfo("Decrypted", f"Saved: {os.path.basename(save_path)}")

            if save_path.endswith('.py'):
                subprocess.run(["python", save_path])
            elif save_path.endswith('.bat'):
                subprocess.run([save_path], shell=True)

    except (InvalidTag, ValueError):
        messagebox.showerror("Error", "Decryption failed. Incorrect password or file corrupted.")

# =========================
# ☠️ Secure File Shredder (Improved)
# =========================
def destroy_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    confirm = messagebox.askyesno("Are you sure?", f"This will permanently delete:\n{filepath}")
    if not confirm:
        return

    try:
        # Ask for overwrite passes (default 3)
        passes = simpledialog.askinteger("Overwrite Passes", "How many passes? (default 3)", initialvalue=3)
        if passes is None:
            return

        size = os.path.getsize(filepath)

        # Open the file for overwriting
        with open(filepath, 'r+b') as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                if i % 10 == 0:
                    print(f"Pass {i + 1} completed...")

        tempname = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12)) + ".del"
        temp_path = os.path.join(os.path.dirname(filepath), tempname)

        os.rename(filepath, temp_path)
        os.remove(temp_path)

        messagebox.showinfo("Destroyed", "File securely shredded.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to shred file:\n{e}")

# =========================
# 🧪 Password Strength Check
# =========================
def check_password_strength(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[\W_]', password)
    )

# =========================
# 🖥️ GUI Setup
# =========================
root = tk.Tk()
root.title("Cheezzy Encryptor PRO 🔐")
root.geometry("450x420")
root.configure(bg="#1e1e1e")

tk.Label(root, text="🔐 Advanced File Encryption Tool", font=("Arial", 16), fg="white", bg="#1e1e1e").pack(pady=20)

tk.Button(root, text="Encrypt File(s)", command=encrypt_file, bg="#007bff", fg="white", font=("Arial", 12), width=32).pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_file, bg="#28a745", fg="white", font=("Arial", 12), width=32).pack(pady=10)
tk.Button(root, text="☠️ Destroy File (Shred Forever)", command=destroy_file, bg="#dc3545", fg="white", font=("Arial", 12), width=32).pack(pady=10)

tk.Label(root, text="AES-256 • PBKDF2 • GCM • by CheezzyBoii", font=("Arial", 9), fg="#aaaaaa", bg="#1e1e1e").pack(side="bottom", pady=15)

root.mainloop()
