from cryptography.fernet import Fernet
import os

def generate_key():
    """Generate encryption key"""
    return Fernet.generate_key()

def encrypt_file(filename, key):
    """Encrypt a file"""
    f = Fernet(key)
    with open(filename, 'rb') as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename + '.encrypted', 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(filename, key):
    """Decrypt a file"""
    f = Fernet(key)
    with open(filename + '.encrypted', 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, 'wb') as file:
        file.write(decrypted_data)