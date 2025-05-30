import sqlite3
from werkzeug.security import generate_password_hash
from db_crypto import generate_key, encrypt_file
import os

def init_database():
    try:
        print("Creating database...")
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Create users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0
            )
        ''')
        
        # Add default admin user if table is empty
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            admin_password = generate_password_hash('admin123')
            c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                     ('admin', admin_password, True))
        
        conn.commit()
        conn.close()
        
        # Generate new encryption key if not exists
        if not os.path.exists('key.key'):
            print("Generating encryption key...")
            key = generate_key()
            with open('key.key', 'wb') as key_file:
                key_file.write(key)
        
        # Encrypt database
        print("Encrypting database...")
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
        encrypt_file('users.db', key)
        
        # Remove unencrypted database
        if os.path.exists('users.db'):
            os.remove('users.db')
            
        print("Database initialization complete!")
        
    except Exception as e:
        print(f"Error initializing database: {str(e)}")

if __name__ == "__main__":
    init_database()