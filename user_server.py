from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps
import datetime
import jwt  # This should be PyJWT

app = Flask(__name__)
# Get secret key from environment variable
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
# Get database URL from environment variable
DATABASE_URL = os.getenv('DATABASE_URL', 'users.db')

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token.split()[1], app.config['SECRET_KEY'], algorithms=["HS256"])
            if not data.get('admin'):
                return jsonify({'message': 'Admin privileges required'}), 403
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Missing credentials'}), 401
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password, is_admin FROM users WHERE username = ?", (auth.get('username'),))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user[0], auth.get('password')):
        token = jwt.encode({
            'username': auth.get('username'),
            'admin': user[1],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")  # Added algorithm parameter
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username, is_admin FROM users")
    users = [{'username': u[0], 'admin': bool(u[1])} for u in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/users', methods=['POST'])
@admin_required
def add_user():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing user data'}), 400
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                 (data['username'], 
                  generate_password_hash(data['password']), 
                  data.get('admin', False)))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User added successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 400

@app.route('/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Check if last admin
    c.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    admin_count = c.fetchone()[0]
    c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    
    if user and admin_count <= 1 and user[0]:
        return jsonify({'message': 'Cannot delete last admin'}), 400
    
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User deleted successfully'})

def init_db():
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

if __name__ == '__main__':
    init_db()  # Initialize database before starting server
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)