import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
from urllib3.exceptions import InsecureRequestWarning
import os
import hashlib
from db_crypto import decrypt_file, encrypt_file
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class AdminTool:
    def __init__(self, root):
        # Change this to your Railway URL
        self.server_url = 'https://your-app-name.up.railway.app'
        self.token = None
        self.root = root
        
        # Configure root window
        self.root.title("User Management")
        window_width = 400
        window_height = 600
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Hide root window initially
        self.root.withdraw()
        
        # Show login window first
        if not self.show_login():
            self.root.quit()
            return
            
        # Setup and show main window after successful login
        self.setup_main_window()

    def setup_main_window(self):
        """Initialize the main application window"""
        # Show main window
        self.root.deiconify()  # Show the window
        self.root.attributes('-alpha', 1)  # Make it fully visible
        self.root.state('normal')  # Ensure window is not minimized
        self.root.lift()  # Bring to front
        self.root.focus_force()  # Force focus
        self.root.resizable(False, False)
        
        # Create main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add User section
        ttk.Label(main_frame, text="Add New User", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Username
        ttk.Label(main_frame, text="Username:").pack(anchor="w")
        self.username = ttk.Entry(main_frame, width=30)
        self.username.pack(fill="x", pady=5)
        
        # Password
        ttk.Label(main_frame, text="Password:").pack(anchor="w")
        self.password = ttk.Entry(main_frame, show="*", width=30)
        self.password.pack(fill="x", pady=5)
        
        # Admin checkbox
        self.is_admin = tk.BooleanVar()
        ttk.Checkbutton(main_frame, text="Admin privileges", 
                       variable=self.is_admin).pack(pady=5)
        
        # Add button
        ttk.Button(main_frame, text="Add User", 
                  command=self.add_user).pack(pady=10)
        
        # Separator
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=20)
        
        # Users list
        ttk.Label(main_frame, text="Existing Users", 
                 font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Treeview for users
        self.tree = ttk.Treeview(main_frame, columns=('Username', 'Admin'), 
                                show='headings', height=10)
        self.tree.heading('Username', text='Username')
        self.tree.heading('Admin', text='Admin')
        self.tree.pack(fill='both', expand=True, pady=10)
        
        # Delete button
        ttk.Button(main_frame, text="Delete Selected", 
                  command=self.delete_user).pack(pady=10)
        
        # Load existing users
        self.load_users()
        
    def show_login(self):
        """Show login dialog and return success status"""
        print("Creating login window...")
        login_window = tk.Toplevel()  # Create independent window
        
        # Configure login window
        login_width = 300
        login_height = 200
        screen_width = login_window.winfo_screenwidth()
        screen_height = login_window.winfo_screenheight()
        x = (screen_width - login_width) // 2
        y = (screen_height - login_height) // 2
        login_window.geometry(f"{login_width}x{login_height}+{x}+{y}")
        
        # Set window properties
        login_window.title("Admin Login")
        login_window.resizable(False, False)
        login_window.attributes('-topmost', True)
        login_window.focus_force()
        
        # Configure window style
        login_window.protocol("WM_DELETE_WINDOW", lambda: login_window.destroy())
        
        # Create main container
        main_frame = ttk.Frame(login_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        ttk.Label(main_frame, text="Username:").pack(anchor="w")
        username = ttk.Entry(main_frame, width=30)
        username.pack(fill="x", pady=(0, 10))
        
        # Password
        ttk.Label(main_frame, text="Password:").pack(anchor="w")
        password = ttk.Entry(main_frame, show="*", width=30)
        password.pack(fill="x", pady=(0, 20))
        
        result = {'success': False}
        
        def try_login():
            try:
                response = requests.post(
                    f'{self.server_url}/login',
                    json={'username': username.get(), 'password': password.get()},
                    verify=False
                )
                if response.status_code == 200:
                    self.token = response.json()['token']
                    result['success'] = True
                    login_window.destroy()
                else:
                    messagebox.showerror("Error", "Invalid credentials")
            except Exception as e:
                messagebox.showerror("Error", f"Connection failed: {str(e)}")
        
        # Login button
        login_btn = ttk.Button(main_frame, text="Login", command=try_login)
        login_btn.pack(pady=10)
        
        # Bind Enter key
        login_window.bind('<Return>', lambda e: try_login())
        
        # Set initial focus
        username.focus_force()
        
        # Update window
        login_window.update_idletasks()
        
        # Wait for window
        login_window.wait_window()
        
        return result['success']

    def add_user(self):
        try:
            response = requests.post(
                f'{self.server_url}/users',
                headers={'Authorization': f'Bearer {self.token}'},
                json={
                    'username': self.username.get(),
                    'password': self.password.get(),
                    'admin': self.is_admin.get()
                },
                verify=False
            )
            if response.status_code == 200:
                messagebox.showinfo("Success", "User added successfully")
                self.load_users()
            else:
                messagebox.showerror("Error", response.json()['message'])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add user: {str(e)}")

    def load_users(self):
        try:
            response = requests.get(
                f'{self.server_url}/users',
                headers={'Authorization': f'Bearer {self.token}'},
                verify=False
            )
            if response.status_code == 200:
                users = response.json()
                self.tree.delete(*self.tree.get_children())
                for user in users:
                    self.tree.insert('', 'end', 
                                   values=(user['username'], 
                                         'Yes' if user['admin'] else 'No'))
            else:
                messagebox.showerror("Error", response.json()['message'])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load users: {str(e)}")
    
    def delete_user(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user to delete")
            return
            
        username = self.tree.item(selected[0])['values'][0]
        
        if messagebox.askyesno("Confirm", f"Delete user {username}?"):
            try:
                response = requests.delete(
                    f'{self.server_url}/users/{username}',
                    headers={'Authorization': f'Bearer {self.token}'},
                    verify=False
                )
                if response.status_code == 200:
                    messagebox.showinfo("Success", "User deleted successfully")
                    self.load_users()
                else:
                    messagebox.showerror("Error", response.json()['message'])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete user: {str(e)}")

    @staticmethod
    def verify_credentials(username, password):
        try:
            # Decrypt database for verification
            if os.path.exists('users.db.encrypted'):
                with open('key.key', 'rb') as key_file:
                    key = key_file.read()
                decrypt_file('users.db', key)
            
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                     (username, hashed_password))
            
            result = c.fetchone() is not None
            conn.close()
            
            if os.path.exists('users.db'):
                # Re-encrypt database only if decryption happened
                if os.path.exists('users.db.encrypted'):
                    with open('key.key', 'rb') as key_file:
                        key = key_file.read()
                    encrypt_file('users.db', key)
                    os.remove('users.db')  # Remove decrypted file
                    
            return result
        except Exception as e:
            print(f"Error verifying credentials: {str(e)}")
            return False

if __name__ == "__main__":
    try:
        print("Starting Admin Tool...")
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        # Force update
        root.update_idletasks()
        
        print("Creating admin tool instance...")
        app = AdminTool(root)
        
        print("Starting mainloop...")
        root.mainloop()
    except Exception as e:
        print(f"Error starting application: {str(e)}")
        import traceback
        traceback.print_exc()