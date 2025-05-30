import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import requests
import time
from typing import List, Dict, Optional
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from functools import lru_cache
import queue
import sqlite3
import hashlib
from functools import wraps
from db_crypto import decrypt_file, encrypt_file
import os

class ProxyCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Proxy Checker Tool")
        
        # Hide main window initially
        self.root.withdraw()
        
        # Initialize components
        self.session = self._create_session()
        self.proxy_cache = {}
        self.cache_duration = 300
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.log_queue = queue.Queue()
        self.stop_requested = False
        self.tooltip = None

        try:
            self.root.iconbitmap('assets/app_icon.ico')
        except tk.TclError:
            print("Warning: Could not load application icon")

        # Show login window
        print("Creating login window")
        login = LoginWindow(root)
        root.wait_window(login.window)
        
        if not login.result:
            print("Login failed or cancelled")
            root.quit()
            return
        
        print("Login successful, setting up main window")
        
        # Setup main window
        self.root.deiconify()  # Show main window
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.minsize(700, 700)
        
        # Add scrollbar for the entire window
        container = ttk.Frame(self.root, borderwidth=0)  # Remove border
        container.grid(row=0, column=0, sticky="nsew")
        
        # Create canvas with scrollbar
        canvas = tk.Canvas(container, borderwidth=0, highlightthickness=0)  # Remove canvas border
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas, borderwidth=0)  # Remove frame border
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Add mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar components
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Initialize session with connection pooling
        self.session = self._create_session()
        
        # Cache for working proxies
        self.proxy_cache: Dict[str, tuple[bool, float]] = {}
        self.cache_duration = 300  # 5 minutes
        
        # Thread pool for concurrent operations
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Queue for thread-safe result logging
        self.log_queue = queue.Queue()
        
        # Stop flag for checking process
        self.stop_requested = False
        
        # Tooltip reference
        self.tooltip = None
        
        self.setup_ui()
        self.start_log_consumer()
        
        # Finally show the main window
        self.root.deiconify()

    def _create_session(self) -> requests.Session:
        """Create a session with connection pooling and retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=retry_strategy
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def setup_ui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)  # Remove padding here
        
        # Main tab
        main_tab = ttk.Frame(self.notebook)  # Remove padding here
        self.notebook.add(main_tab, text="Proxy Checker")
        
        # Logs tab
        logs_tab = ttk.Frame(self.notebook)  # Remove padding here
        self.notebook.add(logs_tab, text="Logs")
        
        # Setup main tab contents
        main_container = ttk.Frame(main_tab, padding=(5, 5, 5, 5))  # Add consistent padding here
        main_container.pack(fill=tk.BOTH, expand=True)

        # Input Frame
        input_frame = ttk.LabelFrame(main_container, text="Credentials Input", padding="5")
        input_frame.pack(fill=tk.X, pady=(0, 5))

        # Add help icon and tooltip
        help_text = "Format: email|password|ip|port|optional_fields"
        help_frame = ttk.Frame(input_frame)
        help_frame.pack(fill=tk.X)
        ttk.Label(help_frame, text="Input Credentials").pack(side=tk.LEFT)
        help_btn = ttk.Label(help_frame, text="(?)")
        help_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(help_btn, help_text)

        self.input_text = scrolledtext.ScrolledText(input_frame, width=80, height=10)
        self.input_text.pack(fill=tk.X, pady=5)

        # Input controls
        input_controls = ttk.Frame(input_frame)
        input_controls.pack(fill=tk.X)
        ttk.Button(input_controls, text="Clear Input", 
                   command=lambda: self.input_text.delete('1.0', tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_controls, text="Load File", 
                   command=self.load_input_file).pack(side=tk.LEFT, padx=5)

        # Proxy List Frame
        proxy_frame = ttk.LabelFrame(main_container, text="Proxy List", padding="5")
        proxy_frame.pack(fill=tk.X, pady=5)

        proxy_help = ttk.Frame(proxy_frame)
        proxy_help.pack(fill=tk.X)
        ttk.Label(proxy_help, text="Proxy IPs (one per line)").pack(side=tk.LEFT)
        proxy_help_btn = ttk.Label(proxy_help, text="(?)")
        proxy_help_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(proxy_help_btn, "Enter proxy IPs, port 3128 will be used")

        self.proxy_list_text = scrolledtext.ScrolledText(proxy_frame, width=80, height=5)
        self.proxy_list_text.pack(fill=tk.X, pady=5)

        # Proxy controls
        proxy_controls = ttk.Frame(proxy_frame)
        proxy_controls.pack(fill=tk.X)
        ttk.Button(proxy_controls, text="Clear Proxies", 
                   command=lambda: self.proxy_list_text.delete('1.0', tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(proxy_controls, text="Load Proxies", 
                   command=self.load_proxy_file).pack(side=tk.LEFT, padx=5)

        # Control Frame
        control_frame = ttk.Frame(main_container)
        control_frame.pack(fill=tk.X, pady=5)

        self.run_button = ttk.Button(control_frame, text="Start Checking", command=self.start_check)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_check, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Progress Frame
        progress_frame = ttk.LabelFrame(main_container, text="Progress", padding="5")
        progress_frame.pack(fill=tk.X, pady=5)

        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress.pack(fill=tk.X, pady=5)
        self.progress_label = ttk.Label(progress_frame, text="Ready")
        self.progress_label.pack()

        # Results Frame
        results_frame = ttk.LabelFrame(main_container, text="Results", padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.results_text = scrolledtext.ScrolledText(results_frame, width=80, height=10, state='disabled')
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Results controls
        results_controls = ttk.Frame(results_frame)
        results_controls.pack(fill=tk.X)
        ttk.Button(results_controls, text="Clear Results", 
                   command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(results_controls, text="Save Results", 
                   command=self.save_results).pack(side=tk.LEFT, padx=5)

        # Setup logs tab with consistent padding
        log_frame = ttk.LabelFrame(logs_tab, text="Proxy Change History", padding=(5, 5, 5, 5))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.change_log_text = scrolledtext.ScrolledText(log_frame, width=80, height=20, state='disabled')
        self.change_log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Add clear logs button
        ttk.Button(log_frame, text="Clear Logs", 
                   command=self.clear_change_logs).pack(side=tk.LEFT, padx=5)

    @lru_cache(maxsize=1000)
    def test_proxy(self, proxy_str: str) -> bool:
        """Test proxy with caching"""
        # Check cache first
        if proxy_str in self.proxy_cache:
            success, timestamp = self.proxy_cache[proxy_str]
            if time.time() - timestamp < self.cache_duration:
                return success

        proxy_conf = {
            "http": f"http://{proxy_str}",
            "https": f"http://{proxy_str}"
        }
        try:
            self.session.get(
                'https://httpbin.org/ip',
                proxies=proxy_conf,
                timeout=5
            )
            self.proxy_cache[proxy_str] = (True, time.time())
            return True
        except requests.RequestException:
            self.proxy_cache[proxy_str] = (False, time.time())
            return False

    def check_proxies_concurrent(self, ip_list: List[str], exclude_ip: str = None) -> Optional[str]:
        """Check multiple proxies concurrently, excluding the specified IP"""
        # Filter out the excluded IP and any previously used IPs
        available_ips = [ip for ip in ip_list if ip != exclude_ip]
        random.shuffle(available_ips)  # Randomize the order
        
        futures = []
        for ip in available_ips:
            proxy_str = f"{ip}:3128"
            futures.append(
                self.executor.submit(self.test_proxy, proxy_str)
            )
            
        for future, ip in zip(as_completed(futures), available_ips):
            try:
                if future.result():
                    return ip
            except Exception:
                continue
        return None

    def check_all(self):
        try:
            self.stop_requested = False
            self.stop_button.config(state=tk.NORMAL)
            inputs = [line.strip() for line in self.input_text.get('1.0', 'end').splitlines() if line.strip()]
            proxy_ips = [line.strip() for line in self.proxy_list_text.get('1.0', 'end').splitlines() if line.strip()]
            
            if not inputs or not proxy_ips:
                messagebox.showerror("Error", "Please provide both credentials and proxy list")
                return
                
            random.shuffle(proxy_ips)
            total = len(inputs)
            
            # Process entries in chunks while maintaining order
            chunk_size = 10
            for i in range(0, len(inputs), chunk_size):
                if self.stop_requested:
                    self.log_queue.put("Process stopped by user")
                    break
                chunk = inputs[i:i + chunk_size]
                futures = {}  # Use dict to maintain order
                
                for entry in chunk:
                    future = self.executor.submit(self.process_entry, entry, proxy_ips)
                    futures[future] = entry  # Map future to original entry
                
                # Process results in order
                for future in futures:
                    try:
                        result = future.result()
                        if result:
                            self.log_queue.put(result)
                    except Exception as e:
                        self.log_queue.put(f"Error processing entry: {str(e)}")
                
                # Update progress
                self.progress_var.set((i + len(chunk)) / total * 100)
                self.progress_label.config(text=f"Processing {i + len(chunk)}/{total} entries...")
                
        finally:
            self.run_button.config(state='normal')
            self.stop_button.config(state=tk.DISABLED)
            self.progress_label.config(text="Complete" if not self.stop_requested else "Stopped")

    def process_entry(self, entry: str, proxy_ips: List[str]) -> str:
        """Process a single entry"""
        parts = entry.split('|')
        if len(parts) < 4:
            return f"Invalid entry format: {entry}"
            
        email, pwd, ip, port, *rest = parts
        original = f"{ip}:3128"
        
        if self.test_proxy(original):
            return entry
        
        new_ip = self.check_proxies_concurrent(proxy_ips, exclude_ip=ip)
        if new_ip:
            changed_proxy = f"{email}|{pwd}|{new_ip}|3128|" + '|'.join(rest)
            self.log_proxy_change(ip, new_ip)  # Log the proxy change
            return changed_proxy
        return f"{email}|{pwd}|NO_WORKING_PROXY|" + '|'.join(rest)

    def start_log_consumer(self):
        """Start consumer thread for log messages"""
        def consumer():
            while True:
                try:
                    message = self.log_queue.get(timeout=0.1)
                    self.log_result(message)
                except queue.Empty:
                    continue
                
        threading.Thread(target=consumer, daemon=True).start()

    def start_check(self):
        """Start the checking process"""
        self.clear_results()  # Clear results before starting new check
        self.run_button.config(state='disabled')
        self.progress_var.set(0)
        threading.Thread(target=self.check_all, daemon=True).start()

    def log_result(self, message):
        self.results_text.config(state='normal')
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state='disabled')

    def create_tooltip(self, widget, text):
        """Create a tooltip for a given widget."""
        def enter(event):
            self.tooltip = tk.Toplevel()
            self.tooltip.wm_overrideredirect(True)
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 20
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = ttk.Label(self.tooltip, text=text, justify=tk.LEFT,
                             background="#ffffe0", relief=tk.SOLID, borderwidth=1)
            label.pack()
            
        def leave(event):
            if hasattr(self, 'tooltip'):
                self.tooltip.destroy()
                
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    def load_input_file(self):
        """Load input credentials from a file."""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            try:
                with open(filename, 'r') as file:
                    self.input_text.delete('1.0', tk.END)
                    self.input_text.insert('1.0', file.read())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def load_proxy_file(self):
        """Load proxy list from a file."""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            try:
                with open(filename, 'r') as file:
                    self.proxy_list_text.delete('1.0', tk.END)
                    self.proxy_list_text.insert('1.0', file.read())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def save_results(self):
        """Save results to a file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            try:
                with open(filename, 'w') as file:
                    file.write(self.results_text.get('1.0', tk.END))
                messagebox.showinfo("Success", "Results saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def clear_results(self):
        """Clear the results text area."""
        self.results_text.config(state='normal')
        self.results_text.delete('1.0', tk.END)
        self.results_text.config(state='disabled')
        self.progress_var.set(0)
        self.progress_label.config(text="Ready")

    def stop_check(self):
        """Stop the checking process."""
        self.stop_requested = True
        self.stop_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Stopping...")

    def log_proxy_change(self, old_ip: str, new_ip: str):
        """Log proxy changes"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] Changed proxy: {old_ip} → {new_ip}\n"
        self.change_log_text.config(state='normal')
        self.change_log_text.insert(tk.END, log_entry)
        self.change_log_text.see(tk.END)
        self.change_log_text.config(state='disabled')

    def clear_change_logs(self):
        """Clear the change logs"""
        self.change_log_text.config(state='normal')
        self.change_log_text.delete('1.0', tk.END)
        self.change_log_text.config(state='disabled')

class LoginWindow:
    def __init__(self, parent):
        print("Initializing login window")
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title("Login")
        self.window.geometry("300x220")  # Increased height for better spacing
        self.window.resizable(False, False)
        
        # Center window
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        x = (screen_width - 300) // 2
        y = (screen_height - 220) // 2
        self.window.geometry(f"+{x}+{y}")
        
        # Force window to stay on top
        self.window.attributes('-topmost', True)
        self.window.focus_force()
        
        # Main container frame
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        ttk.Label(main_frame, text="Username:").pack(pady=5, anchor="w")
        self.username = ttk.Entry(main_frame, width=30)
        self.username.pack(pady=5, fill="x")
        
        # Password
        ttk.Label(main_frame, text="Password:").pack(pady=5, anchor="w")
        self.password = ttk.Entry(main_frame, show="*", width=30)
        self.password.pack(pady=5, fill="x")
        
        # Login button in its own frame for better positioning
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=15, fill="x")
        
        login_btn = ttk.Button(btn_frame, text="Login", command=self.login)
        login_btn.pack(expand=True)
        
        # Bind Enter key to login
        self.window.bind('<Return>', lambda e: self.login())
        
        self.result = False
        
        # Focus username entry
        self.username.focus()
        self.server_url = 'https://your-app-name.up.railway.app'

    def login(self):
        username = self.username.get()
        password = self.password.get()
        
        if self.verify_credentials(username, password):
            self.result = True
            self.window.destroy()
        else:
            messagebox.showerror("Error", "Invalid credentials")
    
    def verify_credentials(self, username, password):
        try:
            response = requests.post(
                f'{self.server_url}/login',
                json={'username': username, 'password': password},
                verify=False
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Error verifying credentials: {str(e)}")
            return False
