# === SECURE SERVER SIDE (FIXED VERSION) ===
import socket
import threading
import json
import hashlib
import os
import sqlite3
import secrets
import time
from datetime import datetime
from contextlib import contextmanager

# Global variables
clients = {}  # socket: username
public_keys = {}  # username: public_key
db_lock = threading.Lock()  # Thread-safe database operations

# === SQLite DB Setup ===
db_file = 'users.db'
os.makedirs("db", exist_ok=True)

# Thread-local storage for database connections
thread_local = threading.local()

def get_db_connection():
    """Get thread-local database connection"""
    if not hasattr(thread_local, 'connection'):
        thread_local.connection = sqlite3.connect(f"db/{db_file}", check_same_thread=False)
        thread_local.connection.execute("PRAGMA foreign_keys = ON")
    return thread_local.connection

@contextmanager
def get_db_cursor():
    """Context manager for database operations"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()

def init_database():
    """Initialize the database with proper schema"""
    with get_db_cursor() as cursor:
        # Create users table with salt for additional security
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """)
        
        # Create login attempts table for rate limiting
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address TEXT,
            username TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN
        )
        """)
    print("[i] Database initialized successfully")

def generate_salt():
    """Generate a random salt for password hashing"""
    return secrets.token_hex(32)

def hash_password_with_salt(password, salt):
    """Hash password with salt using PBKDF2 (more secure than simple SHA256)"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash"""
    return hash_password_with_salt(password, salt) == stored_hash

def check_rate_limit(ip_address, username):
    """Check if user/IP has exceeded login attempts"""
    try:
        with get_db_cursor() as cursor:
            # Check failed attempts in last 15 minutes
            cursor.execute("""
            SELECT COUNT(*) FROM login_attempts 
            WHERE (ip_address = ? OR username = ?) 
            AND success = 0 
            AND datetime(attempt_time) > datetime('now', '-15 minutes')
            """, (ip_address, username))
            
            failed_attempts = cursor.fetchone()[0]
            return failed_attempts < 5  # Allow max 5 failed attempts per 15 minutes
    except Exception as e:
        print(f"[!] Error checking rate limit: {e}")
        return True  # Allow on error to avoid blocking legitimate users

def log_login_attempt(ip_address, username, success):
    """Log login attempt for rate limiting"""
    try:
        with get_db_cursor() as cursor:
            cursor.execute("""
            INSERT INTO login_attempts (ip_address, username, success) 
            VALUES (?, ?, ?)
            """, (ip_address, username, success))
    except Exception as e:
        print(f"[!] Error logging login attempt: {e}")

def authenticate_user(username, password, ip_address):
    """
    Authenticate user credentials
    Returns: (success: bool, message: str, is_new_user: bool)
    """
    
    # Check rate limiting first
    if not check_rate_limit(ip_address, username):
        return False, "Too many failed attempts. Try again later.", False
    
    # Input validation
    if not username or not password:
        return False, "Username and password required.", False
    
    if len(username) > 50 or len(password) > 128:
        return False, "Username or password too long.", False
    
    # Check for invalid characters in username
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, underscores, and hyphens.", False
    
    with db_lock:
        try:
            with get_db_cursor() as cursor:
                # Check if user exists
                cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                
                if row:
                    # Existing user - verify password
                    stored_hash, salt = row
                    
                    if verify_password(password, stored_hash, salt):
                        # Update last login time
                        cursor.execute("""
                        UPDATE users SET last_login = CURRENT_TIMESTAMP 
                        WHERE username = ?
                        """, (username,))
                        
                        log_login_attempt(ip_address, username, True)
                        return True, "Login successful.", False
                    else:
                        log_login_attempt(ip_address, username, False)
                        return False, "Invalid password.", False
                else:
                    # New user - create account
                    salt = generate_salt()
                    password_hash = hash_password_with_salt(password, salt)
                    
                    cursor.execute("""
                    INSERT INTO users (username, password_hash, salt) 
                    VALUES (?, ?, ?)
                    """, (username, password_hash, salt))
                    
                    log_login_attempt(ip_address, username, True)
                    return True, "Account created successfully.", True
                    
        except sqlite3.IntegrityError:
            # Handle race condition where user was created between check and insert
            log_login_attempt(ip_address, username, False)
            return False, "Username already exists.", False
        except Exception as e:
            print(f"[!] Database error during authentication: {e}")
            return False, "Database error occurred.", False

def broadcast_public_keys():
    """Broadcast the list of connected users and their public keys"""
    payload = {
        "type": "peer_list",
        "peers": [
            {"username": user, "public_key": key}
            for user, key in public_keys.items()
        ]
    }
    message = json.dumps(payload).encode()
    
    # Send to all connected clients
    disconnected_clients = []
    for client in list(clients.keys()):
        try:
            client.sendall(message)
        except Exception as e:
            print(f"[!] Failed to send peer list to {clients.get(client, 'unknown')}: {e}")
            disconnected_clients.append(client)
    
    # Clean up disconnected clients
    for client in disconnected_clients:
        cleanup_client(client)

def cleanup_client(client_socket):
    """Clean up client data when they disconnect"""
    if client_socket in clients:
        username = clients[client_socket]
        print(f"[-] {username} disconnected.")
        
        # Remove from tracking dictionaries
        del clients[client_socket]
        if username in public_keys:
            del public_keys[username]
        
        try:
            client_socket.close()
        except:
            pass
        
        # Broadcast updated peer list
        broadcast_public_keys()

def handle_client(client_socket, client_address):
    """Handle individual client connection"""
    username = None
    ip_address = client_address[0]
    
    try:
        print(f"[~] New connection from {client_address}")
        
        # Set socket timeout for authentication phase
        client_socket.settimeout(30)
        
        # Receive authentication data
        auth_data = client_socket.recv(4096)
        if not auth_data:
            print(f"[!] No auth data received from {client_address}")
            return
            
        try:
            auth_payload = json.loads(auth_data.decode())
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON from {client_address}")
            client_socket.sendall(json.dumps({
                "type": "auth_result", 
                "status": "error",
                "message": "Invalid data format"
            }).encode())
            return
        
        # Extract authentication information
        username = auth_payload.get("username", "").strip()
        password = auth_payload.get("auth", "")
        public_key = auth_payload.get("public_key", "")
        
        if not all([username, password, public_key]):
            client_socket.sendall(json.dumps({
                "type": "auth_result",
                "status": "error", 
                "message": "Missing required fields"
            }).encode())
            return
        
        # Check if username is already connected
        if username in public_keys:
            client_socket.sendall(json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "User already connected"
            }).encode())
            return
        
        # Authenticate user
        success, message, is_new_user = authenticate_user(username, password, ip_address)
        
        if success:
            # Authentication successful
            status = "new_user" if is_new_user else "success"
            response = {
                "type": "auth_result",
                "status": status,
                "message": message
            }
            client_socket.sendall(json.dumps(response).encode())
            
            # Remove timeout for normal operation
            client_socket.settimeout(None)
            
            # Add client to active connections
            clients[client_socket] = username
            public_keys[username] = public_key
            
            print(f"[+] {username} {'(new user)' if is_new_user else '(existing user)'} connected from {client_address}")
            
            # Broadcast updated peer list
            broadcast_public_keys()
            
            # Handle ongoing messages
            while True:
                try:
                    msg = client_socket.recv(8192)
                    if not msg:
                        break
                    
                    # Relay message to all other clients
                    disconnected_clients = []
                    for sock in list(clients.keys()):
                        if sock != client_socket:
                            try:
                                sock.sendall(msg)
                            except Exception as e:
                                print(f"[!] Failed to relay message to {clients.get(sock, 'unknown')}: {e}")
                                disconnected_clients.append(sock)
                    
                    # Clean up any disconnected clients
                    for sock in disconnected_clients:
                        cleanup_client(sock)
                        
                except Exception as e:
                    print(f"[!] Error handling message from {username}: {e}")
                    break
        else:
            # Authentication failed
            response = {
                "type": "auth_result",
                "status": "fail",
                "message": message
            }
            client_socket.sendall(json.dumps(response).encode())
            print(f"[!] Authentication failed for {username} from {client_address}: {message}")
            
    except socket.timeout:
        print(f"[!] Authentication timeout for {client_address}")
    except Exception as e:
        print(f"[!] Error with client {client_address}: {e}")
    finally:
        cleanup_client(client_socket)

def periodic_cleanup():
    """Periodic cleanup function that runs every hour"""
    while True:
        try:
            time.sleep(3600)  # Wait 1 hour
            cleanup_old_login_attempts()
        except Exception as e:
            print(f"[!] Cleanup thread error: {e}")

def cleanup_old_login_attempts():
    """Clean up old login attempts (run periodically)"""
    try:
        with get_db_cursor() as cursor:
            cursor.execute("""
            DELETE FROM login_attempts 
            WHERE datetime(attempt_time) < datetime('now', '-1 day')
            """)
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                print(f"[i] Cleaned up {deleted_count} old login attempts")
    except Exception as e:
        print(f"[!] Error during cleanup: {e}")

def start_server(host='0.0.0.0', port=5000):
    """Start the chat server"""
    # Initialize database first
    init_database()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((host, port))
        server.listen(10)
        print(f"[+] 🔐 Secure Chat Server started on {host}:{port}")
        print(f"[i] Database: db/{db_file}")
        print(f"[i] Security features: Password hashing, Rate limiting, Input validation")
        
        # Start cleanup thread properly
        cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
        cleanup_thread.start()
        
        while True:
            try:
                client_socket, client_address = server.accept()
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except KeyboardInterrupt:
                print("\n[!] Server shutting down...")
                break
            except Exception as e:
                print(f"[!] Error accepting connection: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start server: {e}")
    finally:
        server.close()
        print("[i] Server stopped.")
        
        # Close all client connections
        for client_socket in list(clients.keys()):
            cleanup_client(client_socket)

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[!] Server interrupted by user")
    except Exception as e:
        print(f"[!] Server error: {e}")