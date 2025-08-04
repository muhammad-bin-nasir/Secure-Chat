# railway_server.py
# Modified version of your server for Railway deployment

import socket
import threading
import json
import hashlib
import time
import os
from datetime import datetime, timedelta

# Get port from environment (Railway sets this)
PORT = int(os.environ.get("PORT", 5000))
HOST = '0.0.0.0'  # Must be 0.0.0.0 for Railway

MAX_CLIENTS = 50
BUFFER_SIZE = 16384

# Client storage
clients = {}
client_usernames = {}
username_to_socket = {}

# User authentication
user_database = {}

# Rate limiting
connection_attempts = {}
MAX_ATTEMPTS_PER_IP = 5
RATE_LIMIT_WINDOW = timedelta(minutes=15)

def hash_password(password):
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()

def check_rate_limit(client_ip):
    """Check if IP is rate limited"""
    now = datetime.now()
    
    if client_ip in connection_attempts:
        attempt_info = connection_attempts[client_ip]
        
        if now - attempt_info["last_attempt"] > RATE_LIMIT_WINDOW:
            connection_attempts[client_ip] = {"count": 1, "last_attempt": now}
            return True
        
        if attempt_info["count"] >= MAX_ATTEMPTS_PER_IP:
            return False
        
        connection_attempts[client_ip]["count"] += 1
        connection_attempts[client_ip]["last_attempt"] = now
        return True
    else:
        connection_attempts[client_ip] = {"count": 1, "last_attempt": now}
        return True

def authenticate_user(username, password, public_key):
    """Authenticate user or create new account"""
    if not username or not password or not public_key:
        return {"status": "fail", "message": "Missing credentials"}
    
    if len(username) > 50 or not username.replace('_', '').replace('-', '').isalnum():
        return {"status": "fail", "message": "Invalid username format"}
    
    if len(password) > 128:
        return {"status": "fail", "message": "Password too long"}
    
    password_hash = hash_password(password)
    
    if username in user_database:
        if user_database[username]["password_hash"] == password_hash:
            user_database[username]["public_key"] = public_key
            user_database[username]["last_login"] = datetime.now()
            return {"status": "success", "message": "Welcome back!"}
        else:
            return {"status": "fail", "message": "Invalid password"}
    else:
        user_database[username] = {
            "password_hash": password_hash,
            "public_key": public_key,
            "last_login": datetime.now()
        }
        return {"status": "new_user", "message": "Account created successfully!"}

def broadcast_peer_list():
    """Send updated peer list to all authenticated clients"""
    peer_list = []
    for sock, username in client_usernames.items():
        if username in user_database:
            peer_list.append({
                "username": username,
                "public_key": user_database[username]["public_key"]
            })
    
    peer_message = {
        "type": "peer_list",
        "peers": peer_list
    }
    
    message_data = json.dumps(peer_message).encode()
    
    disconnected_clients = []
    for client_socket in client_usernames.keys():
        try:
            client_socket.sendall(message_data)
        except:
            disconnected_clients.append(client_socket)
    
    for client_socket in disconnected_clients:
        remove_client(client_socket)

def remove_client(client_socket):
    """Remove client from all tracking structures"""
    try:
        if client_socket in client_usernames:
            username = client_usernames[client_socket]
            del client_usernames[client_socket]
            
            if username in username_to_socket:
                del username_to_socket[username]
            
            print(f"[-] User {username} disconnected")
        
        if client_socket in clients:
            del clients[client_socket]
        
        client_socket.close()
        
        if client_usernames:
            broadcast_peer_list()
            
    except Exception as e:
        print(f"[!] Error removing client: {e}")

def handle_client(client_socket, client_address):
    """Handle individual client connection"""
    print(f"[+] New connection from {client_address}")
    
    client_ip = client_address[0]
    if not check_rate_limit(client_ip):
        print(f"[!] Rate limit exceeded for {client_ip}")
        try:
            client_socket.sendall(json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Too many connection attempts. Please try again later."
            }).encode())
            client_socket.close()
        except:
            pass
        return
    
    clients[client_socket] = {
        "address": client_address,
        "authenticated": False,
        "username": None
    }
    
    try:
        client_socket.settimeout(30)
        auth_data = client_socket.recv(BUFFER_SIZE)
        
        if not auth_data:
            print(f"[!] No auth data received from {client_address}")
            return
        
        try:
            auth_payload = json.loads(auth_data.decode())
            username = auth_payload.get("username", "").strip()
            password = auth_payload.get("auth", "")
            public_key = auth_payload.get("public_key", "")
            
            auth_result = authenticate_user(username, password, public_key)
            
            client_socket.sendall(json.dumps({
                "type": "auth_result",
                **auth_result
            }).encode())
            
            if auth_result["status"] in ["success", "new_user"]:
                clients[client_socket]["authenticated"] = True
                clients[client_socket]["username"] = username
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                print(f"[+] User {username} authenticated from {client_address}")
                
                client_socket.settimeout(None)
                broadcast_peer_list()
                handle_authenticated_client(client_socket, username)
            else:
                print(f"[!] Authentication failed for {client_address}: {auth_result['message']}")
                return
                
        except json.JSONDecodeError:
            print(f"[!] Invalid auth data format from {client_address}")
            client_socket.sendall(json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Invalid authentication data format"
            }).encode())
            return
        except Exception as e:
            print(f"[!] Auth error for {client_address}: {e}")
            client_socket.sendall(json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Authentication error"
            }).encode())
            return
            
    except socket.timeout:
        print(f"[!] Authentication timeout for {client_address}")
    except Exception as e:
        print(f"[!] Client handling error for {client_address}: {e}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client"""
    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break
            
            try:
                message = json.loads(data.decode())
                route_message(client_socket, username, message)
            except json.JSONDecodeError:
                print(f"[!] Invalid message format from {username}")
                continue
            except Exception as e:
                print(f"[!] Message processing error from {username}: {e}")
                continue
                
    except Exception as e:
        print(f"[!] Connection error with {username}: {e}")

def route_message(sender_socket, sender_username, message):
    """Route message to appropriate recipient"""
    msg_type = message.get("type")
    recipient = message.get("to")
    
    if not recipient:
        print(f"[!] No recipient specified in message from {sender_username}")
        return
    
    recipient_socket = username_to_socket.get(recipient)
    if not recipient_socket:
        print(f"[!] Recipient {recipient} not found for message from {sender_username}")
        return
    
    try:
        recipient_socket.sendall(json.dumps(message).encode())
        
        if msg_type == "message":
            print(f"[MSG] {sender_username} -> {recipient}: [encrypted message]")
        elif msg_type == "key_exchange":
            print(f"[KEY] {sender_username} -> {recipient}: Key exchange")
        elif msg_type == "file_header":
            filename = message.get("filename", "unknown")
            filesize = message.get("filesize", 0)
            print(f"[FILE] {sender_username} -> {recipient}: Starting file '{filename}' ({filesize} bytes)")
        elif msg_type == "file_chunk":
            print(f"[FILE] {sender_username} -> {recipient}: File chunk")
        elif msg_type == "file_end":
            filename = message.get("filename", "unknown")
            print(f"[FILE] {sender_username} -> {recipient}: File '{filename}' completed")
        else:
            print(f"[?] {sender_username} -> {recipient}: {msg_type}")
            
    except Exception as e:
        print(f"[!] Failed to forward message from {sender_username} to {recipient}: {e}")
        if recipient_socket in client_usernames:
            remove_client(recipient_socket)

def cleanup_old_rate_limits():
    """Clean up old rate limit entries"""
    while True:
        try:
            now = datetime.now()
            expired_ips = []
            
            for ip, attempt_info in connection_attempts.items():
                if now - attempt_info["last_attempt"] > RATE_LIMIT_WINDOW:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del connection_attempts[ip]
            
            time.sleep(300)
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
            time.sleep(60)

def print_server_stats():
    """Print server statistics periodically"""
    while True:
        try:
            time.sleep(60)
            connected_users = len(client_usernames)
            total_users = len(user_database)
            rate_limited_ips = len(connection_attempts)
            
            print(f"[STATS] Connected: {connected_users}, Total users: {total_users}, Rate-limited IPs: {rate_limited_ips}")
            
            if connected_users > 0:
                usernames = list(client_usernames.values())
                print(f"[STATS] Online users: {', '.join(usernames)}")
                
        except Exception as e:
            print(f"[!] Stats error: {e}")

def start_server():
    """Start the secure chat server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        print(f"[*] 🔐 Secure Chat Server with File Transfer")
        print(f"[*] Listening on {HOST}:{PORT}")
        print(f"[*] Max clients: {MAX_CLIENTS}")
        print(f"[*] Buffer size: {BUFFER_SIZE} bytes")
        print(f"[*] Server started at {datetime.now()}")
        print("-" * 50)
        
        threading.Thread(target=cleanup_old_rate_limits, daemon=True).start()
        threading.Thread(target=print_server_stats, daemon=True).start()
        
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                
                if len(clients) >= MAX_CLIENTS:
                    print(f"[!] Server at capacity, rejecting {client_address}")
                    try:
                        client_socket.sendall(json.dumps({
                            "type": "auth_result",
                            "status": "error",
                            "message": "Server at capacity. Please try again later."
                        }).encode())
                        client_socket.close()
                    except:
                        pass
                    continue
                
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                print(f"[!] Error accepting connection: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\n[*] Server shutdown requested")
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        print("[*] Closing server...")
        
        for client_socket in list(clients.keys()):
            try:
                client_socket.close()
            except:
                pass
        
        server_socket.close()
        print("[*] Server closed")

if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        print(f"[!] Fatal server error: {e}")
        import traceback
        traceback.print_exc()
