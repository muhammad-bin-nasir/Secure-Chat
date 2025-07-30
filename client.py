# ===🔐 Encrypted Chat - Updated for Secure Server===
import time
import sys
import threading
import socket
import json
import base64
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QListWidget, QComboBox, QMessageBox, QInputDialog
)

from PyQt5.QtCore import Qt, pyqtSignal, QObject
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import sys
import traceback

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    print("[!!] Uncaught exception:", "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))

sys.excepthook = handle_exception

# ===🔐 Generate RSA Keys for Each Client===
key_pair = RSA.generate(2048)
public_key = key_pair.publickey().export_key()
private_key = key_pair.export_key()

peer_public_keys = {}   # username -> public key string
peer_key_hashes = {}    # username -> SHA256 hash
aes_session_keys = {}   # username -> AES session key

# ===🔐 Crypto Helpers===
def sha256_digest(data):
    return hashlib.sha256(data).hexdigest()

def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt(key, enc_data):
    try:
        nonce = base64.b64decode(enc_data["nonce"])
        ciphertext = base64.b64decode(enc_data["ciphertext"])
        tag = base64.b64decode(enc_data["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except:
        return "[Decryption failed]"

def rsa_encrypt(pub_key_str, secret_key):
    peer_key = RSA.import_key(pub_key_str)
    cipher_rsa = PKCS1_OAEP.new(peer_key)
    return base64.b64encode(cipher_rsa.encrypt(secret_key)).decode()

def rsa_decrypt(encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher_rsa.decrypt(base64.b64decode(encrypted_key))

# ===🔁 PyQt5 Signal Bridge===
class Communicator(QObject):
    message_received = pyqtSignal(str, str)
    peer_list_updated = pyqtSignal(list)

# ===📡 Chat Client Class===
class ChatClient(QWidget):
    message_signal = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Encrypted Chat - Secure Edition")
        self.resize(800, 600)
        self.message_signal.connect(self.display_system_message)
        self.comm = Communicator()
        self.comm.message_received.connect(self.display_message)
        self.comm.peer_list_updated.connect(self.update_peer_list)

        # Server mode variables
        self.server_sock = None
        
        # P2P mode variables
        self.p2p_socket = None
        self.p2p_listener = None
        self.p2p_connected = False
        self.connection_lock = threading.Lock()
        
        self.username = ""
        self.peers = []
        self.p2p_mode = False
        self.peer_ip = None
        self.public_key = public_key.decode()

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        top_bar = QHBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Your username")
        self.server_ip_input = QLineEdit("127.0.0.1")
        self.remote_port_input = QLineEdit("5000")  # Changed default to match server
        self.local_port_input = QLineEdit("6001")
        self.remote_port_input.setFixedWidth(60)
        self.local_port_input.setFixedWidth(60)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.choose_connection_type)

        top_bar.addWidget(QLabel("Connect Port:"))
        top_bar.addWidget(self.remote_port_input)
        top_bar.addWidget(QLabel("Listen Port:"))
        top_bar.addWidget(self.local_port_input)
        top_bar.addWidget(QLabel("Username:"))
        top_bar.addWidget(self.username_input)
        top_bar.addWidget(QLabel("Server/Peer IP:"))
        top_bar.addWidget(self.server_ip_input)
        top_bar.addWidget(self.connect_btn)

        layout.addLayout(top_bar)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        mid_bar = QHBoxLayout()
        self.peers_list = QListWidget()
        self.peers_list.setFixedWidth(150)
        mid_bar.addWidget(self.peers_list)

        right_side = QVBoxLayout()
        self.encryption_select = QComboBox()
        self.encryption_select.addItems(["AES (with RSA)"])
        self.message_input = QLineEdit()
        self.message_input.returnPressed.connect(self.send_message)
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)

        right_side.addWidget(QLabel("Encryption Method:"))
        right_side.addWidget(self.encryption_select)
        right_side.addWidget(self.message_input)
        right_side.addWidget(self.send_btn)
        mid_bar.addLayout(right_side)
        layout.addLayout(mid_bar)

        self.setLayout(layout)

    def display_system_message(self, message):
        self.chat_display.append(message)

    # ===🔌 Connection Mode===
    def choose_connection_type(self):
        choice = QMessageBox.question(self, "Connection Type", "Use P2P mode?", QMessageBox.Yes | QMessageBox.No)
        self.p2p_mode = choice == QMessageBox.Yes
        if self.p2p_mode:
            self.connect_p2p()
        else:
            self.connect_to_server()

    def connect_to_server(self):
        self.username = self.username_input.text().strip()
        server_ip = self.server_ip_input.text().strip()
        
        # Input validation
        if not self.username:
            self.message_signal.emit("[!] Please enter a username!")
            return
            
        if len(self.username) > 50:
            self.message_signal.emit("[!] Username too long (max 50 characters)!")
            return
            
        # Check username format (alphanumeric + underscore/hyphen only)
        if not self.username.replace('_', '').replace('-', '').isalnum():
            self.message_signal.emit("[!] Username can only contain letters, numbers, underscores, and hyphens!")
            return
        
        try:
            remote_port = int(self.remote_port_input.text())
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.settimeout(10)  # 10 second connection timeout
            self.server_sock.connect((server_ip, remote_port))
            self.message_signal.emit(f"[+] Connected to {server_ip}:{remote_port}")

            # Start message listener thread
            threading.Thread(target=self.listen_for_server_messages, daemon=True).start()

            # Get password from user
            password, ok = QInputDialog.getText(
                self, 
                "Authentication", 
                f"Enter password for user '{self.username}':",
                QLineEdit.Password
            )
            
            if not ok or not password:
                self.message_signal.emit("[!] No password entered.")
                self.server_sock.close()
                return
                
            if len(password) > 128:
                self.message_signal.emit("[!] Password too long (max 128 characters)!")
                self.server_sock.close()
                return

            # Send authentication data
            auth_data = {
                "username": self.username,
                "public_key": self.public_key,
                "auth": password
            }
            
            self.server_sock.sendall(json.dumps(auth_data).encode())
            self.message_signal.emit("[~] Authenticating...")

        except ValueError:
            self.message_signal.emit("[!] Invalid port number!")
        except socket.timeout:
            self.message_signal.emit("[!] Connection timeout!")
            if self.server_sock:
                self.server_sock.close()
        except ConnectionRefusedError:
            self.message_signal.emit(f"[!] Connection refused by {server_ip}:{remote_port}")
        except Exception as e:
            self.message_signal.emit(f"[!] Connection failed: {e}")
            if self.server_sock:
                self.server_sock.close()

    def connect_p2p(self):
        self.username = self.username_input.text().strip()
        self.peer_ip = self.server_ip_input.text().strip()
        
        if not self.username:
            self.message_signal.emit("[!] Enter a username first!")
            return

        try:
            remote_port = int(self.remote_port_input.text())
            local_port = int(self.local_port_input.text())
        except ValueError:
            self.message_signal.emit("[!] Invalid port numbers!")
            return

        # Start listening for incoming connections
        self.start_p2p_listener(local_port)
        
        # Try to connect to peer
        self.attempt_p2p_connection(self.peer_ip, remote_port)

    def start_p2p_listener(self, port):
        """Start listening for incoming P2P connections"""
        def listener():
            try:
                self.p2p_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.p2p_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.p2p_listener.bind(("0.0.0.0", port))
                self.p2p_listener.listen(1)
                self.message_signal.emit(f"[~] Listening for P2P connections on port {port}...")

                while not self.p2p_connected:
                    try:
                        self.p2p_listener.settimeout(1.0)  # Short timeout for checking connection status
                        conn, addr = self.p2p_listener.accept()
                        
                        with self.connection_lock:
                            if not self.p2p_connected:
                                conn.settimeout(None)  # Remove timeout for actual communication
                                self.p2p_socket = conn
                                self.p2p_connected = True
                                self.message_signal.emit(f"[+] Peer connected from {addr}")
                                
                                # Close the listener since we have a connection
                                try:
                                    self.p2p_listener.close()
                                except:
                                    pass
                                
                                # Start message listener for this connection
                                threading.Thread(target=self.listen_for_p2p_messages, daemon=True).start()
                                
                                # Send our introduction
                                intro = json.dumps({
                                    "type": "introduction",
                                    "username": self.username,
                                    "public_key": self.public_key
                                })
                                self.p2p_socket.sendall(intro.encode())
                                break
                            else:
                                conn.close()
                    except socket.timeout:
                        # Check if we should stop listening
                        continue
                    except Exception as e:
                        if not self.p2p_connected:
                            self.message_signal.emit(f"[!] Listener error: {e}")
                        break
                        
            except Exception as e:
                self.message_signal.emit(f"[!] Failed to start listener: {e}")
            finally:
                try:
                    if self.p2p_listener:
                        self.p2p_listener.close()
                except:
                    pass

        threading.Thread(target=listener, daemon=True).start()

    def attempt_p2p_connection(self, peer_ip, remote_port):
        """Attempt to connect to peer"""
        def connector():
            # Wait a bit to let the listener start
            time.sleep(1)
            
            for attempt in range(12):
                with self.connection_lock:
                    if self.p2p_connected:
                        return
                
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(5)  # 5 second timeout for connection attempt
                    test_sock.connect((peer_ip, remote_port))
                    
                    with self.connection_lock:
                        if not self.p2p_connected:
                            test_sock.settimeout(None)  # Remove timeout for communication
                            self.p2p_socket = test_sock
                            self.p2p_connected = True
                            self.message_signal.emit(f"[+] Connected to peer {peer_ip}:{remote_port}")
                            
                            # Close the listener since we have a connection
                            try:
                                if self.p2p_listener:
                                    self.p2p_listener.close()
                            except:
                                pass
                            
                            # Send introduction
                            intro = json.dumps({
                                "type": "introduction", 
                                "username": self.username,
                                "public_key": self.public_key
                            })
                            self.p2p_socket.sendall(intro.encode())
                            
                            # Start message listener
                            threading.Thread(target=self.listen_for_p2p_messages, daemon=True).start()
                            return
                        else:
                            test_sock.close()
                            return
                            
                except (ConnectionRefusedError, socket.timeout):
                    test_sock.close()
                    if attempt < 11:  # Don't show message on last attempt
                        self.message_signal.emit(f"[~] Attempt {attempt + 1}/12: Retrying connection...")
                    time.sleep(3)  # Reduced retry interval
                except Exception as e:
                    test_sock.close()
                    self.message_signal.emit(f"[!] Connection error: {e}")
                    return

            # Only show this if we're still not connected
            with self.connection_lock:
                if not self.p2p_connected:
                    self.message_signal.emit("[!] Could not connect to peer after 12 attempts.")

        threading.Thread(target=connector, daemon=True).start()

    def listen_for_server_messages(self):
        """Handle messages from server"""
        while True:
            try:
                data = self.server_sock.recv(8192)
                if not data:
                    self.message_signal.emit("[!] Server disconnected")
                    break
                    
                try:
                    payload = json.loads(data.decode())
                    self.process_message(payload)
                except json.JSONDecodeError as e:
                    self.message_signal.emit(f"[!] Invalid message format from server: {e}")
                    continue
                    
            except socket.timeout:
                continue
            except Exception as e:
                self.message_signal.emit(f"[!] Server message error: {e}")
                break
        
        # Cleanup on disconnection
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass
            self.server_sock = None
        
        # Clear peer list
        self.comm.peer_list_updated.emit([])

    def listen_for_p2p_messages(self):
        """Handle messages from P2P peer"""
        self.message_signal.emit("[i] P2P message listener started")
        
        while self.p2p_connected:
            try:
                # Use a timeout to periodically check connection status
                self.p2p_socket.settimeout(1.0)
                data = self.p2p_socket.recv(8192)
                
                if not data:
                    self.message_signal.emit("[i] Peer disconnected (no data)")
                    break
                    
                # Remove timeout for processing
                self.p2p_socket.settimeout(None)
                payload = json.loads(data.decode())
                self.process_message(payload)
                
            except socket.timeout:
                # This is normal - just checking if we should continue
                continue
            except json.JSONDecodeError as e:
                self.message_signal.emit(f"[!] Invalid message format: {e}")
                continue
            except Exception as e:
                self.message_signal.emit(f"[!] P2P message error: {e}")
                break
        
        # Connection lost cleanup
        with self.connection_lock:
            self.p2p_connected = False
            if self.p2p_socket:
                try:
                    self.p2p_socket.close()
                except:
                    pass
                self.p2p_socket = None
        
        self.message_signal.emit("[!] P2P connection lost")
        
        # Clear the peer list
        self.comm.peer_list_updated.emit([])

    def process_message(self, payload):
        """Process incoming messages (both server and P2P)"""
        msg_type = payload.get("type")
        
        if msg_type == "auth_result":
            # Handle authentication response from server
            status = payload.get("status")
            message = payload.get("message", "")
            
            if status == "success":
                self.message_signal.emit(f"[+] ✅ Login successful! {message}")
            elif status == "new_user":
                self.message_signal.emit(f"[+] 🆕 Account created! {message}")
            elif status == "fail":
                self.message_signal.emit(f"[!] ❌ Authentication failed: {message}")
                if self.server_sock:
                    self.server_sock.close()
                    self.server_sock = None
            elif status == "error":
                self.message_signal.emit(f"[!] ⚠️ Server error: {message}")
                if self.server_sock:
                    self.server_sock.close()
                    self.server_sock = None
            else:
                self.message_signal.emit(f"[!] Unknown auth status: {status}")
        
        elif msg_type == "introduction":
            # Handle peer introduction in P2P mode
            peer_name = payload["username"]
            peer_key = payload["public_key"]
            peer_public_keys[peer_name] = peer_key
            peer_key_hashes[peer_name] = sha256_digest(peer_key.encode())
            
            # Update peer list for P2P (just show the connected peer)
            peer_display = f"{peer_name} [{peer_key_hashes[peer_name][:6]}...]"
            self.comm.peer_list_updated.emit([peer_display])
            self.message_signal.emit(f"[+] Peer identified as: {peer_name}")
            
        elif msg_type == "key_exchange":
            key = rsa_decrypt(payload["encrypted_key"])
            aes_session_keys[payload["from"]] = key
            self.message_signal.emit(f"[i] Session key received from {payload['from']}")

        elif msg_type == "message":
            peer = payload["from"]
            if peer in aes_session_keys:
                msg = aes_decrypt(aes_session_keys[peer], payload)
            else:
                msg = "[Key missing]"
            self.comm.message_received.emit(peer, msg)

        elif msg_type == "peer_list":
            # Server mode peer list
            peer_list = []
            for peer in payload["peers"]:
                uname = peer["username"]
                pkey = peer["public_key"]
                peer_public_keys[uname] = pkey
                peer_key_hashes[uname] = sha256_digest(pkey.encode())
                peer_list.append(f"{uname} [{peer_key_hashes[uname][:6]}...]")
            self.comm.peer_list_updated.emit(peer_list)
        
        else:
            self.message_signal.emit(f"[?] Unknown message type: {msg_type}")

    def update_peer_list(self, peers):
        self.peers = peers
        self.peers_list.clear()
        self.peers_list.addItems(peers)

    def display_message(self, sender, message):
        self.chat_display.append(f"🔐 {sender}: {message}")

    def send_message(self):
        msg = self.message_input.text().strip()
        if not msg:
            return
            
        selected = self.peers_list.selectedItems()
        if not selected:
            self.message_signal.emit("[!] Select a peer first!")
            return

        peer_label = selected[0].text()
        peer = peer_label.split(" [")[0]

        # Check if we have a connection
        if not self.p2p_mode and not self.server_sock:
            self.message_signal.emit("[!] Not connected to server!")
            return
        elif self.p2p_mode and not self.p2p_connected:
            self.message_signal.emit("[!] Not connected to peer!")
            return

        # Establish session key if needed
        if peer not in aes_session_keys:
            if peer not in peer_public_keys:
                self.message_signal.emit(f"[!] No public key for {peer}!")
                return
                
            session_key = get_random_bytes(16)
            encrypted_key = rsa_encrypt(peer_public_keys[peer], session_key)
            key_payload = {
                "type": "key_exchange",
                "to": peer,
                "from": self.username,
                "encrypted_key": encrypted_key
            }
            
            # Send via appropriate socket
            try:
                if self.p2p_mode and self.p2p_connected:
                    self.p2p_socket.sendall(json.dumps(key_payload).encode())
                elif self.server_sock:
                    self.server_sock.sendall(json.dumps(key_payload).encode())
                else:
                    self.message_signal.emit("[!] No connection available")
                    return
                    
                aes_session_keys[peer] = session_key
                self.message_signal.emit(f"[i] Session key sent to {peer}")
            except Exception as e:
                self.message_signal.emit(f"[!] Failed to send key: {e}")
                return

        # Encrypt and send message
        enc = aes_encrypt(aes_session_keys[peer], msg)
        enc.update({
            "type": "message",
            "to": peer,
            "from": self.username
        })

        try:
            if self.p2p_mode and self.p2p_connected:
                self.p2p_socket.sendall(json.dumps(enc).encode())
            elif self.server_sock:
                self.server_sock.sendall(json.dumps(enc).encode())
            else:
                self.message_signal.emit("[!] No connection available")
                return
                
            self.chat_display.append(f"You to {peer}: {msg}")
            self.message_input.clear()
            
        except Exception as e:
            self.message_signal.emit(f"[!] Failed to send message: {e}")

# ===💬 Launch UI===
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatClient()
    window.show()
    sys.exit(app.exec_())