# ===🔐 Enhanced Crypto Utils with File Support===
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import base64

# ===🔑 RSA Functions===
def generate_rsa_keypair():
    """Generate RSA key pair for asymmetric encryption"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Convert public key to PEM format for transmission"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key, password=None):
    """Convert private key to PEM format for storage"""
    encryption_algorithm = serialization.NoEncryption()
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

def deserialize_public_key(pem_data):
    """Load public key from PEM format"""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def deserialize_private_key(pem_data, password=None):
    """Load private key from PEM format"""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    
    password_bytes = password.encode() if password else None
    return serialization.load_pem_private_key(
        pem_data, 
        password=password_bytes, 
        backend=default_backend()
    )

def rsa_encrypt(data, public_key):
    """Encrypt data using RSA public key"""
    if isinstance(data, str):
        data = data.encode()
    
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext, private_key):
    """Decrypt data using RSA private key"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(data, private_key):
    """Sign data using RSA private key"""
    if isinstance(data, str):
        data = data.encode()
    
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(signature, data, public_key):
    """Verify signature using RSA public key"""
    if isinstance(data, str):
        data = data.encode()
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ===🔐 AES Functions===
def generate_aes_key():
    """Generate random AES-256 key"""
    return os.urandom(32)  # 256-bit key

def derive_key_from_password(password, salt=None):
    """Derive AES key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    if isinstance(password, str):
        password = password.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return key, salt

def aes_encrypt(message, key):
    """Encrypt message using AES-CFB mode"""
    if isinstance(message, str):
        message = message.encode()
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    """Decrypt message using AES-CFB mode"""
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def aes_encrypt_gcm(message, key):
    """Encrypt message using AES-GCM mode (provides authentication)"""
    if isinstance(message, str):
        message = message.encode()
    
    iv = os.urandom(12)  # GCM uses 96-bit IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    return {
        'iv': iv,
        'ciphertext': ciphertext,
        'tag': encryptor.tag
    }

def aes_decrypt_gcm(encrypted_data, key):
    """Decrypt message using AES-GCM mode"""
    iv = encrypted_data['iv']
    ciphertext = encrypted_data['ciphertext']
    tag = encrypted_data['tag']
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ===📁 File Encryption Functions===
def encrypt_file(file_path, key, output_path=None):
    """Encrypt a file using AES-GCM"""
    if output_path is None:
        output_path = file_path + '.encrypted'
    
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # Write IV to the beginning of the file
        outfile.write(iv)
        
        # Encrypt file in chunks
        while True:
            chunk = infile.read(8192)
            if not chunk:
                break
            outfile.write(encryptor.update(chunk))
        
        # Finalize and write authentication tag
        outfile.write(encryptor.finalize())
        outfile.write(encryptor.tag)
    
    return output_path

def decrypt_file(encrypted_file_path, key, output_path=None):
    """Decrypt a file encrypted with AES-GCM"""
    if output_path is None:
        if encrypted_file_path.endswith('.encrypted'):
            output_path = encrypted_file_path[:-10]  # Remove .encrypted extension
        else:
            output_path = encrypted_file_path + '.decrypted'
    
    with open(encrypted_file_path, 'rb') as infile:
        # Read IV from the beginning
        iv = infile.read(12)
        
        # Read the entire file to get the tag at the end
        encrypted_data = infile.read()
        
        # Extract tag (last 16 bytes) and ciphertext
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[:-16]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    with open(output_path, 'wb') as outfile:
        # Decrypt in chunks
        chunk_size = 8192
        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:i + chunk_size]
            outfile.write(decryptor.update(chunk))
        
        outfile.write(decryptor.finalize())
    
    return output_path

def encrypt_file_stream(file_data, key):
    """Encrypt file data in memory using AES-GCM"""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    
    return {
        'iv': base64.b64encode(iv).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(encryptor.tag).decode()
    }

def decrypt_file_stream(encrypted_data, key):
    """Decrypt file data in memory using AES-GCM"""
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()

# ===🔐 Hybrid Encryption (RSA + AES)===
def hybrid_encrypt(data, public_key):
    """Encrypt data using hybrid encryption (RSA + AES)"""
    # Generate random AES key
    aes_key = generate_aes_key()
    
    # Encrypt data with AES
    encrypted_data = aes_encrypt_gcm(data, aes_key)
    
    # Encrypt AES key with RSA
    encrypted_key = rsa_encrypt(aes_key, public_key)
    
    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'encrypted_data': {
            'iv': base64.b64encode(encrypted_data['iv']).decode(),
            'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode(),
            'tag': base64.b64encode(encrypted_data['tag']).decode()
        }
    }

def hybrid_decrypt(encrypted_package, private_key):
    """Decrypt data using hybrid decryption (RSA + AES)"""
    # Decrypt AES key with RSA
    encrypted_key = base64.b64decode(encrypted_package['encrypted_key'])
    aes_key = rsa_decrypt(encrypted_key, private_key)
    
    # Prepare encrypted data for AES decryption
    encrypted_data = {
        'iv': base64.b64decode(encrypted_package['encrypted_data']['iv']),
        'ciphertext': base64.b64decode(encrypted_package['encrypted_data']['ciphertext']),
        'tag': base64.b64decode(encrypted_package['encrypted_data']['tag'])
    }
    
    # Decrypt data with AES
    return aes_decrypt_gcm(encrypted_data, aes_key)

# ===🔍 Utility Functions===
def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate hash of a file"""
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def calculate_data_hash(data, algorithm='sha256'):
    """Calculate hash of data"""
    if isinstance(data, str):
        data = data.encode()
    
    return hashlib.new(algorithm, data).hexdigest()

def secure_delete_file(file_path, passes=3):
    """Securely delete a file by overwriting it multiple times"""
    if not os.path.exists(file_path):
        return False
    
    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(file_path)
        return True
    except Exception:
        return False

def generate_secure_filename():
    """Generate a secure random filename"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')

def verify_file_integrity(file_path, expected_hash, algorithm='sha256'):
    """Verify file integrity using hash comparison"""
    actual_hash = calculate_file_hash(file_path, algorithm)
    return actual_hash == expected_hash

# ===🔑 Key Management===
def save_key_to_file(key, file_path, password=None):
    """Save a key to file with optional password protection"""
    key_data = key
    
    if password:
        # Encrypt the key with password-derived key
        derived_key, salt = derive_key_from_password(password)
        encrypted_key = aes_encrypt_gcm(key, derived_key)
        
        key_data = {
            'encrypted': True,
            'salt': base64.b64encode(salt).decode(),
            'data': {
                'iv': base64.b64encode(encrypted_key['iv']).decode(),
                'ciphertext': base64.b64encode(encrypted_key['ciphertext']).decode(),
                'tag': base64.b64encode(encrypted_key['tag']).decode()
            }
        }
    else:
        key_data = {
            'encrypted': False,
            'data': base64.b64encode(key).decode()
        }
    
    with open(file_path, 'w') as f:
        import json
        json.dump(key_data, f, indent=2)

def load_key_from_file(file_path, password=None):
    """Load a key from file with optional password"""
    with open(file_path, 'r') as f:
        import json
        key_data = json.load(f)
    
    if key_data['encrypted']:
        if not password:
            raise ValueError("Password required for encrypted key")
        
        salt = base64.b64decode(key_data['salt'])
        derived_key, _ = derive_key_from_password(password, salt)
        
        encrypted_data = {
            'iv': base64.b64decode(key_data['data']['iv']),
            'ciphertext': base64.b64decode(key_data['data']['ciphertext']),
            'tag': base64.b64decode(key_data['data']['tag'])
        }
        
        return aes_decrypt_gcm(encrypted_data, derived_key)
    else:
        return base64.b64decode(key_data['data'])

# ===🧪 Testing Functions===
def test_crypto_functions():
    """Test all crypto functions"""
    print("Testing crypto functions...")
    
    # Test RSA
    private_key, public_key = generate_rsa_keypair()
    test_data = b"Hello, World!"
    
    encrypted = rsa_encrypt(test_data, public_key)
    decrypted = rsa_decrypt(encrypted, private_key)
    assert decrypted == test_data, "RSA encryption/decryption failed"
    print("✓ RSA encryption/decryption works")
    
    # Test AES
    aes_key = generate_aes_key()
    test_message = "This is a test message"
    
    encrypted_aes = aes_encrypt(test_message, aes_key)
    decrypted_aes = aes_decrypt(encrypted_aes, aes_key)
    assert decrypted_aes.decode() == test_message, "AES encryption/decryption failed"
    print("✓ AES encryption/decryption works")
    
    # Test AES-GCM
    encrypted_gcm = aes_encrypt_gcm(test_message, aes_key)
    decrypted_gcm = aes_decrypt_gcm(encrypted_gcm, aes_key)
    assert decrypted_gcm.decode() == test_message, "AES-GCM encryption/decryption failed"
    print("✓ AES-GCM encryption/decryption works")
    
    # Test hybrid encryption
    hybrid_encrypted = hybrid_encrypt(test_message, public_key)
    hybrid_decrypted = hybrid_decrypt(hybrid_encrypted, private_key)
    assert hybrid_decrypted.decode() == test_message, "Hybrid encryption/decryption failed"
    print("✓ Hybrid encryption/decryption works")
    
    print("All crypto tests passed! 🎉")

if __name__ == "__main__":
    test_crypto_functions()