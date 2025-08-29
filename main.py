import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import customtkinter as ctk
from CTkMessagebox import CTkMessagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import shutil
import json
import datetime
import random
import tempfile
from pathlib import Path
import logging
import sqlite3
import uuid
import re
from PIL import Image, ImageTk
import threading
import time
import io
import struct
import numpy as np
from io import BytesIO
import zlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("encryptor_activity.log"),
        logging.StreamHandler()
    ]
)

# Set the appearance mode and default color theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class PasswordManager:
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self._initialize_db()
        
    def _initialize_db(self):
        """Create the database and tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_passwords (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def set_master_password(self, password):
        """Set or update the master password"""
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if master password exists
        cursor.execute("SELECT COUNT(*) FROM master_password")
        if cursor.fetchone()[0] > 0:
            cursor.execute("UPDATE master_password SET password_hash = ?, salt = ?", (password_hash, salt))
        else:
            cursor.execute("INSERT INTO master_password (password_hash, salt) VALUES (?, ?)", (password_hash, salt))
        
        conn.commit()
        conn.close()
        return True
    
    def verify_master_password(self, password):
        """Verify if the provided master password is correct"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM master_password")
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False
            
        stored_hash, salt = result
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        return password_hash == stored_hash
    
    def save_password(self, name, path, password, master_password):
        """Save an encrypted password entry"""
        if not self.verify_master_password(master_password):
            return False
        
        # Generate a key from master password
        key = self._derive_key_from_password(master_password)
        
        # Encrypt the folder password
        f = Fernet(key)
        encrypted_password = f.encrypt(password.encode()).decode()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO saved_passwords (name, path, encrypted_password) VALUES (?, ?, ?)",
            (name, path, encrypted_password)
        )
        conn.commit()
        conn.close()
        return True
    
    def get_saved_passwords(self, master_password):
        """Get all saved passwords (decrypted with master password)"""
        if not self.verify_master_password(master_password):
            return None
        
        # Generate a key from master password
        key = self._derive_key_from_password(master_password)
        f = Fernet(key)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, path, encrypted_password, created_at FROM saved_passwords ORDER BY created_at DESC")
        password_entries = []
        
        for row in cursor.fetchall():
            id, name, path, encrypted_password, created_at = row
            try:
                decrypted_password = f.decrypt(encrypted_password.encode()).decode()
                password_entries.append({
                    'id': id,
                    'name': name,
                    'path': path,
                    'password': decrypted_password,
                    'created_at': created_at
                })
            except Exception as e:
                logging.error(f"Failed to decrypt password entry {id}: {e}")
        
        conn.close()
        return password_entries
    
    def delete_password(self, password_id):
        """Delete a saved password entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM saved_passwords WHERE id = ?", (password_id,))
        conn.commit()
        conn.close()
        return True
    
    def _derive_key_from_password(self, password):
        """Derive a key from the master password for encrypting/decrypting stored passwords"""
        password_bytes = password.encode()
        salt = b'masterpasswordsalt'  # This should ideally be stored securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password_bytes))
    
    def has_master_password(self):
        """Check if a master password is set"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master_password")
        result = cursor.fetchone()[0] > 0
        conn.close()
        return result


class ActivityLogger:
    def __init__(self, db_path="activity_logs.db"):
        self.db_path = db_path
        self._initialize_db()
        
    def _initialize_db(self):
        """Create the database and tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY,
                operation TEXT NOT NULL,
                status TEXT NOT NULL,
                path TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def log_activity(self, operation, status, path, details=None):
        """Log an activity in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO activity_logs (operation, status, path, details) VALUES (?, ?, ?, ?)",
            (operation, status, path, details)
        )
        conn.commit()
        conn.close()
        
        # Also log to the standard log file
        log_message = f"{operation} - {status} - {path} - {details}"
        if status == "SUCCESS":
            logging.info(log_message)
        elif status == "FAILED":
            logging.error(log_message)
        else:
            logging.warning(log_message)
    
    def get_recent_logs(self, limit=100):
        """Get recent activity logs"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?", 
            (limit,)
        )
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs


class RecentFilesManager:
    def __init__(self, max_entries=10):
        self.max_entries = max_entries
        self.recent_files_path = os.path.join(os.path.expanduser('~'), '.folder_encryptor_recent')
        self.recent_files = self._load_recent_files()
    
    def _load_recent_files(self):
        """Load recent files from the storage file"""
        if os.path.exists(self.recent_files_path):
            try:
                with open(self.recent_files_path, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_recent_files(self):
        """Save recent files to the storage file"""
        with open(self.recent_files_path, 'w') as f:
            json.dump(self.recent_files, f)
    
    def add_recent_file(self, file_path, operation, timestamp=None):
        """Add a file to recent files list"""
        if not timestamp:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
        # Check if file already exists in recent files
        for i, entry in enumerate(self.recent_files):
            if entry['path'] == file_path:
                # Update timestamp and operation
                self.recent_files[i]['timestamp'] = timestamp
                self.recent_files[i]['operation'] = operation
                self.recent_files.insert(0, self.recent_files.pop(i))  # Move to top
                self._save_recent_files()
                return
                
        # Add new entry
        self.recent_files.insert(0, {
            'path': file_path,
            'operation': operation,
            'timestamp': timestamp
        })
        
        # Trim list if necessary
        if len(self.recent_files) > self.max_entries:
            self.recent_files = self.recent_files[:self.max_entries]
            
        self._save_recent_files()
    
    def get_recent_files(self):
        """Get the list of recent files"""
        return self.recent_files
    
    def clear_recent_files(self):
        """Clear the recent files list"""
        self.recent_files = []
        self._save_recent_files()


class EnhancedFolderEncryptor:
    def __init__(self):
        self.default_salt = b'saltysalt123456'
        self.encrypted_extension = '.encrypted'
        self.metadata_file = '.metadata.json'
        self.encryption_algorithms = {
            'AES-128': {'key_size': 16, 'algorithm': algorithms.AES},
            'AES-256': {'key_size': 32, 'algorithm': algorithms.AES},
            'ChaCha20': {'key_size': 32, 'algorithm': algorithms.ChaCha20}
        }
        self.default_algorithm = 'AES-256'
        self.integrity_check = True
        self.activity_logger = ActivityLogger()
    
    def _get_key_from_password(self, password, salt=None, algorithm='AES-256'):
        """Generate a key from the password with the specified algorithm"""
        if salt is None:
            salt = self.default_salt
            
        password_bytes = password.encode('utf-8')
        
        # For Fernet (AES algorithms), we always need 32 bytes before base64 encoding
        if 'AES' in algorithm:
            # For Fernet, always use 32 bytes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # Always 32 bytes for Fernet
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password_bytes)
            # Convert to base64 for Fernet
            return base64.urlsafe_b64encode(key)
        else:
            # For non-Fernet algorithms like ChaCha20
            key_size = self.encryption_algorithms[algorithm]['key_size']
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_size,
                salt=salt,
                iterations=100000,
            )
            return kdf.derive(password_bytes)
    
    def shred_file(self, file_path, passes=3):
        """
        Securely delete a file by overwriting its contents multiple times
        before deletion
        """
        if not os.path.exists(file_path):
            return False
            
        try:
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Open the file for binary overwrite
            with open(file_path, 'wb') as f:
                for _ in range(passes):
                    # Seek to beginning
                    f.seek(0)
                    
                    # Overwrite with random data
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Overwrite with zeros
                    f.seek(0)
                    f.write(b'\x00' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Overwrite with ones
                    f.seek(0)
                    f.write(b'\xFF' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            os.remove(file_path)
            return True
        except Exception as e:
            logging.error(f"Failed to shred file {file_path}: {e}")
            return False
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file for integrity verification"""
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
        
    def encrypt_folder(self, folder_path, password, algorithm='AES-256', shred_original=False, 
                       progress_callback=None):
        """
        Encrypt all files in the folder with the given password
        using the specified encryption algorithm
        """
        folder_path = Path(folder_path)
        encrypted_folder = folder_path.with_suffix(self.encrypted_extension)
        
        # Check if encryption algorithm is supported
        if algorithm not in self.encryption_algorithms:
            error_msg = f"Unsupported encryption algorithm: {algorithm}"
            self.activity_logger.log_activity("ENCRYPT", "FAILED", str(folder_path), error_msg)
            raise ValueError(error_msg)
        
        # Generate a unique salt for this encryption
        encryption_salt = os.urandom(16)
        
        # Generate key from password
        key = self._get_key_from_password(password, encryption_salt, algorithm)
        
        if 'AES' in algorithm:
            fernet = Fernet(key)
        
        # Create an encrypted folder
        if encrypted_folder.exists():
            shutil.rmtree(encrypted_folder)
        
        encrypted_folder.mkdir()
        
        # Metadata to store original file paths and integrity information
        metadata = {
            'algorithm': algorithm,
            'salt': base64.b64encode(encryption_salt).decode(),
            'created': datetime.datetime.now().isoformat(),
            'files': {}
        }
        
        # List all files and subdirectories
        all_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
        
        # Process each file
        total_files = len(all_files)
        processed_files = 0
        
        for file_path in all_files:
            try:
                # Get the relative path
                rel_path = os.path.relpath(file_path, folder_path)
                
                # Read the file content
                with open(file_path, 'rb') as file:
                    data = file.read()
                
                # Calculate hash for integrity verification
                file_hash = hashlib.sha256(data).hexdigest()
                
                # Encrypt the file content
                if 'AES' in algorithm:
                    encrypted_data = fernet.encrypt(data)
                elif algorithm == 'ChaCha20':
                    # Generate nonce for ChaCha20
                    nonce = os.urandom(16)
                    cipher = Cipher(
                        self.encryption_algorithms[algorithm]['algorithm'](key, nonce),
                        mode=None
                    )
                    encryptor = cipher.encryptor()
                    encrypted_data = nonce + encryptor.update(data) + encryptor.finalize()
                
                # Generate a unique name for the encrypted file
                encrypted_file_name = base64.urlsafe_b64encode(rel_path.encode()).decode()
                encrypted_file_path = os.path.join(encrypted_folder, encrypted_file_name)
                
                # Save the encrypted content
                with open(encrypted_file_path, 'wb') as file:
                    file.write(encrypted_data)
                
                # Store the original path and hash in metadata
                metadata['files'][encrypted_file_name] = {
                    'path': rel_path,
                    'hash': file_hash,
                    'size': len(data)
                }
                
                # Shred original file if requested
                if shred_original:
                    self.shred_file(file_path)
                
                processed_files += 1
                
                # Update progress if callback is provided
                if progress_callback:
                    progress = (processed_files / total_files) * 100
                    progress_callback(progress)
            
            except Exception as e:
                error_msg = f"Error encrypting {file_path}: {e}"
                logging.error(error_msg)
                self.activity_logger.log_activity("ENCRYPT", "FAILED", file_path, error_msg)
        
        # Save metadata
        metadata_path = os.path.join(encrypted_folder, self.metadata_file)
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.activity_logger.log_activity(
            "ENCRYPT", 
            "SUCCESS", 
            str(folder_path), 
            f"Encrypted to {encrypted_folder} using {algorithm}"
        )
        
        return str(encrypted_folder)
    
    def decrypt_folder(self, encrypted_folder_path, password, output_folder=None, 
                       verify_integrity=True, progress_callback=None):
        """
        Decrypt an encrypted folder with the given password
        and optionally verify file integrity
        """
        # Load metadata to get encryption algorithm and salt
        encrypted_folder_path = Path(encrypted_folder_path)
        metadata_path = os.path.join(encrypted_folder_path, self.metadata_file)
        
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            algorithm = metadata.get('algorithm', self.default_algorithm)
            salt = base64.b64decode(metadata.get('salt', '')) if metadata.get('salt') else self.default_salt
            
            # Generate key from password
            key = self._get_key_from_password(password, salt, algorithm)
            
            if 'AES' in algorithm:
                fernet = Fernet(key)
            
            # Default output folder is the original folder name (without .encrypted extension)
            if output_folder is None:
                output_folder = encrypted_folder_path.with_suffix('')
            else:
                output_folder = Path(output_folder)
            
            # Create output folder if it doesn't exist
            if output_folder.exists():
                shutil.rmtree(output_folder)
            output_folder.mkdir()
            
            # Get all encrypted files (excluding metadata)
            encrypted_files = [f for f in os.listdir(encrypted_folder_path) 
                             if os.path.isfile(os.path.join(encrypted_folder_path, f)) 
                             and f != self.metadata_file]
            
            # Track integrity verification failures
            integrity_failures = []
            
            # Process each file
            total_files = len(encrypted_files)
            processed_files = 0
            
            for encrypted_file_name in encrypted_files:
                try:
                    # Get file metadata
                    file_meta = metadata['files'].get(encrypted_file_name)
                    if not file_meta:
                        continue
                    
                    original_rel_path = file_meta['path']
                    expected_hash = file_meta.get('hash')
                    
                    # Construct the output path
                    output_path = os.path.join(output_folder, original_rel_path)
                    
                    # Make sure the directory exists
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    # Read the encrypted data
                    encrypted_file_path = os.path.join(encrypted_folder_path, encrypted_file_name)
                    with open(encrypted_file_path, 'rb') as file:
                        encrypted_data = file.read()
                    
                    # Decrypt the data
                    if 'AES' in algorithm:
                        try:
                            decrypted_data = fernet.decrypt(encrypted_data)
                        except Exception as e:
                            raise ValueError(f"Decryption failed, possibly incorrect password: {e}")
                    elif algorithm == 'ChaCha20':
                        # Extract nonce (first 16 bytes)
                        nonce, encrypted_data = encrypted_data[:16], encrypted_data[16:]
                        cipher = Cipher(
                            self.encryption_algorithms[algorithm]['algorithm'](key, nonce),
                            mode=None
                        )
                        decryptor = cipher.decryptor()
                        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    # Verify integrity if requested
                    if verify_integrity and expected_hash:
                        actual_hash = hashlib.sha256(decrypted_data).hexdigest()
                        if actual_hash != expected_hash:
                            integrity_failures.append(original_rel_path)
                            error_msg = f"Integrity check failed for {original_rel_path}"
                            self.activity_logger.log_activity("INTEGRITY", "FAILED", output_path, error_msg)
                    
                    # Write the decrypted data
                    with open(output_path, 'wb') as file:
                        file.write(decrypted_data)
                    
                    processed_files += 1
                    
                    # Update progress if callback is provided
                    if progress_callback:
                        progress = (processed_files / total_files) * 100
                        progress_callback(progress)
                
                except Exception as e:
                    error_msg = f"Error decrypting {encrypted_file_name}: {e}"
                    logging.error(error_msg)
                    self.activity_logger.log_activity("DECRYPT", "FAILED", str(encrypted_folder_path), error_msg)
                    if "incorrect password" in str(e).lower():
                        raise ValueError("Incorrect password")
            
            # Report integrity verification results
            if verify_integrity and integrity_failures:
                warning_msg = f"Integrity check failed for {len(integrity_failures)} files"
                self.activity_logger.log_activity(
                    "DECRYPT", 
                    "WARNING", 
                    str(output_folder), 
                    warning_msg
                )
                raise Warning(f"Decryption completed but integrity check failed for {len(integrity_failures)} files")
            else:
                self.activity_logger.log_activity(
                    "DECRYPT", 
                    "SUCCESS", 
                    str(encrypted_folder_path), 
                    f"Decrypted to {output_folder}"
                )
            
            return str(output_folder)
        
        except json.JSONDecodeError:
            error_msg = "Invalid metadata file. The folder may not be encrypted properly."
            self.activity_logger.log_activity("DECRYPT", "FAILED", str(encrypted_folder_path), error_msg)
            raise ValueError(error_msg)
        
        except FileNotFoundError:
            error_msg = "Metadata file not found. The folder may not be encrypted properly."
            self.activity_logger.log_activity("DECRYPT", "FAILED", str(encrypted_folder_path), error_msg)
            raise ValueError(error_msg)
        
        except Exception as e:
            error_msg = f"Decryption failed: {e}"
            self.activity_logger.log_activity("DECRYPT", "FAILED", str(encrypted_folder_path), error_msg)
            raise


class PasswordStrengthMeter:
    def __init__(self):
        self.patterns = {
            'sequential_chars': re.compile(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mnop|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', re.IGNORECASE),
            'sequential_nums': re.compile(r'(123|234|345|456|567|678|789|890)'),
            'repeated_chars': re.compile(r'(.)\1{2,}'),
            'common_words': re.compile(r'(password|qwerty|admin|welcome|123456|111111)', re.IGNORECASE)
        }
    
    def check_strength(self, password):
        """
        Check the strength of a password and return a score (0-100) and feedback
        """
        if not password:
            return 0, "No password", []
            
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        elif len(password) >= 6:
            score += 10
        else:
            feedback.append("Password is too short")
        
        # Character variety
        if any(c.islower() for c in password):
            score += 10
        else:
            feedback.append("Add lowercase letters")
            
        if any(c.isupper() for c in password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
            
        if any(c.isdigit() for c in password):
            score += 20
        else:
            feedback.append("Add numbers")
            
        if any(not c.isalnum() for c in password):
            score += 25
        else:
            feedback.append("Add special characters")
        
        # Penalize common patterns
        pattern_found = False
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(password):
                score -= 15
                pattern_found = True
                
        if pattern_found:
            feedback.append("Avoid common patterns and sequences")
        
        # Adjust final score
        score = max(0, min(score, 100))
        
        # Determine strength category
        if score < 30:
            strength = "Weak"
        elif score < 60:
            strength = "Moderate"
        elif score < 80:
            strength = "Strong"
        else:
            strength = "Very Strong"
            
        if not feedback and score >= 80:
            feedback.append("Excellent password!")
            
        return score, strength, feedback


class SteganographyTool:
    """
    Class for steganography operations - hiding data in images and extracting hidden data
    """
    
    def __init__(self):
        self.activity_logger = ActivityLogger()
        self.supported_formats = ['.png', '.bmp']  # Lossless formats are better for steganography
    
    def _can_fit_data(self, image_path, data_size):
        """
        Check if the image can fit the data
        Returns maximum data size and boolean indicating if it can fit
        """
        try:
            with Image.open(image_path) as img:
                # For LSB steganography in a 24-bit image, we can use 
                # at most 1 bit per color channel
                max_bytes = (img.width * img.height * 3) // 8
                
                # We need 4 bytes to store size information
                max_bytes -= 4
                
                return max_bytes, max_bytes >= data_size
        except Exception as e:
            logging.error(f"Error checking image capacity: {e}")
            return 0, False
    
    def get_image_capacity(self, image_path):
        """Returns the maximum data size that can be hidden in the image"""
        max_size, _ = self._can_fit_data(image_path, 0)
        return max_size
    
    def hide_data_in_image(self, image_path, data, output_path=None, password=None):
        """
        Hide data in an image using LSB steganography
        If password is provided, encrypts data before hiding
        Returns the path to the output image
        """
        try:
            # Compress data to reduce space required
            compressed_data = zlib.compress(data.encode() if isinstance(data, str) else data)
            
            # Optional: Encrypt data if password is provided
            if password:
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(compressed_data)
                data_to_hide = salt + encrypted_data
            else:
                data_to_hide = compressed_data
                
            # Check if the image can fit the data
            max_size, can_fit = self._can_fit_data(image_path, len(data_to_hide))
            if not can_fit:
                raise ValueError(f"Data is too large to hide in this image. Maximum size: {max_size} bytes")
            
            # Open the image and keep original mode
            img = Image.open(image_path)
            original_mode = img.mode
            has_alpha = 'A' in original_mode
            
            # Work with RGB or RGBA depending on the original image
            if original_mode not in ('RGB', 'RGBA'):
                if has_alpha:
                    img = img.convert('RGBA')
                else:
                    img = img.convert('RGB')
            
            # Get pixel data as a list
            pixels = list(img.getdata())
            width, height = img.size
            
            # Prepare the data with size header (4 bytes for data length)
            data_len = len(data_to_hide)
            size_header = data_len.to_bytes(4, byteorder='big')
            full_data = size_header + data_to_hide
            
            # Convert data to bit array
            bit_array = []
            for byte in full_data:
                for i in range(7, -1, -1):
                    bit_array.append((byte >> i) & 1)
            
            # Make a copy of pixels to modify
            modified_pixels = pixels.copy()
            data_index = 0
            
            # Embed data in the least significant bits of pixels
            for i, pixel in enumerate(pixels):
                if data_index >= len(bit_array):
                    break
                    
                # Handle both RGB and RGBA
                if has_alpha:
                    r, g, b, a = pixel
                else:
                    r, g, b = pixel
                
                # Modify R channel LSB if needed
                if data_index < len(bit_array):
                    r = (r & ~1) | bit_array[data_index]
                    data_index += 1
                
                # Modify G channel LSB if needed
                if data_index < len(bit_array):
                    g = (g & ~1) | bit_array[data_index]
                    data_index += 1
                
                # Modify B channel LSB if needed
                if data_index < len(bit_array):
                    b = (b & ~1) | bit_array[data_index]
                    data_index += 1
                
                # Update the pixel in our copy
                if has_alpha:
                    modified_pixels[i] = (r, g, b, a)  # Preserve alpha
                else:
                    modified_pixels[i] = (r, g, b)
            
            # Create new image with modified pixels
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(modified_pixels)
            
            # Copy metadata from original image if possible
            try:
                exif_data = img.info.get('exif')
                if exif_data:
                    new_img.info['exif'] = exif_data
            except:
                pass  # Skip if can't copy EXIF data
            
            # Save the image
            if output_path is None:
                file_name, file_ext = os.path.splitext(image_path)
                output_path = f"{file_name}_steganography.png"
                
            # Save with highest quality and compression settings for PNG
            new_img.save(output_path, format='PNG', compress_level=0)
            
            self.activity_logger.log_activity(
                "STEGANOGRAPHY", 
                "SUCCESS", 
                output_path, 
                f"Data hidden in image: {os.path.basename(output_path)}"
            )
            
            return output_path
            
        except Exception as e:
            error_msg = f"Failed to hide data in image: {e}"
            logging.error(error_msg)
            self.activity_logger.log_activity("STEGANOGRAPHY", "FAILED", image_path, error_msg)
            raise
    
    def extract_data_from_image(self, image_path, password=None):
        """
        Extract hidden data from an image
        If password is provided, decrypts the data after extraction
        Returns the extracted data
        """
        try:
            # Open the image
            img = Image.open(image_path)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get pixel data
            pixels = list(img.getdata())
            
            # Extract LSBs from pixels
            extracted_bits = []
            for r, g, b in pixels:
                # Extract LSB from R, G, B channels
                extracted_bits.append(r & 1)
                extracted_bits.append(g & 1)
                extracted_bits.append(b & 1)
            
            # Convert bit array to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 8 <= len(extracted_bits):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | extracted_bits[i + j]
                    extracted_bytes.append(byte)
            
            # First 4 bytes are the data length
            data_len = int.from_bytes(extracted_bytes[:4], byteorder='big')
            
            # Extract only the data bytes (4 header bytes + data_len)
            data = extracted_bytes[4:4 + data_len]
            
            # Handle decryption if password provided
            if password:
                try:
                    # Extract salt (first 16 bytes)
                    salt = bytes(data[:16])
                    encrypted_data = bytes(data[16:])
                    
                    # Derive key from password
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                    
                    # Decrypt data
                    fernet = Fernet(key)
                    decompressed_data = zlib.decompress(fernet.decrypt(encrypted_data))
                except Exception as e:
                    raise ValueError(f"Failed to decrypt data: {e}")
            else:
                # Just decompress the data
                decompressed_data = zlib.decompress(bytes(data))
            
            # Try to decode as UTF-8 text, return bytes if not possible
            try:
                result = decompressed_data.decode('utf-8')
            except UnicodeDecodeError:
                result = decompressed_data
                
            self.activity_logger.log_activity(
                "STEGANOGRAPHY", 
                "SUCCESS", 
                image_path, 
                f"Data extracted from image: {os.path.basename(image_path)}"
            )
                
            return result
            
        except Exception as e:
            error_msg = f"Failed to extract data from image: {e}"
            logging.error(error_msg)
            self.activity_logger.log_activity("STEGANOGRAPHY", "FAILED", image_path, error_msg)
            raise
    
    def is_file_supported(self, file_path):
        """Check if the file format is supported for steganography"""
        _, ext = os.path.splitext(file_path.lower())
        return ext in self.supported_formats
    
    def has_hidden_data(self, image_path):
        """
        Check if an image likely contains hidden data
        This is a simple heuristic and may not be 100% accurate
        """
        try:
            # Open the image
            img = Image.open(image_path)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Sample the first few pixels to extract potential size header
            pixels = list(img.getdata())[:50]  # Take first 50 pixels
            
            # Extract LSBs from pixels
            extracted_bits = []
            for r, g, b in pixels:
                # Extract LSB from R, G, B channels
                extracted_bits.append(r & 1)
                extracted_bits.append(g & 1)
                extracted_bits.append(b & 1)
            
            # Convert first 32 bits (4 bytes) to an integer - this should be the data length
            if len(extracted_bits) >= 32:
                size_bits = extracted_bits[:32]
                size_value = 0
                for bit in size_bits:
                    size_value = (size_value << 1) | bit
                
                # Check if the size value is reasonable
                img_capacity = (img.width * img.height * 3) // 8 - 4
                
                # If size is between 1 and the maximum capacity, it likely has data
                return 0 < size_value <= img_capacity
            
            return False
            
        except Exception as e:
            logging.error(f"Error checking for hidden data: {e}")
            return False


class ModernEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Vault Pro")
        self.root.geometry("900x650")
        self.root.minsize(800, 600)
        
        # Load images and icons
        self.load_assets()
        
        # Initialize managers
        self.encryptor = EnhancedFolderEncryptor()
        self.password_manager = PasswordManager()
        self.recent_files = RecentFilesManager()
        self.password_meter = PasswordStrengthMeter()
        self.steganography = SteganographyTool()
        
        # Set up theme variables
        self.appearance_mode_var = ctk.StringVar(value="System")
        self.color_theme_var = ctk.StringVar(value="blue")
        
        # Configure the main container
        self.configure_gui()
        
        # Create sidebar for navigation
        self.create_sidebar()
        
        # Create main content area
        self.create_content_area()
        
        # Create status bar - IMPORTANT: Create this BEFORE showing any frame
        self.create_status_bar()
        
        # Initial active tab
        self.show_frame("encrypt")
        
        # Bind closing event to save settings
        root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def load_assets(self):
        """Load images and icons for the application"""
        # Create a dictionary to store our images
        self.images = {}
        
        # Define the icons we need
        self.icons = {
            "encrypt": "🔒",
            "decrypt": "🔓",
            "stego": "🖼️",
            "recent": "⏱️",
            "logs": "📋",
            "settings": "⚙️"
        }
    
    def configure_gui(self):
        """Configure the GUI appearance and layout"""
        # Set appearance mode based on system (can be changed in settings)
        ctk.set_appearance_mode(self.appearance_mode_var.get())
        ctk.set_default_color_theme(self.color_theme_var.get())
        
        # Create a main container frame with padding
        self.main_container = ctk.CTkFrame(self.root)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
    def create_sidebar(self):
        """Create a sidebar for navigation"""
        # Sidebar frame
        self.sidebar = ctk.CTkFrame(self.main_container, width=200, corner_radius=10)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        # App logo/name
        ctk.CTkLabel(
            self.sidebar, 
            text="Secure Vault Pro", 
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(20, 30))
        
        # Navigation buttons
        self.nav_buttons = {}
        
        # Function to handle button clicks with animation
        def handle_nav_click(tab_name):
            for btn in self.nav_buttons.values():
                btn.configure(fg_color="transparent")
            self.nav_buttons[tab_name].configure(fg_color=("gray75", "gray25"))
            self.show_frame(tab_name)
        
        # Create navigation buttons
        for tab_name, icon in self.icons.items():
            display_name = tab_name.capitalize()
            btn = ctk.CTkButton(
                self.sidebar,
                text=f"{icon} {display_name}",
                font=ctk.CTkFont(size=14),
                height=40,
                anchor="w",
                corner_radius=5,
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                command=lambda t=tab_name: handle_nav_click(t)
            )
            btn.pack(fill="x", padx=10, pady=5)
            self.nav_buttons[tab_name] = btn
        
        # Version info at the bottom
        ctk.CTkLabel(
            self.sidebar, 
            text="v2.0.0", 
            font=ctk.CTkFont(size=12)
        ).pack(side="bottom", pady=10)
        
    def create_status_bar(self):
        """Create an animated status bar at the bottom of the window"""
        self.status_frame = ctk.CTkFrame(self.root, height=30, fg_color=("gray90", "gray20"))
        self.status_frame.pack(side="bottom", fill="x")
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready", anchor="w")
        self.status_label.pack(side="left", padx=10)
        
        # Display current date and time in status bar
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label = ctk.CTkLabel(self.status_frame, text=current_time, anchor="e")
        self.time_label.pack(side="right", padx=10)
        
        # Initialize animation variables
        self.status_text = ""
        self.target_status_text = "Ready"
        self.typing_index = 0
        self.typing_speed = 50  # milliseconds per character
        
    def create_content_area(self):
        """Create the main content area with frames for each tab"""
        # Content frame
        self.content = ctk.CTkFrame(self.main_container, corner_radius=10)
        self.content.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Create frames for each section
        self.frames = {}
        
        # Encrypt frame
        self.frames["encrypt"] = ctk.CTkFrame(self.content, corner_radius=0)
        self.setup_encrypt_frame(self.frames["encrypt"])
        
        # Decrypt frame
        self.frames["decrypt"] = ctk.CTkFrame(self.content, corner_radius=0)
        self.setup_decrypt_frame(self.frames["decrypt"])
        
        # Steganography frame
        self.frames["stego"] = ctk.CTkFrame(self.content, corner_radius=0)
        self.setup_steganography_frame(self.frames["stego"])
        
        # Recent files frame
        self.frames["recent"] = ctk.CTkFrame(self.content, corner_radius=0)
        self.setup_recent_frame(self.frames["recent"])
        
        # Logs frame
        self.frames["logs"] = ctk.CTkFrame(self.content, corner_radius=0)
        self.setup_logs_frame(self.frames["logs"])
        
        # Settings frame
        self.frames["settings"] = ctk.CTkFrame(self.content, corner_radius=0)
        self.setup_settings_frame(self.frames["settings"])
        
        # Initially hide all frames
        for frame in self.frames.values():
            frame.pack_forget()
    
    def show_frame(self, tab_name):
        """Show the selected frame with an animation effect"""
        # Hide all frames
        for frame in self.frames.values():
            frame.pack_forget()
        
        # Update the selected nav button
        for btn_name, btn in self.nav_buttons.items():
            if btn_name == tab_name:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")
        
        # Show the selected frame with a slight animation
        frame = self.frames[tab_name]
        frame.pack(fill="both", expand=True)
        
        # Apply a fade-in effect
        frame.update_idletasks()
        frame._fg_color = frame._fg_color  # This forces a redraw
        
        # Set status message based on tab
        status_messages = {
            "encrypt": "Ready to encrypt files securely...",
            "decrypt": "Decrypt your protected files here...",
            "stego": "Hide or extract data using steganography...",
            "recent": "View your recently accessed files...",
            "logs": "Check activity logs and security events...",
            "settings": "Configure application settings and security options..."
        }
        self.animate_status_text(status_messages.get(tab_name, "Ready"))
        
        # Update current time in status bar
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.configure(text=current_time)
    
    def animate_status_text(self, new_text):
        """Animate the status text with a typing effect"""
        self.target_status_text = new_text
        self.typing_index = 0
        self.status_text = ""
        self.type_next_char()
    
    def type_next_char(self):
        """Type the next character in the status animation"""
        if self.typing_index < len(self.target_status_text):
            self.status_text += self.target_status_text[self.typing_index]
            self.status_label.configure(text=self.status_text)
            self.typing_index += 1
            self.root.after(self.typing_speed, self.type_next_char)
    
    def change_appearance_mode(self, new_mode):
        """Change the appearance mode (light/dark)"""
        ctk.set_appearance_mode(new_mode)
    
    def change_color_theme(self, new_theme):
        """Change the color theme"""
        ctk.set_default_color_theme(new_theme)
        # This requires app restart to fully take effect for all widgets
        confirm = CTkMessagebox(
            title="Restart Required", 
            message="Some changes will only take effect after restarting the application. Restart now?",
            icon="question",
            option_1="Yes",
            option_2="No"
        )
        if confirm.get() == "Yes":
            self.root.destroy()
            # Re-launch the application (this would need to be implemented based on how the app is started)
    
    def setup_encrypt_frame(self, parent):
        """Set up the encrypt tab with all components"""
        # Create a scrollable frame
        container = ctk.CTkScrollableFrame(parent, corner_radius=0)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title with animation effect
        title_label = ctk.CTkLabel(
            container, 
            text="Encrypt Folder", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(anchor="w", pady=(0, 20))
        
        # Description with fade-in effect
        desc_label = ctk.CTkLabel(
            container,
            text="Protect your sensitive files with strong encryption",
            font=ctk.CTkFont(size=14),
            text_color=("gray40", "gray60")
        )
        desc_label.pack(anchor="w", pady=(0, 20))
        
        # Folder selection with glowing effect on hover
        folder_frame = ctk.CTkFrame(container)
        folder_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            folder_frame, 
            text="Select Folder to Encrypt:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        folder_input_frame = ctk.CTkFrame(folder_frame, fg_color="transparent")
        folder_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.encrypt_folder_var = tk.StringVar()
        folder_entry = ctk.CTkEntry(
            folder_input_frame, 
            textvariable=self.encrypt_folder_var,
            height=40,
            placeholder_text="Path to folder"
        )
        folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_btn = ctk.CTkButton(
            folder_input_frame,
            text="Browse",
            width=100,
            height=40,
            command=self.browse_encrypt_folder
        )
        browse_btn.pack(side="right")
        
        # Password section with animated strength meter
        password_frame = ctk.CTkFrame(container)
        password_frame.pack(fill="x", pady=15)
        
        ctk.CTkLabel(
            password_frame, 
            text="Set Encryption Password:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.encrypt_password_var = tk.StringVar()
        password_entry = ctk.CTkEntry(
            password_frame, 
            textvariable=self.encrypt_password_var,
            show="•",
            height=40,
            placeholder_text="Enter strong password"
        )
        password_entry.pack(fill="x", padx=10, pady=5)
        password_entry.bind("<KeyRelease>", self.check_password_strength)
        
        # Password strength meter
        strength_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        strength_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(strength_frame, text="Password Strength:").pack(side="left")
        
        self.strength_var = tk.IntVar(value=0)
        self.strength_bar = ctk.CTkProgressBar(strength_frame, height=10)
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=10)
        self.strength_bar.set(0)
        
        self.strength_label = ctk.CTkLabel(strength_frame, text="No password")
        self.strength_label.pack(side="left")
        
        # Confirm password
        ctk.CTkLabel(
            password_frame, 
            text="Confirm Password:", 
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.encrypt_confirm_password_var = tk.StringVar()
        ctk.CTkEntry(
            password_frame, 
            textvariable=self.encrypt_confirm_password_var,
            show="•",
            height=40,
            placeholder_text="Confirm your password"
        ).pack(fill="x", padx=10, pady=5)
        
        # Options section
        options_frame = ctk.CTkFrame(container)
        options_frame.pack(fill="x", pady=15)
        
        ctk.CTkLabel(
            options_frame, 
            text="Encryption Options:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Algorithm selection
        algo_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        algo_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(algo_frame, text="Algorithm:").pack(side="left")
        
        self.algorithm_var = tk.StringVar(value="AES-256")
        algorithm_combo = ctk.CTkOptionMenu(
            algo_frame,
            variable=self.algorithm_var,
            values=list(self.encryptor.encryption_algorithms.keys()),
            width=150,
            height=32
        )
        algorithm_combo.pack(side="left", padx=10)
        
        # Checkboxes for options
        self.shred_var = tk.BooleanVar(value=False)
        shred_cb = ctk.CTkCheckBox(
            options_frame,
            text="Securely delete original files after encryption",
            variable=self.shred_var,
            checkbox_height=24,
            checkbox_width=24
        )
        shred_cb.pack(anchor="w", padx=10, pady=5)
        
        self.save_password_var = tk.BooleanVar(value=False)
        self.save_password_cb = ctk.CTkCheckBox(
            options_frame,
            text="Save encryption password (protected by master password)",
            variable=self.save_password_var,
            checkbox_height=24,
            checkbox_width=24
        )
        self.save_password_cb.pack(anchor="w", padx=10, pady=5)
        
        # Check if master password is set
        if not self.password_manager.has_master_password():
            self.save_password_cb.configure(state="disabled")
            
        # Progress bar with animated label
        progress_frame = ctk.CTkFrame(container)
        progress_frame.pack(fill="x", pady=15)
        
        self.encrypt_progress_label = ctk.CTkLabel(
            progress_frame, 
            text="Ready to encrypt"
        )
        self.encrypt_progress_label.pack(anchor="w", padx=10, pady=(10, 5))
        
        self.encrypt_progress = ctk.CTkProgressBar(progress_frame, height=15)
        self.encrypt_progress.pack(fill="x", padx=10, pady=5)
        self.encrypt_progress.set(0)
        
        # Encrypt button with hover effect
        encrypt_button = ctk.CTkButton(
            container,
            text="Encrypt Folder",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.encrypt_folder,
            hover_color=("darkblue", "#144870")
        )
        encrypt_button.pack(fill="x", pady=20)
        
        # Drop zone (visual indicator)
        # drop_frame = ctk.CTkFrame(container, fg_color=("gray90", "gray20"), corner_radius=10)
        # drop_frame.pack(fill="x", pady=10, ipady=20)
        
        # ctk.CTkLabel(
        #     drop_frame,
        #     text="Or drop folder here to encrypt",
        #     font=ctk.CTkFont(size=16),
        #     text_color=("gray40", "gray70")
        # ).pack(pady=10)
    
    def setup_decrypt_frame(self, parent):
        """Set up the decrypt tab with all components"""
        # Create a scrollable frame
        container = ctk.CTkScrollableFrame(parent, corner_radius=0)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            container, 
            text="Decrypt Folder", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", pady=(0, 20))
        
        # Description
        ctk.CTkLabel(
            container,
            text="Access your encrypted files securely",
            font=ctk.CTkFont(size=14),
            text_color=("gray40", "gray60")
        ).pack(anchor="w", pady=(0, 20))
        
        # Encrypted folder selection
        folder_frame = ctk.CTkFrame(container)
        folder_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            folder_frame, 
            text="Select Encrypted Folder:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        folder_input_frame = ctk.CTkFrame(folder_frame, fg_color="transparent")
        folder_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.decrypt_folder_var = tk.StringVar()
        folder_entry = ctk.CTkEntry(
            folder_input_frame, 
            textvariable=self.decrypt_folder_var,
            height=40,
            placeholder_text="Path to encrypted folder"
        )
        folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_btn = ctk.CTkButton(
            folder_input_frame,
            text="Browse",
            width=100,
            height=40,
            command=self.browse_decrypt_folder
        )
        browse_btn.pack(side="right")
        
        # Output folder selection
        output_frame = ctk.CTkFrame(container)
        output_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            output_frame, 
            text="Select Output Folder (Optional):", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        output_input_frame = ctk.CTkFrame(output_frame, fg_color="transparent")
        output_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.output_folder_var = tk.StringVar()
        output_entry = ctk.CTkEntry(
            output_input_frame, 
            textvariable=self.output_folder_var,
            height=40,
            placeholder_text="Leave empty for default location"
        )
        output_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_output_btn = ctk.CTkButton(
            output_input_frame,
            text="Browse",
            width=100,
            height=40,
            command=self.browse_output_folder
        )
        browse_output_btn.pack(side="right")
        
        # Password section
        password_frame = ctk.CTkFrame(container)
        password_frame.pack(fill="x", pady=15)
        
        ctk.CTkLabel(
            password_frame, 
            text="Enter Decryption Password:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        password_input_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        password_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.decrypt_password_var = tk.StringVar()
        self.decrypt_password_entry = ctk.CTkEntry(
            password_input_frame, 
            textvariable=self.decrypt_password_var,
            show="•",
            height=40,
            placeholder_text="Enter your decryption password"
        )
        self.decrypt_password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        load_pw_btn = ctk.CTkButton(
            password_input_frame,
            text="Load Saved",
            width=120,
            height=40,
            command=self.load_saved_password
        )
        load_pw_btn.pack(side="right")
        
        # Options section
        options_frame = ctk.CTkFrame(container)
        options_frame.pack(fill="x", pady=15)
        
        ctk.CTkLabel(
            options_frame, 
            text="Decryption Options:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Checkboxes for options
        self.integrity_check_var = tk.BooleanVar(value=True)
        integrity_cb = ctk.CTkCheckBox(
            options_frame,
            text="Verify file integrity after decryption",
            variable=self.integrity_check_var,
            checkbox_height=24,
            checkbox_width=24
        )
        integrity_cb.pack(anchor="w", padx=10, pady=5)
        
        # Progress bar
        progress_frame = ctk.CTkFrame(container)
        progress_frame.pack(fill="x", pady=15)
        
        self.decrypt_progress_label = ctk.CTkLabel(
            progress_frame, 
            text="Ready to decrypt"
        )
        self.decrypt_progress_label.pack(anchor="w", padx=10, pady=(10, 5))
        
        self.decrypt_progress = ctk.CTkProgressBar(progress_frame, height=15)
        self.decrypt_progress.pack(fill="x", padx=10, pady=5)
        self.decrypt_progress.set(0)
        
        # Decrypt button
        decrypt_button = ctk.CTkButton(
            container,
            text="Decrypt Folder",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.decrypt_folder,
            fg_color="#007bff",
            hover_color=("darkblue", "#144870")
        )
        decrypt_button.pack(fill="x", pady=20)
        
        # Drop zone
        # drop_frame = ctk.CTkFrame(container, fg_color=("gray90", "gray20"), corner_radius=10)
        # drop_frame.pack(fill="x", pady=10, ipady=20)
        
        # ctk.CTkLabel(
        #     drop_frame,
        #     text="Or drop encrypted folder here",
        #     font=ctk.CTkFont(size=16),
        #     text_color=("gray40", "gray70")
        # ).pack(pady=10)

    def setup_steganography_frame(self, parent):
        """Set up the steganography tab with all components"""
        # Create a notebook for hide/extract tabs
        self.stego_notebook = ctk.CTkTabview(parent, corner_radius=0)
        self.stego_notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Add tabs
        self.stego_notebook.add("Hide Data")
        self.stego_notebook.add("Extract Data")
        
        # Set up hide data tab
        hide_tab = self.stego_notebook.tab("Hide Data")
        self.setup_hide_data_tab(hide_tab)
        
        # Set up extract data tab
        extract_tab = self.stego_notebook.tab("Extract Data")
        self.setup_extract_data_tab(extract_tab)

    def setup_hide_data_tab(self, parent):
        """Setup tab for hiding data in images"""
        # Create a scrollable frame to contain all content
        scrollable_container = ctk.CTkScrollableFrame(parent)
        scrollable_container.pack(fill="both", expand=True)
        
        # Title
        ctk.CTkLabel(
            scrollable_container, 
            text="Hide Data in Images", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", pady=(0, 15))
        
        # Description
        ctk.CTkLabel(
            scrollable_container,
            text="Conceal sensitive information inside innocent-looking images",
            font=ctk.CTkFont(size=14),
            text_color=("gray40", "gray60")
        ).pack(anchor="w", pady=(0, 20))
        
        # Carrier image selection
        image_frame = ctk.CTkFrame(scrollable_container)
        image_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            image_frame, 
            text="Select Carrier Image:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        image_input_frame = ctk.CTkFrame(image_frame, fg_color="transparent")
        image_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.carrier_image_var = tk.StringVar()
        image_entry = ctk.CTkEntry(
            image_input_frame, 
            textvariable=self.carrier_image_var,
            height=40,
            placeholder_text="Path to PNG or BMP image"
        )
        image_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_image_btn = ctk.CTkButton(
            image_input_frame,
            text="Browse",
            width=100,
            height=40,
            command=self.browse_carrier_image
        )
        browse_image_btn.pack(side="right")
        
        # Image preview and capacity info
        preview_frame = ctk.CTkFrame(scrollable_container)
        preview_frame.pack(fill="x", pady=10)
        
        self.carrier_preview_frame = ctk.CTkFrame(preview_frame, width=200, height=150)
        self.carrier_preview_frame.pack(side="left", padx=10, pady=10)
        
        self.carrier_preview_label = ctk.CTkLabel(
            self.carrier_preview_frame,
            text="Image Preview",
            font=ctk.CTkFont(size=12)
        )
        self.carrier_preview_label.place(relx=0.5, rely=0.5, anchor="center")
        
        # Capacity info
        capacity_info = ctk.CTkFrame(preview_frame)
        capacity_info.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(
            capacity_info,
            text="Capacity Information:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.capacity_label = ctk.CTkLabel(
            capacity_info,
            text="No image selected",
            font=ctk.CTkFont(size=12)
        )
        self.capacity_label.pack(anchor="w", padx=10, pady=5)
        
        # Data to hide section
        data_frame = ctk.CTkFrame(scrollable_container)
        data_frame.pack(fill="x", pady=10)
        
        # Tabs for different data input methods - FIX: Store reference as class attribute
        self.data_tabs = ctk.CTkTabview(data_frame, height=200)
        self.data_tabs.pack(fill="x", padx=10, pady=10)
        self.data_tabs.add("Text")
        self.data_tabs.add("File")
        
        # Text tab
        text_tab = self.data_tabs.tab("Text")
        ctk.CTkLabel(
            text_tab,
            text="Enter text to hide:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.hide_text_entry = ctk.CTkTextbox(text_tab, height=120)
        self.hide_text_entry.pack(fill="both", expand=True, padx=10, pady=5)
        
        # File tab
        file_tab = self.data_tabs.tab("File")
        ctk.CTkLabel(
            file_tab,
            text="Select file to hide:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        file_input_frame = ctk.CTkFrame(file_tab, fg_color="transparent")
        file_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.hide_file_var = tk.StringVar()
        file_entry = ctk.CTkEntry(
            file_input_frame, 
            textvariable=self.hide_file_var,
            height=40,
            placeholder_text="Path to file"
        )
        file_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_file_btn = ctk.CTkButton(
            file_input_frame,
            text="Browse",
            width=100,
            height=40,
            command=self.browse_file_to_hide
        )
        browse_file_btn.pack(side="right")
        
        # File info label
        self.file_info_label = ctk.CTkLabel(
            file_tab,
            text="No file selected",
            font=ctk.CTkFont(size=12)
        )
        self.file_info_label.pack(anchor="w", padx=10, pady=5)
        
        # Security options
        security_frame = ctk.CTkFrame(scrollable_container)
        security_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            security_frame,
            text="Security Options:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Password protection option
        password_frame = ctk.CTkFrame(security_frame, fg_color="transparent")
        password_frame.pack(fill="x", padx=10, pady=5)
        
        self.stego_password_enabled = tk.BooleanVar(value=False)
        stego_pw_checkbox = ctk.CTkCheckBox(
            password_frame,
            text="Password protect hidden data",
            variable=self.stego_password_enabled,
            command=self.toggle_stego_password,
            checkbox_height=24,
            checkbox_width=24
        )
        stego_pw_checkbox.pack(side="left", padx=5)
        
        self.stego_password_var = tk.StringVar()
        self.stego_password_entry = ctk.CTkEntry(
            password_frame,
            textvariable=self.stego_password_var,
            show="•",
            width=200,
            placeholder_text="Enter password",
            state="disabled"
        )
        self.stego_password_entry.pack(side="left", padx=10)
        
        # Output settings
        output_frame = ctk.CTkFrame(parent)
        output_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            output_frame,
            text="Output Settings:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        output_path_frame = ctk.CTkFrame(output_frame, fg_color="transparent")
        output_path_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(
            output_path_frame,
            text="Output image path:"
        ).pack(side="left", padx=5)
        
        self.stego_output_var = tk.StringVar()
        output_entry = ctk.CTkEntry(
            output_path_frame,
            textvariable=self.stego_output_var,
            width=300,
            placeholder_text="Leave empty to use default location"
        )
        output_entry.pack(side="left", fill="x", expand=True, padx=10)
        
        browse_output_btn = ctk.CTkButton(
            output_path_frame,
            text="Browse",
            width=100,
            command=self.browse_stego_output
        )
        browse_output_btn.pack(side="right")
        
        # Progress bar
        progress_frame = ctk.CTkFrame(parent)
        progress_frame.pack(fill="x", pady=10)
        
        self.stego_hide_progress_label = ctk.CTkLabel(
            progress_frame,
            text="Ready"
        )
        self.stego_hide_progress_label.pack(anchor="w", padx=10, pady=(5, 5))
        
        self.stego_hide_progress = ctk.CTkProgressBar(progress_frame, height=15)
        self.stego_hide_progress.pack(fill="x", padx=10, pady=5)
        self.stego_hide_progress.set(0)
        
        # Hide data button
        hide_button = ctk.CTkButton(
            parent,
            text="Hide Data",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.hide_data,
            fg_color="#007bff",
            hover_color="#0056b3"
        )
        hide_button.pack(fill="x", padx=10, pady=20)

    def setup_extract_data_tab(self, parent):
        """Setup tab for extracting hidden data from images"""
        # Create a scrollable frame to contain all content
        scrollable_container = ctk.CTkScrollableFrame(parent)
        scrollable_container.pack(fill="both", expand=True)
        
        # Title
        ctk.CTkLabel(
            scrollable_container, 
            text="Extract Hidden Data", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", pady=(0, 15))
        
        # Description
        ctk.CTkLabel(
            scrollable_container,
            text="Retrieve concealed data from steganographic images",
            font=ctk.CTkFont(size=14),
            text_color=("gray40", "gray60")
        ).pack(anchor="w", pady=(0, 20))
        
        # Image selection
        image_frame = ctk.CTkFrame(scrollable_container)
        image_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            image_frame, 
            text="Select Image with Hidden Data:", 
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        image_input_frame = ctk.CTkFrame(image_frame, fg_color="transparent")
        image_input_frame.pack(fill="x", padx=10, pady=5)
        
        self.extract_image_var = tk.StringVar()
        image_entry = ctk.CTkEntry(
            image_input_frame, 
            textvariable=self.extract_image_var,
            height=40,
            placeholder_text="Path to image with hidden data"
        )
        image_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_image_btn = ctk.CTkButton(
            image_input_frame,
            text="Browse",
            width=100,
            height=40,
            command=self.browse_stego_image
        )
        browse_image_btn.pack(side="right")
        
        # Image preview 
        preview_frame = ctk.CTkFrame(scrollable_container)
        preview_frame.pack(fill="x", pady=10)
        
        self.stego_preview_frame = ctk.CTkFrame(preview_frame, width=200, height=150)
        self.stego_preview_frame.pack(side="left", padx=10, pady=10)
        
        self.stego_preview_label = ctk.CTkLabel(
            self.stego_preview_frame,
            text="Image Preview",
            font=ctk.CTkFont(size=12)
        )
        self.stego_preview_label.place(relx=0.5, rely=0.5, anchor="center")
        
        # Detection info
        detection_info = ctk.CTkFrame(preview_frame)
        detection_info.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(
            detection_info,
            text="Detection Results:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        
        self.detection_label = ctk.CTkLabel(
            detection_info,
            text="No image selected",
            font=ctk.CTkFont(size=12)
        )
        self.detection_label.pack(anchor="w", padx=10, pady=5)
        
        detect_btn = ctk.CTkButton(
            detection_info,
            text="Analyze Image",
            command=self.analyze_stego_image
        )
        detect_btn.pack(anchor="w", padx=10, pady=5)
        
        # Password section
        password_frame = ctk.CTkFrame(scrollable_container)
        password_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            password_frame,
            text="Extraction Password (if required):",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.extract_password_var = tk.StringVar()
        password_entry = ctk.CTkEntry(
            password_frame,
            textvariable=self.extract_password_var,
            show="•",
            placeholder_text="Leave empty if no password"
        )
        password_entry.pack(fill="x", padx=10, pady=5)
        
        # Output options
        output_frame = ctk.CTkFrame(scrollable_container)
        output_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            output_frame,
            text="Output Options:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Output method selection
        self.extract_output_method = tk.StringVar(value="view")
        
        view_radio = ctk.CTkRadioButton(
            output_frame,
            text="View extracted data",
            variable=self.extract_output_method,
            value="view",
            command=self.toggle_extract_output
        )
        view_radio.pack(anchor="w", padx=20, pady=5)
        
        save_radio = ctk.CTkRadioButton(
            output_frame,
            text="Save extracted data to file",
            variable=self.extract_output_method,
            value="save",
            command=self.toggle_extract_output
        )
        save_radio.pack(anchor="w", padx=20, pady=5)
        
        # Save path frame (initially hidden)
        self.save_path_frame = ctk.CTkFrame(output_frame, fg_color="transparent")
        
        self.extract_save_path_var = tk.StringVar()
        save_entry = ctk.CTkEntry(
            self.save_path_frame,
            textvariable=self.extract_save_path_var,
            placeholder_text="Output file path"
        )
        save_entry.pack(side="left", fill="x", expand=True, padx=(20, 10))
        
        save_browse_btn = ctk.CTkButton(
            self.save_path_frame,
            text="Browse",
            width=100,
            command=self.browse_extract_output
        )
        save_browse_btn.pack(side="right", padx=(0, 10))
        
        # Progress bar
        progress_frame = ctk.CTkFrame(parent)
        progress_frame.pack(fill="x", pady=10)
        
        self.stego_extract_progress_label = ctk.CTkLabel(
            progress_frame,
            text="Ready"
        )
        self.stego_extract_progress_label.pack(anchor="w", padx=10, pady=(5, 5))
        
        self.stego_extract_progress = ctk.CTkProgressBar(progress_frame, height=15)
        self.stego_extract_progress.pack(fill="x", padx=10, pady=5)
        self.stego_extract_progress.set(0)
        
        # Extract button
        extract_button = ctk.CTkButton(
            parent,
            text="Extract Data",
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.extract_data,
            fg_color="#007bff",
            hover_color="#0056b3"
        )
        extract_button.pack(fill="x", padx=10, pady=20)
    
    def toggle_stego_password(self):
        """Enable or disable the password entry based on checkbox"""
        if self.stego_password_enabled.get():
            self.stego_password_entry.configure(state="normal")
        else:
            self.stego_password_entry.configure(state="disabled")
    
    def toggle_extract_output(self):
        """Show or hide save path frame based on output method"""
        if self.extract_output_method.get() == "save":
            self.save_path_frame.pack(fill="x", pady=5)
        else:
            self.save_path_frame.pack_forget()
    
    def browse_carrier_image(self):
        """Browse for a carrier image"""
        filetypes = [("Supported Images", "*.png *.bmp"), ("PNG files", "*.png"), ("BMP files", "*.bmp")]
        image_path = filedialog.askopenfilename(title="Select Carrier Image", filetypes=filetypes)
        if image_path:
            self.carrier_image_var.set(image_path)
            self.update_carrier_preview(image_path)
            self.animate_status_text(f"Selected carrier image: {os.path.basename(image_path)}")
    
    def browse_file_to_hide(self):
        """Browse for a file to hide"""
        file_path = filedialog.askopenfilename(title="Select File to Hide")
        if file_path:
            self.hide_file_var.set(file_path)
            self.update_file_info(file_path)
            self.animate_status_text(f"Selected file to hide: {os.path.basename(file_path)}")
    
    def browse_stego_output(self):
        """Browse for output location for steganography"""
        file_path = filedialog.asksaveasfilename(
            title="Save Output Image As", 
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if file_path:
            self.stego_output_var.set(file_path)
            self.animate_status_text(f"Selected output path: {os.path.basename(file_path)}")
    
    def browse_stego_image(self):
        """Browse for an image with hidden data"""
        filetypes = [("Supported Images", "*.png *.bmp"), ("PNG files", "*.png"), ("BMP files", "*.bmp")]
        image_path = filedialog.askopenfilename(title="Select Image with Hidden Data", filetypes=filetypes)
        if image_path:
            self.extract_image_var.set(image_path)
            self.update_stego_preview(image_path)
            self.analyze_stego_image()
            self.animate_status_text(f"Selected image: {os.path.basename(image_path)}")
    
    def browse_extract_output(self):
        """Browse for output location for extracted data"""
        file_path = filedialog.asksaveasfilename(title="Save Extracted Data As")
        if file_path:
            self.extract_save_path_var.set(file_path)
            self.animate_status_text(f"Selected save path: {os.path.basename(file_path)}")
    
    def update_carrier_preview(self, image_path):
        """Update the carrier image preview and capacity info"""
        try:
            # Load and resize image for preview
            img = Image.open(image_path)
            
            # Calculate capacity
            capacity = self.steganography.get_image_capacity(image_path)
            
            # Update capacity label
            self.capacity_label.configure(text=f"Maximum data size: {capacity/1024:.2f} KB")
            
            # Resize for preview
            width, height = img.size
            max_size = 150
            scale = min(max_size / width, max_size / height)
            new_size = (int(width * scale), int(height * scale))
            
            img_resized = img.resize(new_size, Image.LANCZOS)
            
            # Convert to CTkImage for proper HighDPI display
            photo = ctk.CTkImage(light_image=img_resized, dark_image=img_resized, size=new_size)
            
            # Clear previous content and show image
            for widget in self.carrier_preview_frame.winfo_children():
                widget.destroy()
                
            img_label = ctk.CTkLabel(self.carrier_preview_frame, image=photo, text="")
            img_label.image = photo  # Keep a reference
            img_label.place(relx=0.5, rely=0.5, anchor="center")
            
        except Exception as e:
            logging.error(f"Error updating preview: {e}")
            self.capacity_label.configure(text="Error loading image")
    
    def update_stego_preview(self, image_path):
        """Update the stego image preview"""
        try:
            # Load and resize image for preview
            img = Image.open(image_path)
            
            # Resize for preview
            width, height = img.size
            max_size = 150
            scale = min(max_size / width, max_size / height)
            new_size = (int(width * scale), int(height * scale))
            
            img_resized = img.resize(new_size, Image.LANCZOS)
            
            # Convert to CTkImage for proper HighDPI display
            photo = ctk.CTkImage(light_image=img_resized, dark_image=img_resized, size=new_size)
            
            # Clear previous content and show image
            for widget in self.stego_preview_frame.winfo_children():
                widget.destroy()
                
            img_label = ctk.CTkLabel(self.stego_preview_frame, image=photo, text="")
            img_label.image = photo  # Keep a reference
            img_label.place(relx=0.5, rely=0.5, anchor="center")
            
        except Exception as e:
            logging.error(f"Error updating preview: {e}")
    
    def update_file_info(self, file_path):
        """Update file info label with details about the selected file"""
        try:
            size = os.path.getsize(file_path)
            file_type = "Binary file"
            
            # Try to identify text files
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(1024)  # Try to read some content
                file_type = "Text file"
            except UnicodeDecodeError:
                pass  # Not a text file
            
            self.file_info_label.configure(
                text=f"File: {os.path.basename(file_path)}\nSize: {size/1024:.2f} KB\nType: {file_type}"
            )
        except Exception as e:
            self.file_info_label.configure(text=f"Error: {e}")
    
    def analyze_stego_image(self):
        """Analyze image to detect hidden data"""
        image_path = self.extract_image_var.get()
        if not image_path:
            self.detection_label.configure(text="No image selected")
            return
            
        try:
            # Check if the file is a supported format
            if not self.steganography.is_file_supported(image_path):
                self.detection_label.configure(text="Unsupported image format.\nOnly PNG and BMP are supported.")
                return
                
            # Check for hidden data
            has_data = self.steganography.has_hidden_data(image_path)
            
            if has_data:
                self.detection_label.configure(
                    text="✅ Hidden data detected.\nExtract to view contents.",
                    text_color=("green", "#00aa00")
                )
            else:
                self.detection_label.configure(
                    text="❌ No hidden data detected\nor pattern is unrecognized.",
                    text_color=("red", "#cc0000")
                )
                
        except Exception as e:
            self.detection_label.configure(text=f"Analysis error: {e}")
    
    def hide_data(self):
        """Hide data in the carrier image"""
        # Get input values
        carrier_image = self.carrier_image_var.get()
        use_password = self.stego_password_enabled.get()
        password = self.stego_password_var.get() if use_password else None
        output_path = self.stego_output_var.get() or None
        
        # Validate image
        if not carrier_image:
            CTkMessagebox(title="Error", message="Please select a carrier image", icon="cancel")
            return
            
        if not self.steganography.is_file_supported(carrier_image):
            CTkMessagebox(title="Error", message="Unsupported image format. Only PNG and BMP are supported.", icon="cancel")
            return
        
        # Get data to hide based on active tab
        active_tab = self.stego_notebook.get()
        
        if active_tab == "Hide Data":
            if self.data_tabs.get() == "Text":
                data = self.hide_text_entry.get("1.0", "end-1c")
                if not data:
                    CTkMessagebox(title="Error", message="Please enter text to hide", icon="cancel")
                    return
            else:  # File tab
                file_path = self.hide_file_var.get()
                if not file_path:
                    CTkMessagebox(title="Error", message="Please select a file to hide", icon="cancel")
                    return
                    
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()
                except Exception as e:
                    CTkMessagebox(title="Error", message=f"Failed to read file: {e}", icon="cancel")
                    return
        
        # Check if data can fit
        try:
            max_size, can_fit = self.steganography._can_fit_data(carrier_image, 
                                                                len(data) if isinstance(data, bytes) else len(data.encode()))
            if not can_fit:
                CTkMessagebox(
                    title="Error", 
                    message=f"Data is too large to hide in this image.\nMaximum size: {max_size/1024:.2f} KB", 
                    icon="cancel"
                )
                return
        except Exception as e:
            CTkMessagebox(title="Error", message=f"Error checking image capacity: {e}", icon="cancel")
            return
        
        # Set up progress
        self.stego_hide_progress.set(0)
        self.stego_hide_progress_label.configure(text="Processing...")
        self.animate_status_text("Hiding data in image...")
        
        # Use threading to keep UI responsive
        def hide_data_thread():
            try:
                # Simulate progress (actual steganography doesn't have progress tracking in our implementation)
                for i in range(1, 101):
                    self.root.after(0, lambda p=i: self.stego_hide_progress.set(p/100))
                    if i == 20:
                        self.root.after(0, lambda: self.stego_hide_progress_label.configure(text="Preparing data..."))
                    elif i == 40:
                        self.root.after(0, lambda: self.stego_hide_progress_label.configure(text="Embedding data..."))
                    elif i == 70:
                        self.root.after(0, lambda: self.stego_hide_progress_label.configure(text="Finalizing image..."))
                    elif i == 90:
                        self.root.after(0, lambda: self.stego_hide_progress_label.configure(text="Saving output..."))
                    time.sleep(0.02)
                
                # Perform steganography
                result_path = self.steganography.hide_data_in_image(carrier_image, data, output_path, password)
                
                # Update UI on success
                self.root.after(0, lambda: self.hide_data_success(result_path))
                
            except Exception as e:
                # Update UI on error
                self.root.after(0, lambda: self.hide_data_error(str(e)))
        
        # Start the thread
        threading.Thread(target=hide_data_thread).start()
    
    def hide_data_success(self, result_path):
        """Handle successful data hiding"""
        self.stego_hide_progress.set(1.0)
        self.stego_hide_progress_label.configure(text="Complete!")
        self.animate_status_text("Data hidden successfully")
        
        # Add to recent files
        self.recent_files.add_recent_file(result_path, "Steganography")
        
        # Show success message with the output path
        CTkMessagebox(
            title="Success", 
            message=f"Data successfully hidden in image.\nSaved to: {result_path}",
            icon="check"
        )
        
        # Reset progress bar after delay
        self.root.after(3000, lambda: self.stego_hide_progress.set(0))
    
    def hide_data_error(self, error_msg):
        """Handle error in data hiding"""
        self.stego_hide_progress.set(0)
        self.stego_hide_progress_label.configure(text="Failed!")
        self.animate_status_text("Failed to hide data")
        
        # Show error message
        CTkMessagebox(
            title="Error", 
            message=f"Failed to hide data: {error_msg}",
            icon="cancel"
        )
    
    def extract_data(self):
        """Extract hidden data from image"""
        # Get input values
        image_path = self.extract_image_var.get()
        password = self.extract_password_var.get() or None
        output_method = self.extract_output_method.get()
        output_path = self.extract_save_path_var.get() if output_method == "save" else None
        
        # Validate inputs
        if not image_path:
            CTkMessagebox(title="Error", message="Please select an image with hidden data", icon="cancel")
            return
            
        if not self.steganography.is_file_supported(image_path):
            CTkMessagebox(title="Error", message="Unsupported image format. Only PNG and BMP are supported.", icon="cancel")
            return
            
        if output_method == "save" and not output_path:
            CTkMessagebox(title="Error", message="Please specify an output path", icon="cancel")
            return
        
        # Set up progress
        self.stego_extract_progress.set(0)
        self.stego_extract_progress_label.configure(text="Processing...")
        self.animate_status_text("Extracting data from image...")
        
        # Use threading to keep UI responsive
        def extract_data_thread():
            try:
                # Simulate progress
                for i in range(1, 101):
                    self.root.after(0, lambda p=i: self.stego_extract_progress.set(p/100))
                    if i == 30:
                        self.root.after(0, lambda: self.stego_extract_progress_label.configure(text="Reading image data..."))
                    elif i == 60:
                        self.root.after(0, lambda: self.stego_extract_progress_label.configure(text="Extracting hidden data..."))
                    elif i == 90:
                        self.root.after(0, lambda: self.stego_extract_progress_label.configure(text="Processing extracted data..."))
                    time.sleep(0.02)
                
                # Extract data
                extracted_data = self.steganography.extract_data_from_image(image_path, password)
                
                # Handle extracted data based on output method
                if output_method == "save":
                    # Save to file
                    with open(output_path, 'wb' if isinstance(extracted_data, bytes) else 'w') as f:
                        f.write(extracted_data)
                    result_info = f"Data saved to: {output_path}"
                else:
                    # View in dialog
                    result_info = extracted_data if isinstance(extracted_data, str) else f"Binary data ({len(extracted_data)} bytes)"
                
                # Update UI on success
                self.root.after(0, lambda: self.extract_data_success(result_info, output_method == "save"))
                
            except Exception as e:
                # Update UI on error
                self.root.after(0, lambda: self.extract_data_error(str(e)))
        
        # Start the thread
        threading.Thread(target=extract_data_thread).start()
    
    def extract_data_success(self, result_info, saved_to_file=False):
        """Handle successful data extraction"""
        self.stego_extract_progress.set(1.0)
        self.stego_extract_progress_label.configure(text="Complete!")
        self.animate_status_text("Data extracted successfully")
        
        if saved_to_file:
            # Show success message with the output path
            CTkMessagebox(
                title="Success", 
                message=f"Data successfully extracted.\n{result_info}",
                icon="check"
            )
        else:
            # Show extracted data in a dialog
            self.show_extracted_data(result_info)
        
        # Reset progress bar after delay
        self.root.after(3000, lambda: self.stego_extract_progress.set(0))
    
    def extract_data_error(self, error_msg):
        """Handle error in data extraction"""
        self.stego_extract_progress.set(0)
        self.stego_extract_progress_label.configure(text="Failed!")
        self.animate_status_text("Failed to extract data")
        
        # Show error message
        CTkMessagebox(
            title="Error", 
            message=f"Failed to extract data: {error_msg}",
            icon="cancel"
        )
    
    def show_extracted_data(self, data):
        """Show extracted data in a dialog"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Extracted Data")
        dialog.geometry("600x600")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Create a text area for the data
        data_text = ctk.CTkTextbox(dialog, width=580, height=350)
        data_text.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Insert the data
        data_text.insert("1.0", data)
        
        # Make it read-only
        data_text.configure(state="disabled")
        
        # Add a close button
        close_btn = ctk.CTkButton(
            dialog,
            text="Close",
            command=dialog.destroy,
            width=100
        )
        close_btn.pack(pady=10)
    
    def setup_recent_frame(self, parent):
        """Setup the recent files tab"""
        # Create a main container
        container = ctk.CTkFrame(parent)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            header_frame, 
            text="Recent Files", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(side="left")
        
        # Refresh button
        refresh_btn = ctk.CTkButton(
            header_frame,
            text="🔄 Refresh",
            width=120,
            command=self.refresh_recent
        )
        refresh_btn.pack(side="right")
        
        # Clear button
        clear_btn = ctk.CTkButton(
            header_frame,
            text="🗑️ Clear History",
            width=120,
            fg_color="#dc3545",
            hover_color="#b02a37",
            command=self.clear_recent
        )
        clear_btn.pack(side="right", padx=10)
        
        # Create table frame
        table_frame = ctk.CTkFrame(container, fg_color=("gray95", "gray20"))
        table_frame.pack(fill="both", expand=True, pady=10)
        
        # Create a custom table with modern styling
        # Since CustomTkinter doesn't have a built-in treeview, we'll use a frame with labels
        self.recent_list_frame = ctk.CTkScrollableFrame(table_frame)
        self.recent_list_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Add headers
        header_frame = ctk.CTkFrame(self.recent_list_frame, height=40)
        header_frame.pack(fill="x", pady=(0, 10))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_columnconfigure(1, weight=3)
        header_frame.grid_columnconfigure(2, weight=2)
        
        ctk.CTkLabel(header_frame, text="Operation", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10)
        ctk.CTkLabel(header_frame, text="Path", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, sticky="w", padx=10)
        ctk.CTkLabel(header_frame, text="Date & Time", font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, sticky="w", padx=10)
        
        # Populate the list initially
        self.refresh_recent()
        
        # Button frame at bottom
        button_frame = ctk.CTkFrame(container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(15, 0))
        
        # Open selected button
        open_btn = ctk.CTkButton(
            button_frame,
            text="Open Selected File",
            width=200,
            height=40,
            command=self.open_selected_recent
        )
        open_btn.pack(side="left")
    
    def setup_logs_frame(self, parent):
        """Setup the activity logs tab"""
        # Create a main container
        container = ctk.CTkFrame(parent)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            header_frame, 
            text="Activity Logs", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(side="left")
        
        # Refresh button
        refresh_btn = ctk.CTkButton(
            header_frame,
            text="🔄 Refresh",
            width=120,
            command=self.refresh_logs
        )
        refresh_btn.pack(side="right")
        
        # Create table frame
        table_frame = ctk.CTkFrame(container, fg_color=("gray95", "gray20"))
        table_frame.pack(fill="both", expand=True, pady=10)
        
        # Since CustomTkinter doesn't have a built-in treeview, we'll use a frame with labels
        self.logs_list_frame = ctk.CTkScrollableFrame(table_frame)
        self.logs_list_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Add headers
        header_frame = ctk.CTkFrame(self.logs_list_frame, height=40)
        header_frame.pack(fill="x", pady=(0, 10))
        header_frame.grid_columnconfigure(0, weight=2)
        header_frame.grid_columnconfigure(1, weight=1)
        header_frame.grid_columnconfigure(2, weight=1)
        header_frame.grid_columnconfigure(3, weight=3)
        
        ctk.CTkLabel(header_frame, text="Date & Time", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10)
        ctk.CTkLabel(header_frame, text="Operation", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, sticky="w", padx=10)
        ctk.CTkLabel(header_frame, text="Status", font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, sticky="w", padx=10)
        ctk.CTkLabel(header_frame, text="Path", font=ctk.CTkFont(weight="bold")).grid(row=0, column=3, sticky="w", padx=10)
        
        # Populate the logs
        self.refresh_logs()
        
        # Button frame at bottom
        button_frame = ctk.CTkFrame(container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(15, 0))
        
        # View details button
        view_btn = ctk.CTkButton(
            button_frame,
            text="View Details",
            width=200,
            height=40,
            command=self.view_log_details
        )
        view_btn.pack(side="left")
    
    def setup_settings_frame(self, parent):
        """Setup the settings tab"""
        # Create a scrollable frame
        container = ctk.CTkScrollableFrame(parent)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            container, 
            text="Settings", 
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(anchor="w", pady=(0, 20))
        
        # Appearance section
        appearance_frame = ctk.CTkFrame(container)
        appearance_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            appearance_frame, 
            text="Appearance", 
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=15, pady=10)
        
        # Theme selection
        theme_frame = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        theme_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(theme_frame, text="Theme Mode:").pack(side="left")
        
        appearance_menu = ctk.CTkOptionMenu(
            theme_frame,
            values=["System", "Light", "Dark"],
            variable=self.appearance_mode_var,
            command=self.change_appearance_mode,
            width=150
        )
        appearance_menu.pack(side="left", padx=10)
        
        # Color theme
        color_frame = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        color_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(color_frame, text="Color Theme:").pack(side="left")
        
        color_menu = ctk.CTkOptionMenu(
            color_frame,
            values=["blue", "green", "dark-blue"],
            variable=self.color_theme_var,
            command=self.change_color_theme,
            width=150
        )
        color_menu.pack(side="left", padx=10)
        
        # Master password section
        master_pw_frame = ctk.CTkFrame(container)
        master_pw_frame.pack(fill="x", pady=15)
        
        ctk.CTkLabel(
            master_pw_frame, 
            text="Password Manager", 
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=15, pady=10)
        
        if self.password_manager.has_master_password():
            # Change master password
            ctk.CTkLabel(
                master_pw_frame, 
                text="Change master password:",
                font=ctk.CTkFont(weight="bold")
            ).pack(anchor="w", padx=15, pady=(10, 5))
            
            # Current password input
            current_pw_frame = ctk.CTkFrame(master_pw_frame, fg_color="transparent")
            current_pw_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(current_pw_frame, text="Current Password:").pack(side="left", padx=(0, 10))
            
            self.current_master_pw_var = tk.StringVar()
            current_pw_entry = ctk.CTkEntry(
                current_pw_frame, 
                textvariable=self.current_master_pw_var,
                show="•",
                width=250
            )
            current_pw_entry.pack(side="left")
            
            # New password
            new_pw_frame = ctk.CTkFrame(master_pw_frame, fg_color="transparent")
            new_pw_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(new_pw_frame, text="New Password:").pack(side="left", padx=(0, 25))
            
            self.new_master_pw_var = tk.StringVar()
            new_pw_entry = ctk.CTkEntry(
                new_pw_frame, 
                textvariable=self.new_master_pw_var,
                show="•",
                width=250
            )
            new_pw_entry.pack(side="left")
            
            # Confirm new password
            confirm_pw_frame = ctk.CTkFrame(master_pw_frame, fg_color="transparent")
            confirm_pw_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(confirm_pw_frame, text="Confirm Password:").pack(side="left", padx=(0, 10))
            
            self.confirm_master_pw_var = tk.StringVar()
            confirm_pw_entry = ctk.CTkEntry(
                confirm_pw_frame, 
                textvariable=self.confirm_master_pw_var,
                show="•",
                width=250
            )
            confirm_pw_entry.pack(side="left")
            
            # Change password button
            change_pw_btn = ctk.CTkButton(
                master_pw_frame,
                text="Change Master Password",
                command=self.change_master_password,
                fg_color="#007bff",
                hover_color="#0056b3",
                height=40
            )
            change_pw_btn.pack(anchor="e", padx=15, pady=10)
        else:
            # Set new master password
            ctk.CTkLabel(
                master_pw_frame, 
                text="Set a master password to enable password saving:",
                font=ctk.CTkFont(weight="bold")
            ).pack(anchor="w", padx=15, pady=(10, 15))
            
            # New password
            new_pw_frame = ctk.CTkFrame(master_pw_frame, fg_color="transparent")
            new_pw_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(new_pw_frame, text="Master Password:").pack(side="left", padx=(0, 10))
            
            self.new_master_pw_var = tk.StringVar()
            new_pw_entry = ctk.CTkEntry(
                new_pw_frame, 
                textvariable=self.new_master_pw_var,
                show="•",
                width=250
            )
            new_pw_entry.pack(side="left")
            
            # Confirm password
            confirm_pw_frame = ctk.CTkFrame(master_pw_frame, fg_color="transparent")
            confirm_pw_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(confirm_pw_frame, text="Confirm Password:").pack(side="left", padx=(0, 10))
            
            self.confirm_master_pw_var = tk.StringVar()
            confirm_pw_entry = ctk.CTkEntry(
                confirm_pw_frame, 
                textvariable=self.confirm_master_pw_var,
                show="•",
                width=250
            )
            confirm_pw_entry.pack(side="left")
            
            # Set password button
            set_pw_btn = ctk.CTkButton(
                master_pw_frame,
                text="Set Master Password",
                command=self.set_master_password,
                fg_color="#007bff",
                hover_color="#0056b3",
                height=40
            )
            set_pw_btn.pack(anchor="e", padx=15, pady=10)
        
        # Saved passwords section (only if master password is set)
        if self.password_manager.has_master_password():
            saved_pw_frame = ctk.CTkFrame(container)
            saved_pw_frame.pack(fill="x", pady=15)
            
            ctk.CTkLabel(
                saved_pw_frame, 
                text="Saved Passwords", 
                font=ctk.CTkFont(size=16, weight="bold")
            ).pack(anchor="w", padx=15, pady=10)
            
            # Master password input to view
            view_pw_frame = ctk.CTkFrame(saved_pw_frame, fg_color="transparent")
            view_pw_frame.pack(fill="x", padx=15, pady=5)
            
            ctk.CTkLabel(view_pw_frame, text="Enter master password to view:").pack(side="left", padx=(0, 10))
            
            self.view_master_pw_var = tk.StringVar()
            view_pw_entry = ctk.CTkEntry(
                view_pw_frame, 
                textvariable=self.view_master_pw_var,
                show="•",
                width=250
            )
            view_pw_entry.pack(side="left")
            
            # View passwords button
            view_pw_btn = ctk.CTkButton(
                saved_pw_frame,
                text="View Saved Passwords",
                command=self.view_saved_passwords,
                height=40
            )
            view_pw_btn.pack(anchor="e", padx=15, pady=10)
            
        # About section
        about_frame = ctk.CTkFrame(container)
        about_frame.pack(fill="x", pady=15)
        
        ctk.CTkLabel(
            about_frame, 
            text="About", 
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=15, pady=10)
        
        ctk.CTkLabel(
            about_frame, 
            text="Secure Vault Pro v2.0.0",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", padx=15, pady=2)
        
        ctk.CTkLabel(
            about_frame, 
            text="A modern, secure file encryption application",
            font=ctk.CTkFont(size=14),
            text_color=("gray40", "gray60")
        ).pack(anchor="w", padx=15, pady=2)
        
        # Display UTC time provided
        current_date = "2025-08-28 17:37:34"  # Using the date provided
        ctk.CTkLabel(
            about_frame, 
            text=f"© 2025 Secure Vault Team",
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60")
        ).pack(anchor="w", padx=15, pady=(2, 10))
        
        # User info
        user_frame = ctk.CTkFrame(about_frame, fg_color="transparent")
        user_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(
            user_frame,
            text="Current User:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("gray40", "gray60")
        ).pack(side="left")
        
        ctk.CTkLabel(
            user_frame,
            text="Atharva0177",  # Using the username provided
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60")
        ).pack(side="left", padx=5)

    def check_password_strength(self, event=None):
        """Check password strength and update the meter with animation"""
        password = self.encrypt_password_var.get()
        
        if not password:
            self.animate_strength_meter(0, "No password")
            return
            
        score, strength, feedback = self.password_meter.check_strength(password)
        
        # Animate the strength meter
        self.animate_strength_meter(score/100, strength)
    
    def animate_strength_meter(self, target_value, strength_text):
        """Animate the strength meter to the target value"""
        current = self.strength_bar.get()
        
        # Set color based on strength
        if target_value < 0.3:
            self.strength_bar.configure(progress_color="red")
        elif target_value < 0.6:
            self.strength_bar.configure(progress_color="orange")
        else:
            self.strength_bar.configure(progress_color="green")
        
        # Animate to target value
        def animate_step(current, target, steps=10):
            if abs(current - target) < 0.01:
                self.strength_bar.set(target)
                self.strength_label.configure(text=strength_text)
                return
            
            next_value = current + (target - current) / steps
            self.strength_bar.set(next_value)
            self.root.after(20, lambda: animate_step(next_value, target))
        
        animate_step(current, target_value)
    
    def browse_encrypt_folder(self):
        """Browse for a folder to encrypt"""
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if folder_path:
            self.encrypt_folder_var.set(folder_path)
            self.animate_status_text(f"Selected folder: {os.path.basename(folder_path)}")
    
    def browse_decrypt_folder(self):
        """Browse for an encrypted folder"""
        folder_path = filedialog.askdirectory(title="Select Encrypted Folder")
        if folder_path:
            self.decrypt_folder_var.set(folder_path)
            self.animate_status_text(f"Selected encrypted folder: {os.path.basename(folder_path)}")
    
    def browse_output_folder(self):
        """Browse for an output folder for decryption"""
        folder_path = filedialog.askdirectory(title="Select Output Folder")
        if folder_path:
            self.output_folder_var.set(folder_path)
            self.animate_status_text(f"Selected output folder: {os.path.basename(folder_path)}")
    
    def update_encrypt_progress(self, value):
        """Update the encryption progress bar"""
        self.encrypt_progress.set(value/100)
        self.encrypt_progress_label.configure(text=f"Encrypting: {int(value)}%")
        self.root.update_idletasks()
    
    def update_decrypt_progress(self, value):
        """Update the decryption progress bar"""
        self.decrypt_progress.set(value/100)
        self.decrypt_progress_label.configure(text=f"Decrypting: {int(value)}%")
        self.root.update_idletasks()
    
    def encrypt_folder(self):
        """Encrypt a folder with progress animation"""
        folder_path = self.encrypt_folder_var.get()
        password = self.encrypt_password_var.get()
        confirm_password = self.encrypt_confirm_password_var.get()
        algorithm = self.algorithm_var.get()
        shred_original = self.shred_var.get()
        save_password = self.save_password_var.get()
        
        # Validate inputs
        if not folder_path:
            CTkMessagebox(title="Error", message="Please select a folder to encrypt", icon="cancel")
            return
        
        if not password:
            CTkMessagebox(title="Error", message="Please enter a password", icon="cancel")
            return
        
        if password != confirm_password:
            CTkMessagebox(title="Error", message="Passwords do not match", icon="cancel")
            return
        
        # Check password strength
        score, strength, feedback = self.password_meter.check_strength(password)
        if score < 30:
            confirm = CTkMessagebox(
                title="Warning", 
                message=f"Your password is {strength} ({score}/100).\n{'; '.join(feedback)}.\n\nAre you sure you want to continue?",
                icon="warning",
                option_1="Yes",
                option_2="No"
            )
            if confirm.get() != "Yes":
                return
        
        # Start animation
        self.animate_status_text("Preparing to encrypt folder...")
        
        # Create a threading function to run encryption in background
        def encrypt_thread():
            try:
                encrypted_folder = self.encryptor.encrypt_folder(
                    folder_path, 
                    password,
                    algorithm,
                    shred_original,
                    progress_callback=self.update_encrypt_progress
                )
                
                # Add to recent files
                self.recent_files.add_recent_file(encrypted_folder, "Encrypt")
                
                # Save password if requested
                if save_password and self.password_manager.has_master_password():
                    # Show dialog to enter master password
                    master_password = self.prompt_for_master_password()
                    if master_password:
                        folder_name = os.path.basename(folder_path)
                        self.password_manager.save_password(
                            f"Encryption: {folder_name}",
                            folder_path,
                            password,
                            master_password
                        )
                
                # Update UI on the main thread
                                # Update UI on the main thread
                self.root.after(0, lambda: self.encryption_completed(encrypted_folder))
                
            except Exception as e:
                # Update UI on error
                self.root.after(0, lambda: self.encryption_failed(str(e)))
        
        # Start the thread
        self.encrypt_progress.set(0)
        threading.Thread(target=encrypt_thread).start()
    
    def encryption_completed(self, encrypted_folder):
        """Handle completed encryption"""
        self.encrypt_progress.set(1.0)
        self.encrypt_progress_label.configure(text="Encryption completed!")
        self.animate_status_text(f"Folder encrypted successfully to {os.path.basename(encrypted_folder)}")
        
        # Show success message
        CTkMessagebox(
            title="Success", 
            message=f"Folder encrypted successfully to:\n{encrypted_folder}",
            icon="check"
        )
        
        # Reset progress bar after a delay
        self.root.after(3000, lambda: self.encrypt_progress.set(0))
        
        # Refresh recent files tab
        self.refresh_recent()
    
    def encryption_failed(self, error_msg):
        """Handle encryption failure"""
        self.encrypt_progress.set(0)
        self.encrypt_progress_label.configure(text="Encryption failed!")
        self.animate_status_text("Encryption failed")
        
        # Show error message
        CTkMessagebox(
            title="Error", 
            message=f"Encryption failed: {error_msg}",
            icon="cancel"
        )
    
    def decrypt_folder(self):
        """Decrypt a folder with progress animation"""
        folder_path = self.decrypt_folder_var.get()
        password = self.decrypt_password_var.get()
        output_folder = self.output_folder_var.get() or None
        verify_integrity = self.integrity_check_var.get()
        
        # Validate inputs
        if not folder_path:
            CTkMessagebox(title="Error", message="Please select an encrypted folder", icon="cancel")
            return
        
        if not password:
            CTkMessagebox(title="Error", message="Please enter a password", icon="cancel")
            return
        
        # Start animation
        self.animate_status_text("Preparing to decrypt folder...")
        
        # Create a threading function to run decryption in background
        def decrypt_thread():
            try:
                decrypted_folder = self.encryptor.decrypt_folder(
                    folder_path, 
                    password,
                    output_folder,
                    verify_integrity,
                    progress_callback=self.update_decrypt_progress
                )
                
                # Add to recent files
                self.recent_files.add_recent_file(decrypted_folder, "Decrypt")
                
                # Update UI on the main thread
                self.root.after(0, lambda: self.decryption_completed(decrypted_folder))
                
            except ValueError as e:
                # Check if it's an incorrect password error
                error_msg = str(e)
                if "incorrect password" in error_msg.lower():
                    self.root.after(0, lambda: self.decryption_failed("Incorrect password or corrupted data"))
                else:
                    self.root.after(0, lambda: self.decryption_failed(error_msg))
            except Warning as e:
                # Integrity warnings - still completed but with issues
                self.root.after(0, lambda: self.decryption_warning(str(e)))
            except Exception as e:
                self.root.after(0, lambda: self.decryption_failed(str(e)))
        
        # Start the thread
        self.decrypt_progress.set(0)
        threading.Thread(target=decrypt_thread).start()
    
    def decryption_completed(self, decrypted_folder):
        """Handle completed decryption"""
        self.decrypt_progress.set(1.0)
        self.decrypt_progress_label.configure(text="Decryption completed!")
        self.animate_status_text(f"Folder decrypted successfully to {os.path.basename(decrypted_folder)}")
        
        # Show success message
        CTkMessagebox(
            title="Success", 
            message=f"Folder decrypted successfully to:\n{decrypted_folder}",
            icon="check"
        )
        
        # Reset progress bar after a delay
        self.root.after(3000, lambda: self.decrypt_progress.set(0))
        
        # Refresh recent files tab
        self.refresh_recent()
    
    def decryption_warning(self, warning_msg):
        """Handle decryption warnings"""
        self.decrypt_progress.set(1.0)
        self.decrypt_progress_label.configure(text="Decryption completed with warnings")
        self.animate_status_text("Decryption completed with integrity warnings")
        
        # Show warning message
        CTkMessagebox(
            title="Warning", 
            message=warning_msg,
            icon="warning"
        )
        
        # Refresh recent files tab
        self.refresh_recent()
    
    def decryption_failed(self, error_msg):
        """Handle decryption failure"""
        self.decrypt_progress.set(0)
        self.decrypt_progress_label.configure(text="Decryption failed!")
        self.animate_status_text("Decryption failed")
        
        # Show error message
        CTkMessagebox(
            title="Error", 
            message=f"Decryption failed: {error_msg}",
            icon="cancel"
        )
    
    def prompt_for_master_password(self):
        """Show a modal dialog to prompt for master password"""
        master_password = None
        
        # Create dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Enter Master Password")
        dialog.geometry("400x180")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Dialog content
        ctk.CTkLabel(
            dialog, 
            text="Enter your master password:", 
            font=ctk.CTkFont(size=16)
        ).pack(pady=(20, 15))
        
        pw_var = tk.StringVar()
        pw_entry = ctk.CTkEntry(
            dialog, 
            textvariable=pw_var, 
            show="•", 
            width=300,
            height=40
        )
        pw_entry.pack(pady=5)
        pw_entry.focus()
        
        # Variable to store the result
        result = {"password": None}
        
        def on_ok():
            entered_pw = pw_var.get()
            if self.password_manager.verify_master_password(entered_pw):
                result["password"] = entered_pw
                dialog.destroy()
            else:
                CTkMessagebox(master=dialog, title="Error", message="Incorrect master password", icon="cancel")
        
        def on_cancel():
            dialog.destroy()
        
        # Buttons
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(fill="x", pady=20)
        
        ctk.CTkButton(
            button_frame, 
            text="OK",
            width=150,
            command=on_ok
        ).pack(side="left", padx=(75, 5))
        
        ctk.CTkButton(
            button_frame, 
            text="Cancel", 
            width=150,
            fg_color="#6c757d",
            hover_color="#5a6268",
            command=on_cancel
        ).pack(side="left")
        
        # Bind Enter key
        dialog.bind("<Return>", lambda e: on_ok())
        
        # Wait for the dialog to close
        self.root.wait_window(dialog)
        return result["password"]
    
    def load_saved_password(self):
        """Show dialog to select a saved password"""
        if not self.password_manager.has_master_password():
            CTkMessagebox(title="Info", message="No master password set. Please set one in Settings.", icon="info")
            return
        
        master_password = self.prompt_for_master_password()
        if not master_password:
            return
            
        saved_passwords = self.password_manager.get_saved_passwords(master_password)
        if not saved_passwords:
            CTkMessagebox(title="Info", message="No saved passwords found or incorrect master password.", icon="info")
            return
        
        # Create a dialog to select a password
        selected_password = {"password": None, "path": None}
        
        # Create dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Select Saved Password")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Dialog content
        ctk.CTkLabel(
            dialog, 
            text="Select a saved password:", 
            font=ctk.CTkFont(size=16)
        ).pack(anchor="w", padx=20, pady=(20, 15))
        
        # Create a scrollable frame for passwords
        passwords_frame = ctk.CTkScrollableFrame(dialog, width=560, height=250)
        passwords_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Add password entries
        for i, pw in enumerate(saved_passwords):
            # Create a frame for this entry
            entry_frame = ctk.CTkFrame(passwords_frame)
            entry_frame.pack(fill="x", pady=5)
            
            # Name and path
            ctk.CTkLabel(
                entry_frame,
                text=pw['name'],
                font=ctk.CTkFont(weight="bold")
            ).pack(anchor="w", padx=10, pady=(5, 0))
            
            ctk.CTkLabel(
                entry_frame,
                text=pw['path'],
                font=ctk.CTkFont(size=12),
                text_color=("gray40", "gray70")
            ).pack(anchor="w", padx=10)
            
            # Date
            ctk.CTkLabel(
                entry_frame,
                text=f"Created: {pw['created_at']}",
                font=ctk.CTkFont(size=12),
                text_color=("gray40", "gray70")
            ).pack(anchor="w", padx=10, pady=(0, 5))
            
            # Select button
            def make_select_func(password_data):
                return lambda: (
                    selected_password.update({"password": password_data["password"], "path": password_data["path"]}),
                    dialog.destroy()
                )
            
            ctk.CTkButton(
                entry_frame,
                text="Select",
                width=80,
                height=24,
                command=make_select_func(pw)
            ).pack(anchor="e", padx=10, pady=(0, 5))
        
        # Buttons at the bottom
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(fill="x", pady=15)
        
        ctk.CTkButton(
            button_frame, 
            text="Cancel", 
            width=120,
            height=32,
            fg_color="#6c757d",
            hover_color="#5a6268",
            command=dialog.destroy
        ).pack(side="right")
        
        # Wait for the dialog to close
        self.root.wait_window(dialog)
        
        # Apply selected password
        if selected_password["password"]:
            self.decrypt_password_var.set(selected_password["password"])
            
            # If the path matches, also set the folder path
            path_with_extension = selected_password["path"] + self.encryptor.encrypted_extension
            if os.path.exists(path_with_extension):
                self.decrypt_folder_var.set(path_with_extension)
                self.animate_status_text(f"Loaded password for {os.path.basename(selected_password['path'])}")
    
    def set_master_password(self):
        """Set a new master password"""
        new_pw = self.new_master_pw_var.get()
        confirm_pw = self.confirm_master_pw_var.get()
        
        if not new_pw:
            CTkMessagebox(title="Error", message="Please enter a password", icon="cancel")
            return
        
        if new_pw != confirm_pw:
            CTkMessagebox(title="Error", message="Passwords do not match", icon="cancel")
            return
        
        # Check password strength
        score, strength, feedback = self.password_meter.check_strength(new_pw)
        if score < 60:
            confirm = CTkMessagebox(
                title="Warning", 
                message=f"Your master password is {strength} ({score}/100). "
                        f"It's recommended to use a stronger password for the master key.\n\n"
                        f"{'; '.join(feedback)}.\n\nAre you sure you want to continue?",
                icon="warning",
                option_1="Yes",
                option_2="No"
            )
            if confirm.get() != "Yes":
                return
        
        try:
            self.password_manager.set_master_password(new_pw)
            
            CTkMessagebox(title="Success", message="Master password set successfully", icon="check")
            
            # Reset the fields
            self.new_master_pw_var.set("")
            self.confirm_master_pw_var.set("")
            
            # Enable save password checkbox
            if hasattr(self, 'save_password_cb'):
                self.save_password_cb.configure(state="normal")
            
            # Reload the settings frame to reflect changes
            self.frames["settings"].destroy()
            self.frames["settings"] = ctk.CTkFrame(self.content, corner_radius=0)
            self.setup_settings_frame(self.frames["settings"])
            
            if self.frames["settings"].winfo_viewable():
                self.show_frame("settings")
                
        except Exception as e:
            CTkMessagebox(title="Error", message=f"Failed to set master password: {e}", icon="cancel")
    
    def change_master_password(self):
        """Change the master password"""
        current_pw = self.current_master_pw_var.get()
        new_pw = self.new_master_pw_var.get()
        confirm_pw = self.confirm_master_pw_var.get()
        
        if not current_pw or not new_pw:
            CTkMessagebox(title="Error", message="Please enter all passwords", icon="cancel")
            return
        
        if new_pw != confirm_pw:
            CTkMessagebox(title="Error", message="New passwords do not match", icon="cancel")
            return
        
        # Verify current password
        if not self.password_manager.verify_master_password(current_pw):
            CTkMessagebox(title="Error", message="Current password is incorrect", icon="cancel")
            return
        
        # Check password strength
        score, strength, feedback = self.password_meter.check_strength(new_pw)
        if score < 60 and new_pw != current_pw:
            confirm = CTkMessagebox(
                title="Warning", 
                message=f"Your new master password is {strength} ({score}/100). "
                        f"It's recommended to use a stronger password for the master key.\n\n"
                        f"{'; '.join(feedback)}.\n\nAre you sure you want to continue?",
                icon="warning",
                option_1="Yes",
                option_2="No"
            )
            if confirm.get() != "Yes":
                return
        
        try:
            # Set the new master password (this will overwrite the old one)
            self.password_manager.set_master_password(new_pw)
            CTkMessagebox(title="Success", message="Master password changed successfully", icon="check")
            
            # Reset the fields
            self.current_master_pw_var.set("")
            self.new_master_pw_var.set("")
            self.confirm_master_pw_var.set("")
            
        except Exception as e:
            CTkMessagebox(title="Error", message=f"Failed to change master password: {e}", icon="cancel")
    
    def view_saved_passwords(self):
        """Show a dialog with saved passwords"""
        master_password = self.view_master_pw_var.get()
        
        if not master_password:
            CTkMessagebox(title="Error", message="Please enter your master password", icon="cancel")
            return
        
        saved_passwords = self.password_manager.get_saved_passwords(master_password)
        if saved_passwords is None:
            CTkMessagebox(title="Error", message="Incorrect master password", icon="cancel")
            return
        
        if not saved_passwords:
            CTkMessagebox(title="Info", message="No saved passwords found", icon="info")
            return
        
        # Create a dialog to show passwords
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Saved Passwords")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Dialog content
        ctk.CTkLabel(
            dialog, 
            text="Saved Passwords", 
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", padx=20, pady=(20, 15))
        
        # Create a scrollable frame for passwords
        passwords_frame = ctk.CTkScrollableFrame(dialog, width=660, height=350)
        passwords_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Keep track of the password frames to enable deletion
        pw_frames = {}
        
        # Add password entries
        for i, pw in enumerate(saved_passwords):
            # Create a frame for this entry
            entry_frame = ctk.CTkFrame(passwords_frame)
            entry_frame.pack(fill="x", pady=5)
            pw_frames[pw['id']] = entry_frame
            
            # Layout in a grid
            entry_frame.grid_columnconfigure(0, weight=1)
            entry_frame.grid_columnconfigure(1, weight=1)
            
            # Name and path
            ctk.CTkLabel(
                entry_frame,
                text=pw['name'],
                font=ctk.CTkFont(weight="bold")
            ).grid(row=0, column=0, sticky="w", padx=10, pady=(5, 0))
            
            # Date
            ctk.CTkLabel(
                entry_frame,
                text=f"Created: {pw['created_at']}",
                font=ctk.CTkFont(size=12),
                text_color=("gray40", "gray70")
            ).grid(row=0, column=1, sticky="e", padx=10, pady=(5, 0))
            
            # Path
            ctk.CTkLabel(
                entry_frame,
                text=f"Path: {pw['path']}",
                font=ctk.CTkFont(size=12),
                text_color=("gray40", "gray70")
            ).grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 5))
            
            # Password
            password_frame = ctk.CTkFrame(entry_frame, fg_color="transparent")
            password_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 5))
            
            ctk.CTkLabel(
                password_frame,
                text="Password:",
                font=ctk.CTkFont(size=12, weight="bold")
            ).pack(side="left")
            
            ctk.CTkLabel(
                password_frame,
                text=pw['password'],
                font=ctk.CTkFont(size=12)
            ).pack(side="left", padx=5)
            
            # Delete button
            def make_delete_func(pw_id, frame):
                return lambda: self.delete_saved_password(pw_id, frame)
            
            ctk.CTkButton(
                entry_frame,
                text="Delete",
                width=80,
                height=24,
                fg_color="#dc3545",
                hover_color="#c82333",
                command=make_delete_func(pw['id'], entry_frame)
            ).grid(row=3, column=1, sticky="e", padx=10, pady=(0, 5))
        
        # Close button at the bottom
        ctk.CTkButton(
            dialog, 
            text="Close", 
            width=120,
            height=32,
            command=dialog.destroy
        ).pack(side="right", padx=20, pady=15)
    
    def delete_saved_password(self, password_id, frame):
        """Delete a saved password and remove it from the UI"""
        confirm = CTkMessagebox(
            title="Confirm", 
            message="Are you sure you want to delete this saved password?",
            icon="question",
            option_1="Yes",
            option_2="No"
        )
        if confirm.get() == "Yes":
            try:
                self.password_manager.delete_password(password_id)
                frame.destroy()  # Remove from UI
            except Exception as e:
                CTkMessagebox(title="Error", message=f"Failed to delete password: {e}", icon="cancel")
    
    def refresh_recent(self):
        """Refresh the recent files list"""
        # Clear the existing items
        for widget in self.recent_list_frame.winfo_children():
            if widget != self.recent_list_frame.winfo_children()[0]:  # Skip the header
                widget.destroy()
        
        # Add recent files
        recent_files = self.recent_files.get_recent_files()
        
        self.recent_items = []  # Store references to the frames
        
        for i, file in enumerate(recent_files):
            # Create a frame for this entry
            entry_frame = ctk.CTkFrame(self.recent_list_frame)
            entry_frame.pack(fill="x", pady=2)
            entry_frame.grid_columnconfigure(0, weight=1)
            entry_frame.grid_columnconfigure(1, weight=3)
            entry_frame.grid_columnconfigure(2, weight=2)
            
            # Store the path for later use (selecting)
            entry_frame.file_path = file['path']
            self.recent_items.append(entry_frame)
            
            # Background color alternating
            bg_color = ("gray90", "gray25") if i % 2 == 0 else ("gray95", "gray20")
            entry_frame.configure(fg_color=bg_color)
            
            # Operation icon and text
            op_icon = "🔒" if file['operation'] == "Encrypt" else "🔓" if file['operation'] == "Decrypt" else "🖼️"
            op_text = f"{op_icon} {file['operation']}"
            ctk.CTkLabel(entry_frame, text=op_text).grid(row=0, column=0, sticky="w", padx=10, pady=8)
            
            # Path (truncated if too long)
            path_text = file['path']
            if len(path_text) > 40:
                path_text = "..." + path_text[-40:]
            ctk.CTkLabel(entry_frame, text=path_text).grid(row=0, column=1, sticky="w", padx=10, pady=8)
            
            # Date
            ctk.CTkLabel(entry_frame, text=file['timestamp']).grid(row=0, column=2, sticky="w", padx=10, pady=8)
            
            # Make the entire frame clickable
            entry_frame.bind("<Button-1>", lambda e, f=entry_frame: self.select_recent_item(f))
            for child in entry_frame.winfo_children():
                child.bind("<Button-1>", lambda e, f=entry_frame: self.select_recent_item(f))
    
    def select_recent_item(self, frame):
        """Select a recent item and highlight it"""
        # Reset all frames
        for item in self.recent_items:
            item.configure(border_width=0)
        
        # Highlight the selected frame
        frame.configure(border_width=2, border_color=("#007bff", "#3a8eff"))
        
        # Store the selected path
        self.selected_recent_path = frame.file_path
    
    def open_selected_recent(self):
        """Open the selected recent file in file explorer"""
        if hasattr(self, 'selected_recent_path') and self.selected_recent_path:
            path = self.selected_recent_path
            
            if os.path.exists(path):
                # Open file explorer to the path
                if os.name == 'nt':  # Windows
                    os.startfile(os.path.dirname(path))
                elif os.name == 'posix':  # macOS and Linux
                    if os.path.isdir(path):
                        os.system(f"open '{path}'")
                    else:
                        os.system(f"open '{os.path.dirname(path)}'")
            else:
                CTkMessagebox(title="Error", message="The selected path no longer exists", icon="cancel")
        else:
            CTkMessagebox(title="Info", message="Please select an item from the list first", icon="info")
    
    def clear_recent(self):
        """Clear the recent files history"""
        confirm = CTkMessagebox(
            title="Confirm", 
            message="Are you sure you want to clear the recent files history?",
            icon="question",
            option_1="Yes",
            option_2="No"
        )
        if confirm.get() == "Yes":
            self.recent_files.clear_recent_files()
            self.refresh_recent()
            self.animate_status_text("Recent files history cleared")
    
    def refresh_logs(self):
        """Refresh the logs list"""
        # Clear the existing items
        for widget in self.logs_list_frame.winfo_children():
            if widget != self.logs_list_frame.winfo_children()[0]:  # Skip the header
                widget.destroy()
        
        # Add logs
        logs = self.encryptor.activity_logger.get_recent_logs()
        
        self.log_items = []  # Store references to the frames
        
        for i, log in enumerate(logs):
            # Create a frame for this entry
            entry_frame = ctk.CTkFrame(self.logs_list_frame)
            entry_frame.pack(fill="x", pady=2)
            entry_frame.grid_columnconfigure(0, weight=2)
            entry_frame.grid_columnconfigure(1, weight=1)
            entry_frame.grid_columnconfigure(2, weight=1)
            entry_frame.grid_columnconfigure(3, weight=3)
            
            # Store the log data
            entry_frame.log_data = log
            self.log_items.append(entry_frame)
            
            # Background color alternating
            bg_color = ("gray90", "gray25") if i % 2 == 0 else ("gray95", "gray20")
            entry_frame.configure(fg_color=bg_color)
            
            # Timestamp
            ctk.CTkLabel(entry_frame, text=log['timestamp'][:19]).grid(row=0, column=0, sticky="w", padx=10, pady=8)
            
            # Operation
            ctk.CTkLabel(entry_frame, text=log['operation']).grid(row=0, column=1, sticky="w", padx=10, pady=8)
            
            # Status with color
            status_color = "#28a745" if log['status'] == "SUCCESS" else ("#dc3545" if log['status'] == "FAILED" else "#ffc107")
            status_label = ctk.CTkLabel(entry_frame, text=log['status'])
            status_label.grid(row=0, column=2, sticky="w", padx=10, pady=8)
            status_label.configure(text_color=status_color)
            
            # Path (truncated)
            path_text = log['path']
            if len(path_text) > 30:
                path_text = "..." + path_text[-30:]
            ctk.CTkLabel(entry_frame, text=path_text).grid(row=0, column=3, sticky="w", padx=10, pady=8)
            
            # Make the entire frame clickable
            entry_frame.bind("<Button-1>", lambda e, f=entry_frame: self.select_log_item(f))
            for child in entry_frame.winfo_children():
                child.bind("<Button-1>", lambda e, f=entry_frame: self.select_log_item(f))
    
    def select_log_item(self, frame):
        """Select a log item and highlight it"""
        # Reset all frames
        for item in self.log_items:
            item.configure(border_width=0)
        
        # Highlight the selected frame
        frame.configure(border_width=2, border_color=("#007bff", "#3a8eff"))
        
        # Store the selected log
        self.selected_log = frame.log_data
    
    def view_log_details(self):
        """View details of the selected log"""
        if not hasattr(self, 'selected_log'):
            CTkMessagebox(title="Info", message="Please select a log entry first", icon="info")
            return
            
        log = self.selected_log
        
        # Create a dialog for log details
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Log Details")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Dialog content - main container with padding
        container = ctk.CTkFrame(dialog, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            container, 
            text="Log Details", 
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(0, 15))
        
        # Details in a grid
        details_frame = ctk.CTkFrame(container)
        details_frame.pack(fill="x", pady=10)
        
        # Timestamp
        ctk.CTkLabel(details_frame, text="Date & Time:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=15, pady=5)
        ctk.CTkLabel(details_frame, text=log['timestamp']).grid(row=0, column=1, sticky="w", padx=15, pady=5)
        
        # Operation
        ctk.CTkLabel(details_frame, text="Operation:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, sticky="w", padx=15, pady=5)
        ctk.CTkLabel(details_frame, text=log['operation']).grid(row=1, column=1, sticky="w", padx=15, pady=5)
        
        # Status
        ctk.CTkLabel(details_frame, text="Status:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=15, pady=5)
        status_color = "#28a745" if log['status'] == "SUCCESS" else ("#dc3545" if log['status'] == "FAILED" else "#ffc107")
        status_label = ctk.CTkLabel(details_frame, text=log['status'])
        status_label.grid(row=2, column=1, sticky="w", padx=15, pady=5)
        status_label.configure(text_color=status_color)
        
        # Path
        ctk.CTkLabel(details_frame, text="Path:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, sticky="w", padx=15, pady=5)
        ctk.CTkLabel(details_frame, text=log['path'], wraplength=400).grid(row=3, column=1, sticky="w", padx=15, pady=5)
        
        # Details text
        ctk.CTkLabel(container, text="Additional Details:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=5)
        
        details_text = ctk.CTkTextbox(container, height=150)
        details_text.pack(fill="x", padx=15, pady=5)
        details_text.insert("1.0", log['details'] if log['details'] else "No additional details")
        details_text.configure(state="disabled")  # Make read-only
        
        # Close button
        ctk.CTkButton(
            container,
            text="Close",
            width=120,
            height=32,
            command=dialog.destroy
        ).pack(side="right", pady=15)
    
    def on_closing(self):
        """Handle application closing"""
        # Any cleanup or saving of settings could go here
        self.root.destroy()

# Run the application
if __name__ == "__main__":
    # Make sure to install required packages:
    # pip install customtkinter CTkMessagebox pillow numpy
    
    root = ctk.CTk()
    root.title("Secure Vault Pro")
    root.iconbitmap("lock.ico") if os.path.exists("lock.ico") else None
    app = ModernEncryptorGUI(root)
    root.mainloop()