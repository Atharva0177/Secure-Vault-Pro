# Secure Vault Pro

A modern, feature-rich file encryption and data protection application with advanced security features including folder encryption, steganography, and password management.


## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Encrypting Files](#encrypting-files)
  - [Decrypting Files](#decrypting-files)
  - [Steganography](#steganography)
  - [Password Management](#password-management)
  - [Activity Logging](#activity-logging)
- [Security Features](#security-features)
- [Technical Details](#technical-details)

- [Contributing](#contributing)
- [License](#license)

## Features

### Core Functionality
- **Folder Encryption**: Secure your sensitive folders with strong encryption
- **Multiple Algorithms**: Choose between AES-128, AES-256, or ChaCha20 encryption
- **File Integrity**: Verify file integrity after decryption
- **Secure Deletion**: Securely shred original files after encryption

### Steganography
- **Hide Data in Images**: Conceal sensitive information inside innocent-looking images
- **Password Protection**: Optional password protection for hidden data
- **Format Support**: Works with PNG and BMP image formats
- **Detection Tools**: Analyze images to detect hidden data

### Password Management
- **Master Password System**: Protect your encryption passwords with a master password
- **Password Strength Meter**: Real-time feedback on password strength
- **Save & Retrieve**: Save encryption passwords for future access

### User Experience
- **Modern Interface**: Clean, intuitive GUI with dark/light mode support
- **Recent Files**: Quick access to recently encrypted/decrypted folders
- **Activity Logs**: Detailed logs of all security operations
- **Progress Tracking**: Real-time progress for long operations

## Installation

### Prerequisites
- Python 3.7 or higher
- Required packages (see requirements section)

## Requirements

- Python 3.7+
- CustomTkinter
- CTkMessagebox
- cryptography
- Pillow (PIL)
- numpy

### Steps
1. Clone the repository or download the source code:
```
git clone https://github.com/yourusername/secure-vault-pro.git
cd secure-vault-pro
```
2. Install the required dependencies:
```
pip install -r requirements.txt
```
3. Run the application:
```
python main.py
```



## Usage

### Encrypting Files

1. Navigate to the "Encrypt" tab
2. Select a folder to encrypt using the "Browse" button
3. Enter a strong encryption password (and confirm it)
4. Choose your preferred encryption algorithm (AES-256 recommended)
5. Select additional options if needed:
   - Securely delete original files
   - Save encryption password (requires master password)
6. Click "Encrypt Folder" to start the encryption process


### Decrypting Files

1. Navigate to the "Decrypt" tab
2. Select an encrypted folder using the "Browse" button
3. Enter the decryption password or load a saved password
4. Optionally specify an output folder
5. Click "Decrypt Folder" to start the decryption process

### Steganography

#### Hiding Data in Images
1. Navigate to the "Stego" tab and select "Hide Data"
2. Choose a carrier image (PNG or BMP format)
3. Enter text to hide or select a file
4. Optionally add password protection for the hidden data
5. Click "Hide Data" to process the image

#### Extracting Hidden Data
1. Navigate to the "Stego" tab and select "Extract Data"
2. Select an image with hidden data
3. Click "Analyze Image" to check for hidden content
4. Enter extraction password if required
5. Choose to view or save the extracted data
6. Click "Extract Data" to retrieve the hidden information

### Password Management

#### Setting a Master Password
1. Navigate to the "Settings" tab
2. Under "Password Manager", enter and confirm your master password
3. Click "Set Master Password"

#### Saving Encryption Passwords
When encrypting a folder, check "Save encryption password" to store it securely

#### Viewing Saved Passwords
1. Navigate to the "Settings" tab
2. Enter your master password
3. Click "View Saved Passwords"

### Activity Logging

1. Navigate to the "Logs" tab to view a history of security operations
2. Click on any log entry to view detailed information
3. Use the "Refresh" button to update the log list

## Security Features

- **Strong Encryption**: Industry-standard encryption algorithms
- **Key Derivation**: PBKDF2HMAC with 100,000 iterations for password-based key generation
- **Integrity Verification**: SHA-256 hashing to verify file integrity
- **Secure Deletion**: Multi-pass overwriting before deleting sensitive files
- **Password Strength Analysis**: Real-time feedback to encourage strong passwords
- **Protected Storage**: Saved passwords are encrypted with the master password

## Technical Details

### Encryption Methods
- **AES-256**: Advanced Encryption Standard with 256-bit keys (default)
- **AES-128**: Advanced Encryption Standard with 128-bit keys
- **ChaCha20**: Stream cipher designed for high performance in software implementations

### Steganography Technique
- Uses LSB (Least Significant Bit) steganography
- Data compression to maximize storage capacity
- Optional encryption layer for hidden data

### Password Storage
- Passwords stored in SQLite database
- Password hashing with SHA-256 and unique salts
- Encrypted with keys derived from master password




## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This software is for educational purposes only. Always ensure you have proper authorization before encrypting files that aren't yours. Never use this tool for illegal activities.

<!-- Generated on: 2025-08-29 05:35:32 UTC by Atharva0177 -->
