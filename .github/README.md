# 🔐 Password Encrypter

**Author:** Chirantan Swain  
**Creation Date:** 28-Oct-2025  
**License:** MIT  

A simple yet powerful **AES-GCM-based password encryption and decryption tool** built in Python.  
It allows you to securely encrypt and decrypt passwords using a master key.  
Includes a text-based banner, AES encryption (via the `cryptography` module), and a desktop entry for Kali/Linux menus.

---

## 🧠 Features

- AES-256 encryption using `cryptography` library  
- Secure master password authentication  
- CLI-based user interface with banner art  
- Stores encrypted passwords in a text file  
- Integrated with Linux application menu (`.desktop` file)  
- Simple to extend or modify for your own needs  

---

## ⚙️ Installation

### 1️⃣ Install dependencies
```bash
sudo apt update
sudo apt install python3-pip -y
pip3 install cryptography --break-system-packages
2️⃣ Copy the script to your system path
sudo cp password_encrypter /usr/local/bin/
sudo chmod +x /usr/local/bin/password_encrypter
3️⃣ Add desktop entry
sudo nano /usr/share/applications/password_encrypter.desktop
[Desktop Entry]
Type=Application
Name=Password Encrypter
Exec=/usr/local/bin/password_encrypter
Icon=/usr/share/icons/password_encrypter.png
Terminal=true
Categories=Utility;Security;
Comment=Encrypt or decrypt passwords securely using AES encryption.
Save and Update
sudo update-desktop-database
Usage:
password_encrypter
