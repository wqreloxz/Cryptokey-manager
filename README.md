# KeyManager

A minimalist, high-security terminal password manager written in Python. KeyManager utilizes a custom double-encryption layer (Caesar + ptCrypt) to ensure your credentials remain isolated and secure on your local machine.

---

## Core Features

* **Double Encryption Architecture**: Implements a multi-layered encryption approach combining a configurable Caesar cipher with the custom ptCrypt S-box protocol.
* **Intelligent Generation**: Built-in password generator with customizable constraints and real-time strength evaluation.
* **Automated Backups**: Maintains a rolling history of encrypted backups to prevent data loss during accidental deletions.
* **Security Logging**: Tracks all access attempts and administrative actions in a dedicated log file.
* **Import/Export**: Facilitates secure data portability via encrypted `.enc` files.
* **Data Analytics**: Provides a visual distribution of password strength and service categories.

---

## Technical Architecture

The utility is structured into several modular classes to maintain a clean separation of concerns:

### Encryption Layers
* **ptCrypt**: Handles S-box transformations and XOR operations.
* **CaesarCipher**: Provides a primary shift transformation for alphabetic, numeric, and special characters.
* **DoubleEncryption**: Orchestrates the sequence: `Caesar -> ptCrypt -> Hex`.

### Management Modules
* **PasswordGenerator**: Logic for entropy-based password creation and strength scoring.
* **Logger**: Handles persistent audit trails.
* **SecurePassManager**: The central engine managing authentication, file I/O, and the user interface.

---

## Configuration

The application stores data in the user's home directory under a hidden folder:
`~/.securepass/`

* `passwords.enc`: The primary encrypted database.
* `config.json`: User preferences including password length and backup counts.
* `access.log`: System audit trail.
* `backups/`: Rolling encrypted snapshots.

---

## Requirements

* Python 3.6+
* Standard library modules only (no external dependencies required).

---

## Usage

1. **Initialization**: Run the script to set up your Master Password.
   ```bash
   python main.py
2.**Authentication**: Access the main menu by entering your Master Password.

3.**Management**: Use the numeric menu to add, search, or export your credentials.
## Security Disclaimer
This utility uses a custom encryption implementation (ptCrypt) for educational and personal organization purposes. For enterprise-grade security, always consider audited implementations like AES-256.
   
