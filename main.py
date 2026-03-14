#My utility password manager
import random
import string
import json
import os
import hashlib
import base64
import getpass
import sys
from datetime import datetime
from pathlib import Path

#configuration
APP_NAME = "KeyManager"
VERSION = "2.0"
CONFIG_DIR = Path.home() / ".securepass"
PASSWORDS_FILE = CONFIG_DIR / "passwords.enc"
BACKUP_DIR = CONFIG_DIR / "backups"
LOG_FILE = CONFIG_DIR / "access.log"
CONFIG_FILE = CONFIG_DIR / "config.json"
CAESAR_SHIFT = 5  # Default Caesar cipher shift

# encryption classes

class ptCrypt:
    def __init__(self):
        self.s_box = list(range(256))
        self.inv_s_box = list(range(256))
        self._init_sboxes()
    
    def _init_sboxes(self):
        key = bytearray("ptCrypt", "utf-8")
        j = 0
        for i in range(256):
            j = (j + self.s_box[i] + key[i % len(key)]) % 256
            self.s_box[i], self.s_box[j] = self.s_box[j], self.s_box[i]
        
        for i in range(256):
            self.inv_s_box[self.s_box[i]] = i
    
    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        result = bytearray()
        for byte in data:
            result.append(self.s_box[byte])
        
        key = bytearray("ptCrypt", "utf-8")
        for i in range(len(result)):
            result[i] ^= key[i % len(key)]
        
        return result
    
    def decrypt(self, data):
        if isinstance(data, (str, bytes)):
            if isinstance(data, str):
                data = bytes.fromhex(data) if len(data) % 2 == 0 else data.encode()
            data = bytearray(data)
        
        result = bytearray(data)
        key = bytearray("ptCrypt", "utf-8")
        for i in range(len(result)):
            result[i] ^= key[i % len(key)]
        
        decrypted = bytearray()
        for byte in result:
            decrypted.append(self.inv_s_box[byte])
        
        return decrypted.decode('utf-8', errors='ignore')

class CaesarCipher:
    """Caesar cipher with shift"""
    def __init__(self, shift=CAESAR_SHIFT):
        self.shift = shift
    
    def encrypt(self, text):
        result = ""
        for char in text:
            if char.isupper():
                result += chr((ord(char) + self.shift - 65) % 26 + 65)
            elif char.islower():
                result += chr((ord(char) + self.shift - 97) % 26 + 97)
            elif char.isdigit():
                result += chr((ord(char) + self.shift - 48) % 10 + 48)
            else:
                result += chr((ord(char) + self.shift) % 256)
        return result
    
    def decrypt(self, text):
        result = ""
        for char in text:
            if char.isupper():
                result += chr((ord(char) - self.shift - 65) % 26 + 65)
            elif char.islower():
                result += chr((ord(char) - self.shift - 97) % 26 + 97)
            elif char.isdigit():
                result += chr((ord(char) - self.shift - 48) % 10 + 48)
            else:
                result += chr((ord(char) - self.shift) % 256)
        return result

class DoubleEncryption:
    """Double encryption: Caesar -> ptCrypt"""
    def __init__(self, shift=CAESAR_SHIFT):
        self.ptcrypt = ptCrypt()
        self.caesar = CaesarCipher(shift)
        self.shift = shift
    
    def encrypt(self, data):
        caesar_encrypted = self.caesar.encrypt(data)
        ptcrypt_encrypted = self.ptcrypt.encrypt(caesar_encrypted)
        return ptcrypt_encrypted
    
    def decrypt(self, encrypted_data):
        ptcrypt_decrypted = self.ptcrypt.decrypt(encrypted_data)
        final_decrypted = self.caesar.decrypt(ptcrypt_decrypted)
        return final_decrypted
    
    def encrypt_to_hex(self, data):
        return self.encrypt(data).hex()
    
    def decrypt_from_hex(self, hex_data):
        return self.decrypt(hex_data)

class PasswordGenerator:
    """Password generation utility"""
    
    @staticmethod
    def generate(length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True):
        chars = ""
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Ensure at least one of each type if selected
        if use_upper and not any(c.isupper() for c in password):
            password = password[:-1] + random.choice(string.ascii_uppercase)
        if use_lower and not any(c.islower() for c in password):
            password = password[:-1] + random.choice(string.ascii_lowercase)
        if use_digits and not any(c.isdigit() for c in password):
            password = password[:-1] + random.choice(string.digits)
        if use_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            password = password[:-1] + random.choice("!@#$%")
        
        # Shuffle
        password_list = list(password)
        random.shuffle(password_list)
        return ''.join(password_list)
    
    @staticmethod
    def check_strength(password):
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Too short (min 8 chars)")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add digits")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        if score >= 5:
            strength = "VERY STRONG"
        elif score >= 4:
            strength = "STRONG"
        elif score >= 3:
            strength = "MEDIUM"
        elif score >= 2:
            strength = "WEAK"
        else:
            strength = "VERY WEAK"
        
        return strength, feedback

class Logger:
    """Logging utility"""
    
    @staticmethod
    def log(action, user="system", status="success"):
        try:
            CONFIG_DIR.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a") as f:
                f.write(f"[{timestamp}] {user}: {action} - {status}\n")
        except:
            pass
    
    @staticmethod
    def view_logs(lines=20):
        if not LOG_FILE.exists():
            print("No logs found")
            return
        
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()
            for log in logs[-lines:]:
                print(log.strip())

#main

class SecurePassManager:
    """Main password manager application"""
    
    def __init__(self):
        self.crypto = DoubleEncryption(CAESAR_SHIFT)
        self.passwords = {}
        self.master_password = None
        self.authenticated = False
        self.setup_directories()
        self.load_config()
    
    def setup_directories(self):
        """Create necessary directories"""
        CONFIG_DIR.mkdir(exist_ok=True)
        BACKUP_DIR.mkdir(exist_ok=True)
    
    def load_config(self):
        """Load or create config"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.config = json.load(f)
            except:
                self.config = self.default_config()
        else:
            self.config = self.default_config()
            self.save_config()
    
    def default_config(self):
        return {
            "first_run": datetime.now().isoformat(),
            "password_length": 16,
            "auto_backup": True,
            "backup_count": 5,
            "theme": "default",
            "caesar_shift": CAESAR_SHIFT
        }
    
    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def authenticate(self):
        """Authenticate user"""
        print(f"{APP_NAME} v{VERSION}")
        
        if not PASSWORDS_FILE.exists():
            print("First time setup - create master password")
            while True:
                mp1 = getpass.getpass("Create master password: ")
                mp2 = getpass.getpass("Confirm master password: ")
                if mp1 == mp2:
                    self.master_password = mp1
                    self.authenticated = True
                    self.save_data({})
                    Logger.log("First time setup completed")
                    return True
                else:
                    print("Passwords don't match!")
        else:
            attempts = 3
            while attempts > 0:
                mp = getpass.getpass("Enter master password: ")
                try:
                    self.load_data(mp)
                    self.master_password = mp
                    self.authenticated = True
                    Logger.log("Authentication successful")
                    return True
                except:
                    attempts -= 1
                    print(f"Wrong password! {attempts} attempts left")
            
            print("Too many failed attempts!")
            sys.exit(1)
    
    def save_data(self, data):
        """Save encrypted data"""
        json_data = json.dumps(data, indent=2)
        
        # Double encrypt with master password
        master_encrypted = self.crypto.encrypt_to_hex(self.master_password + "::" + json_data)
        
        with open(PASSWORDS_FILE, 'w') as f:
            f.write(master_encrypted)
        
        # Create backup if enabled
        if self.config.get("auto_backup", True):
            self.create_backup(data)
    
    def load_data(self, master_password):
        """Load and decrypt data"""
        if not PASSWORDS_FILE.exists():
            return {}
        
        with open(PASSWORDS_FILE, 'r') as f:
            encrypted_data = f.read().strip()
        
        try:
            decrypted = self.crypto.decrypt_from_hex(encrypted_data)
            if "::" not in decrypted:
                raise ValueError("Invalid data format")
            
            stored_master, json_data = decrypted.split("::", 1)
            
            if stored_master != master_password:
                raise ValueError("Wrong master password")
            
            self.passwords = json.loads(json_data)
            return self.passwords
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def create_backup(self, data=None):
        """Create backup of passwords"""
        if data is None:
            data = self.passwords
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = BACKUP_DIR / f"backup_{timestamp}.enc"
        
        json_data = json.dumps(data, indent=2)
        encrypted = self.crypto.encrypt_to_hex("BACKUP::" + json_data)
        
        with open(backup_file, 'w') as f:
            f.write(encrypted)
        
        # Keep only last N backups
        backups = sorted(BACKUP_DIR.glob("backup_*.enc"))
        max_backups = self.config.get("backup_count", 5)
        
        while len(backups) > max_backups:
            backups[0].unlink()
            backups.pop(0)
        
        Logger.log(f"Backup created: {backup_file.name}")
        return backup_file
    
    def list_backups(self):
        """List available backups"""
        backups = sorted(BACKUP_DIR.glob("backup_*.enc"))
        if not backups:
            print("No backups found")
            return []
        
        print("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            size = backup.stat().st_size
            mod_time = datetime.fromtimestamp(backup.stat().st_mtime)
            print(f"{i}. {backup.name} - {mod_time} - {size} bytes")
        
        return backups
    
    def restore_backup(self, backup_file):
        """Restore from backup"""
        try:
            with open(backup_file, 'r') as f:
                encrypted = f.read().strip()
            
            decrypted = self.crypto.decrypt_from_hex(encrypted)
            if "::" not in decrypted:
                raise ValueError("Invalid backup format")
            
            prefix, json_data = decrypted.split("::", 1)
            if prefix != "BACKUP":
                raise ValueError("Not a valid backup file")
            
            self.passwords = json.loads(json_data)
            self.save_data(self.passwords)
            Logger.log(f"Restored from backup: {backup_file.name}")
            return True
        except Exception as e:
            print(f"Restore failed: {e}")
            return False
    
    def add_password(self):
        """Add a new password"""
        print("\n" + "-"*40)
        print("ADD NEW PASSWORD")
        print("-"*40)
        
        service = input("Service/App name: ").strip()
        if not service:
            print("Service name required!")
            return
        
        username = input("Username/Email: ").strip()
        if not username:
            print("Username required!")
            return
        
        print("\nPassword options:")
        print("1. Generate strong password")
        print("2. Enter manually")
        print("3. Generate with custom settings")
        
        choice = input("Choose (1-3): ").strip()
        
        if choice == "1":
            password = PasswordGenerator.generate()
            print(f"Generated password: {password}")
        elif choice == "2":
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Password required!")
                return
        elif choice == "3":
            length = int(input("Length (default 16): ") or "16")
            use_upper = input("Use uppercase? (y/n): ").lower() == 'y'
            use_lower = input("Use lowercase? (y/n): ").lower() == 'y'
            use_digits = input("Use digits? (y/n): ").lower() == 'y'
            use_special = input("Use special chars? (y/n): ").lower() == 'y'
            
            password = PasswordGenerator.generate(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_special=use_special
            )
            print(f"Generated password: {password}")
        else:
            print("Invalid choice!")
            return
        
        # Check password strength
        strength, feedback = PasswordGenerator.check_strength(password)
        print(f"\nPassword strength: {strength}")
        if feedback:
            print("Suggestions:", ", ".join(feedback))
        
        notes = input("Notes (optional): ").strip()
        
        # Add to database
        self.passwords[service] = {
            "username": username,
            "password": password,
            "notes": notes,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat()
        }
        
        self.save_data(self.passwords)
        Logger.log(f"Added password for {service}")
        print(f"\n✓ Password for {service} saved successfully!")
    
    def view_passwords(self):
        """View all passwords"""
        if not self.passwords:
            print("\nNo passwords stored yet")
            return
        
        print(f"{'#':<3} {'SERVICE':<20} {'USERNAME':<20} {'PASSWORD':<15} {'STRENGTH':<10}")
        
        for i, (service, data) in enumerate(sorted(self.passwords.items()), 1):
            username = data.get('username', 'N/A')
            password = data.get('password', 'N/A')
            
            # Show only first few chars of password
            if len(password) > 10:
                display_pass = password[:5] + "..." + password[-2:]
            else:
                display_pass = password
            
            strength, _ = PasswordGenerator.check_strength(password)
            strength_short = strength[:4] + "." if len(strength) > 4 else strength
            
            print(f"{i:<3} {service[:18] + '..' if len(service) > 18 else service:<20} "
                  f"{username[:18] + '..' if len(username) > 18 else username:<20} "
                  f"{display_pass:<15} {strength_short:<10}")
        
        
        # Show details option
        choice = input("\nShow full details for a service? (number/n): ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(self.passwords):
                service = sorted(self.passwords.keys())[idx]
                data = self.passwords[service]
                
                print(f"\n--- {service} ---")
                print(f"Username: {data['username']}")
                print(f"Password: {data['password']}")
                if data.get('notes'):
                    print(f"Notes: {data['notes']}")
                print(f"Created: {data.get('created', 'Unknown')}")
                print(f"Modified: {data.get('modified', 'Unknown')}")
                
                # Encryption demo
                show_enc = input("\nShow encryption layers? (y/n): ").lower()
                if show_enc == 'y':
                    versions = self.crypto.encrypt_to_hex(data['password'])
                    print(f"Original: {data['password']}")
                    print(f"Caesar (shift={CAESAR_SHIFT}): {self.crypto.caesar.encrypt(data['password'])}")
                    print(f"Double encrypted (hex): {versions[:50]}...")
                    print(f"Binary: {' '.join(format(ord(c), '08b') for c in data['password'][:5])}...")
    
    def edit_password(self):
        """Edit existing password"""
        if not self.passwords:
            print("\nNo passwords to edit")
            return
        
        self.view_passwords()
        
        service = input("\nEnter service name to edit: ").strip()
        if service not in self.passwords:
            print("Service not found!")
            return
        
        data = self.passwords[service]
        print(f"\nEditing {service}")
        print(f"Current username: {data['username']}")
        
        new_username = input("New username (Enter to keep): ").strip()
        if new_username:
            data['username'] = new_username
        
        print("New password options:")
        print("1. Keep current")
        print("2. Generate new")
        print("3. Enter manually")
        
        choice = input("Choose (1-3): ").strip()
        
        if choice == "2":
            data['password'] = PasswordGenerator.generate()
            print(f"New password: {data['password']}")
        elif choice == "3":
            new_pass = getpass.getpass("Enter new password: ")
            if new_pass:
                data['password'] = new_pass
        
        new_notes = input("New notes (Enter to keep): ").strip()
        if new_notes:
            data['notes'] = new_notes
        
        data['modified'] = datetime.now().isoformat()
        self.passwords[service] = data
        self.save_data(self.passwords)
        
        Logger.log(f"Edited password for {service}")
        print(f"\n Password for {service} updated!")
    
    def delete_password(self):
        """Delete a password"""
        if not self.passwords:
            print("\nNo passwords to delete")
            return
        
        self.view_passwords()
        
        service = input("\nEnter service name to delete: ").strip()
        if service not in self.passwords:
            print("Service not found!")
            return
        
        print(f"\nService: {service}")
        print(f"Username: {self.passwords[service]['username']}")
        
        confirm = input(f"Are you sure you want to delete {service}? (y/n): ").lower()
        if confirm == 'y':
            # Create backup before deleting
            self.create_backup()
            
            del self.passwords[service]
            self.save_data(self.passwords)
            
            Logger.log(f"Deleted password for {service}")
            print(f" Password for {service} deleted!")
        else:
            print("Deletion cancelled")
    
    def search_passwords(self):
        """Search passwords"""
        if not self.passwords:
            print("\nNo passwords to search")
            return
        
        search = input("Enter search term: ").strip().lower()
        if not search:
            return
        
        results = []
        for service, data in self.passwords.items():
            if (search in service.lower() or 
                search in data.get('username', '').lower() or
                search in data.get('notes', '').lower()):
                results.append((service, data))
        
        if not results:
            print("No matches found")
            return
        
        print(f"\nFound {len(results)} matches:")
        for service, data in results:
            print(f"Service: {service}")
            print(f"Username: {data['username']}")
            print(f"Password: {data['password']}")
            if data.get('notes'):
                print(f"Notes: {data['notes']}")
    
    def export_passwords(self):
        """Export passwords (encrypted)"""
        filename = input("Export filename (default: export.enc): ").strip()
        if not filename:
            filename = "export.enc"
        
        if not filename.endswith('.enc'):
            filename += '.enc'
        
        export_path = Path(filename)
        
        # Add export metadata
        export_data = {
            "exported": datetime.now().isoformat(),
            "version": VERSION,
            "count": len(self.passwords),
            "passwords": self.passwords
        }
        
        json_data = json.dumps(export_data, indent=2)
        encrypted = self.crypto.encrypt_to_hex("EXPORT::" + json_data)
        
        with open(export_path, 'w') as f:
            f.write(encrypted)
        
        Logger.log(f"Exported passwords to {filename}")
        print(f"✓ Exported to {filename}")
    
    def import_passwords(self):
        """Import passwords from encrypted file"""
        filename = input("Enter filename to import: ").strip()
        if not filename:
            return
        
        import_path = Path(filename)
        if not import_path.exists():
            print("File not found!")
            return
        
        try:
            with open(import_path, 'r') as f:
                encrypted = f.read().strip()
            
            decrypted = self.crypto.decrypt_from_hex(encrypted)
            if "::" not in decrypted:
                raise ValueError("Invalid import format")
            
            prefix, json_data = decrypted.split("::", 1)
            if prefix != "EXPORT":
                raise ValueError("Not a valid export file")
            
            import_data = json.loads(json_data)
            
            print(f"\nImport file contains:")
            print(f"Exported: {import_data['exported']}")
            print(f"Passwords: {import_data['count']}")
            
            confirm = input("Import these passwords? (y/n): ").lower()
            if confirm == 'y':
                # Merge with existing
                self.passwords.update(import_data['passwords'])
                self.save_data(self.passwords)
                Logger.log(f"Imported passwords from {filename}")
                print("✓ Import successful!")
            else:
                print("Import cancelled")
                
        except Exception as e:
            print(f"Import failed: {e}")
    
    def show_stats(self):
        """Show statistics"""
        if not self.passwords:
            print("\nNo passwords stored yet")
            return
        
        total = len(self.passwords)
        strengths = {"VERY STRONG": 0, "STRONG": 0, "MEDIUM": 0, "WEAK": 0, "VERY WEAK": 0}
        
        for data in self.passwords.values():
            strength, _ = PasswordGenerator.check_strength(data['password'])
            strengths[strength] += 1
        
        print("\n" + "="*50)
        print("PASSWORD STATISTICS")
        print("="*50)
        print(f"Total passwords: {total}")
        print("\nPassword strength distribution:")
        for strength, count in strengths.items():
            if count > 0:
                percentage = (count / total) * 100
                bar = "█" * int(percentage / 5)
                print(f"{strength:12}: {bar:<20} {count} ({percentage:.1f}%)")
        
        # Service categories (simple detection)
        categories = {}
        for service in self.passwords.keys():
            service_lower = service.lower()
            if any(word in service_lower for word in ['google', 'gmail', 'youtube']):
                cat = 'Google'
            elif any(word in service_lower for word in ['facebook', 'instagram', 'twitter', 'social']):
                cat = 'Social Media'
            elif any(word in service_lower for word in ['bank', 'paypal', 'finance', 'card']):
                cat = 'Finance'
            elif any(word in service_lower for word in ['work', 'company', 'job']):
                cat = 'Work'
            else:
                cat = 'Other'
            
            categories[cat] = categories.get(cat, 0) + 1
        
        print("\nCategories:")
        for cat, count in categories.items():
            print(f"  {cat}: {count}")
    
    def settings_menu(self):
        """Settings menu"""
        while True:
            print("\n" + "="*50)
            print("SETTINGS")
            print("="*50)
            print(f"1. Password length: {self.config['password_length']}")
            print(f"2. Auto backup: {self.config['auto_backup']}")
            print(f"3. Backup count: {self.config['backup_count']}")
            print(f"4. Caesar shift: {self.config['caesar_shift']}")
            print("5. View logs")
            print("6. Manage backups")
            print("7. Back to main menu")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                new_len = int(input("New password length: ") or self.config['password_length'])
                self.config['password_length'] = new_len
                self.save_config()
            elif choice == "2":
                self.config['auto_backup'] = not self.config['auto_backup']
                self.save_config()
                print(f"Auto backup: {self.config['auto_backup']}")
            elif choice == "3":
                new_count = int(input("Number of backups to keep: ") or self.config['backup_count'])
                self.config['backup_count'] = new_count
                self.save_config()
            elif choice == "4":
                new_shift = int(input("Caesar cipher shift: ") or self.config['caesar_shift'])
                self.config['caesar_shift'] = new_shift
                self.crypto = DoubleEncryption(new_shift)
                self.save_config()
            elif choice == "5":
                lines = int(input("Number of lines to show (default 20): ") or "20")
                Logger.view_logs(lines)
            elif choice == "6":
                self.backup_menu()
            elif choice == "7":
                break
    
    def backup_menu(self):
        """Backup management menu"""
        while True:
            print("\n")
            print("BACKUP MANAGEMENT")
       
            print("1. Create backup now")
            print("2. List backups")
            print("3. Restore from backup")
            print("4. Back")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                backup = self.create_backup()
                print(f"Backup created: {backup.name}")
            elif choice == "2":
                self.list_backups()
            elif choice == "3":
                backups = self.list_backups()
                if backups:
                    idx = int(input("Enter backup number to restore: ")) - 1
                    if 0 <= idx < len(backups):
                        confirm = input("Restore will overwrite current data. Continue? (y/n): ")
                        if confirm.lower() == 'y':
                            if self.restore_backup(backups[idx]):
                                print("Restore successful!")
                            else:
                                print("Restore failed!")
            elif choice == "4":
                break
    
    def run(self):
        """Main application loop"""
        if not self.authenticate():
            return
        
        while True:
            print("MAIN MENU")

            print("1.  Add password")
            print("2.  View passwords")
            print("3.  Edit password")
            print("4.  Delete password")
            print("5.  Search passwords")
            print("6.  Generate password only")
            print("7.  Statistics")
            print("8.  Export/Import")
            print("9.  Settings")
            print("10. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                self.add_password()
            elif choice == "2":
                self.view_passwords()
            elif choice == "3":
                self.edit_password()
            elif choice == "4":
                self.delete_password()
            elif choice == "5":
                self.search_passwords()
            elif choice == "6":
                length = int(input("Password length (default 16): ") or "16")
                print(f"Generated: {PasswordGenerator.generate(length)}")
            elif choice == "7":
                self.show_stats()
            elif choice == "8":
                print("\n1. Export passwords")
                print("2. Import passwords")
                exp_choice = input("Choose: ")
                if exp_choice == "1":
                    self.export_passwords()
                elif exp_choice == "2":
                    self.import_passwords()
            elif choice == "9":
                self.settings_menu()
            elif choice == "10":
                print("\nGoodbye!")
                Logger.log("Application closed")
                break
            else:
                print("Invalid option!")


def main():
    """Main function"""
    try:
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # ASCII Art
        print("""
    
   SECUREPASS MANAGER v2.0              
       Double Encryption         Password Manager    
       Based on ptCrypt protocol             
        """)
        
        app = SecurePassManager()
        app.run()
        
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        Logger.log("Application interrupted")
    except Exception as e:
        print(f"\nError: {e}")
        Logger.log(f"Error: {e}", status="error")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 
