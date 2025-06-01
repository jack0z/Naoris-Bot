#!/usr/bin/env python3
"""
🚀 Naoris Protocol Bot - Automated Points Farming

Created by: jack0z
Telegram: https://t.me/Jack0zdrops
Security: AES-128 + PBKDF2 + HMAC-SHA256

Usage: python main.py
Password: Contact @newjacko via Telegram for access
"""

import os
import sys
import base64
import hashlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
    """Generate encryption key from password using PBKDF2-HMAC-SHA256"""
    if salt is None:
        salt = b'jack0z_naoris_salt_2024'  # Consistent salt for decryption
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # High iteration count for security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def decrypt_and_execute(encrypted_file: str, password: str):
    """Securely decrypt and execute the bot code in memory"""
    if not os.path.exists(encrypted_file):
        print(f"{Fore.RED}❌ Error: Bot core file not found: {encrypted_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please ensure all files are downloaded correctly.{Style.RESET_ALL}")
        return False
    
    try:
        # Generate decryption key using PBKDF2
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        
        # Read encrypted bot data
        with open(encrypted_file, 'rb') as file:
            encrypted_data = file.read()
        
        # Decrypt the bot code
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Execute the decrypted bot code in memory (no traces on disk)
        exec(decrypted_data.decode('utf-8'), globals())
        return True
        
    except Exception as e:
        if "InvalidToken" in str(type(e)):
            print(f"{Fore.RED}❌ Invalid access password!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Contact @newjacko on Telegram for the correct password.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Bot initialization failed: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please contact support if this issue persists.{Style.RESET_ALL}")
        return False

def verify_access():
    """Secure access control with password verification"""
    # SHA256 hash of the correct password for security
    correct_hash = "b6bc2fdcd0459c16a0b19d8d4e073fbe7a03d4140fcbc91f19db5012c1e1ff23"
    
    print(f"\n{Fore.YELLOW}🔐 NAORIS PROTOCOL BOT - SECURE ACCESS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Professional Grade Automation with Military Encryption{Style.RESET_ALL}")
    print(f"{Fore.BLUE}📱 For access password, join: https://t.me/Jack0zdrops{Style.RESET_ALL}")
    
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            password = getpass.getpass(f"{Fore.WHITE}🔑 Enter access password: {Style.RESET_ALL}")
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if input_hash == correct_hash:
                print(f"{Fore.GREEN}✅ Access granted! Initializing secure bot...{Style.RESET_ALL}")
                return password
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    print(f"{Fore.RED}❌ Invalid password. {remaining} attempts remaining.{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}💬 Join https://t.me/Jack0zdrops for support{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Access denied. Maximum attempts exceeded.{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}🔒 Security lockout activated. Contact @newjacko for assistance.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}❌ Access cancelled by user.{Style.RESET_ALL}")
            return None
    
    return None

def display_banner():
    """Display the professional bot banner"""
    banner = f"""
{Fore.CYAN + Style.BRIGHT}
███╗   ██╗ █████╗  ██████╗ ██████╗ ██╗███████╗    ██████╗  ██████╗ ████████╗
████╗  ██║██╔══██╗██╔═══██╗██╔══██╗██║██╔════╝    ██╔══██╗██╔═══██╗╚══██╔══╝
██╔██╗ ██║███████║██║   ██║██████╔╝██║███████╗    ██████╔╝██║   ██║   ██║   
██║╚██╗██║██╔══██║██║   ██║██╔══██╗██║╚════██║    ██╔══██╗██║   ██║   ██║   
██║ ╚████║██║  ██║╚██████╔╝██║  ██║██║███████║    ██████╔╝╚██████╔╝   ██║   
╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝    ╚═════╝  ╚═════╝    ╚═╝   
{Style.RESET_ALL}"""
    
    print(banner)
    print(f"{Fore.GREEN}🔒 SECURE DISTRIBUTION - MILITARY-GRADE ENCRYPTION{Style.RESET_ALL}".center(80))
    print(f"{Fore.YELLOW}⚡ Professional Automation by jack0z ⚡{Style.RESET_ALL}".center(80))
    print(f"{Fore.MAGENTA}{'═' * 80}{Style.RESET_ALL}")

def check_requirements():
    """Verify all required files are present"""
    required_files = [
        "main.encrypted",
        "accounts.json", 
        "proxy.txt",
        "requirements.txt"
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"{Fore.RED}❌ Missing required files:{Style.RESET_ALL}")
        for file in missing_files:
            print(f"   • {file}")
        print(f"\n{Fore.YELLOW}📥 Please download the complete repository from GitHub{Style.RESET_ALL}")
        return False
    
    return True

def main():
    """Main bot initialization and execution"""
    try:
        display_banner()
        
        # Check if all required files are present
        if not check_requirements():
            input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")
            sys.exit(1)
        
        # Verify user access with password
        password = verify_access()
        if not password:
            print(f"{Fore.RED}🚫 Unauthorized access blocked for security.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")
            sys.exit(1)
        
        # Locate encrypted bot core
        encrypted_file = "main.encrypted"
        if not os.path.exists(encrypted_file):
            print(f"{Fore.RED}❌ Bot core file missing: {encrypted_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please re-download the repository or contact support.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"{Fore.CYAN}🔓 Decrypting bot core and starting...{Style.RESET_ALL}")
        print(f"{Fore.GREEN}🚀 Initialization complete - Bot is now running!{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
        
        # Decrypt and execute the bot (memory-only, no traces)
        if not decrypt_and_execute(encrypted_file, password):
            print(f"{Fore.RED}❌ Failed to start bot. Please contact support.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}🚫 Bot stopped by user{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚡ Thanks for using Naoris Protocol Bot by jack0z ⚡{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Critical error: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📱 Contact @newjacko on Telegram for support{Style.RESET_ALL}")
        input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 
