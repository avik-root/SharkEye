#!/usr/bin/env python3
"""
SharkEye - Initial Setup Script
Built by MintFire
"""

import os
import sys
import shutil
import hashlib
import random
import string
import subprocess
import json
import time

def print_banner():
    banner = """
\033[96m=================================================================\033[0m
\033[1m                      S h a r k E y e                            \033[0m
\033[90m                 Network Intrusion Detection                     \033[0m
\033[96m=================================================================\033[0m
\033[92m                       Built by MintFire                         \033[0m
\033[96m=================================================================\033[0m
    """
    print(banner)

def get_total_ram_gb():
    """Cross-platform check for total RAM in GB."""
    try:
        # Linux / Raspberry Pi
        if os.path.exists('/proc/meminfo'):
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemTotal' in line:
                        kb = int(line.split()[1])
                        return kb / (1024 * 1024)
        # macOS
        elif sys.platform == 'darwin':
            out = subprocess.check_output(['sysctl', 'hw.memsize']).decode().strip()
            bytes_ram = int(out.split(':')[1].strip())
            return bytes_ram / (1024**3)
    except Exception:
        pass
    return 0  # Unknown

def get_free_disk_gb():
    """Get free disk space on root in GB."""
    try:
        total, used, free = shutil.disk_usage("/")
        return free / (1024**3)
    except Exception:
        return 0

def check_system():
    print("\033[1m[1] System Resource Check\033[0m")
    ram_gb = get_total_ram_gb()
    disk_gb = get_free_disk_gb()
    
    print(f"    - Total RAM: \033[93m{ram_gb:.1f} GB\033[0m")
    print(f"    - Free Disk: \033[93m{disk_gb:.1f} GB\033[0m")
    
    if disk_gb < 3.0:
        print("\033[91m    [!] CRITICAL: Less than 3GB of free disk space. Ollama models require storage.\033[0m")
        sys.exit(1)
        
    return ram_gb, disk_gb

def check_installed_models():
    print("\n\033[1m[2] LLM Model Check\033[0m")
    try:
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        out = subprocess.check_output(["ollama", "list"]).decode()
        lines = out.strip().split('\n')[1:] # skip header
        models = [line.split()[0] for line in lines if line.strip()]
        
        if models:
            print(f"    \033[92m[✓] Found installed models: {', '.join(models)}\033[0m")
            return models[0] # Default to the first found
        else:
            print("    \033[93m[!] No models found. You can install one later via the WebUI.\033[0m")
            return ""
    except Exception as e:
        print("    \033[93m[!] Ollama not running or not installed. You can fix this later via the WebUI.\033[0m")
        return ""

def terms_and_conditions():
    print("\n\033[1m[3] Terms and Conditions\033[0m")
    terms = """
    1. SharkEye is a Network Intrusion Detection System for internal use.
    2. Do not use this tool on networks you do not own or have permission to monitor.
    3. The developers (MintFire) are not responsible for any misuse.
    4. AI analysis is performed locally; no network traffic is sent to the cloud.
    """
    print(terms)
    agree = input("    Do you accept the Terms and Conditions? (y/n): ").strip().lower()
    if agree != 'y':
        print("\033[91m    [!] Setup aborted.\033[0m")
        sys.exit(1)

def _get_secret_dir():
    # Must match app.py logic!
    app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "app.py"))
    script_hash = hashlib.sha256(app_path.encode()).hexdigest()
    dir_name = f".netaudit_meta_{script_hash[:12]}"
    if os.geteuid() == 0:
        base = "/var/cache"
    else:
        base = os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, dir_name)

def generate_product_key(model_name):
    print("\n\033[1m[4] Security & Unlock\033[0m")
    
    # Generate 16-char random alphanumeric key
    chars = string.ascii_uppercase + string.digits
    raw_key = ''.join(random.choice(chars) for _ in range(16))
    formatted_key = f"{raw_key[:4]}-{raw_key[4:8]}-{raw_key[8:12]}-{raw_key[12:]}"
    
    # Hash it
    key_hash = hashlib.sha256(formatted_key.encode()).hexdigest()
    
    secret_dir = _get_secret_dir()
    os.makedirs(secret_dir, exist_ok=True)
    
    config_path = os.path.join(secret_dir, "setup_config.json")
    config_data = {
        "model_name": model_name,
        "product_key_hash": key_hash,
        "unlocked": False
    }
    
    with open(config_path, "w") as f:
        json.dump(config_data, f)
        
    try:
        os.chmod(secret_dir, 0o700)
        os.chmod(config_path, 0o600)
    except:
        pass
        
    print("\n\033[93m    IMPORTANT: Save this Product Key! You will need it to unlock the web dashboard.\033[0m")
    print(f"\n        \033[1m\033[92mPRODUCT KEY: {formatted_key}\033[0m\n")

def get_local_ip():
    try:
        # Check active interfaces using 'ip' command if available
        out = subprocess.check_output(['ip', '-4', 'addr', 'show']).decode()
        for line in out.splitlines():
            if 'inet ' in line and '127.0.0.1' not in line:
                return line.split('inet ')[1].split('/')[0]
    except Exception:
        pass
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def finish():
    ip = get_local_ip()
    print("\n\033[1m[5] Setup Complete\033[0m")
    print("\n    To start SharkEye, run:")
    print("        \033[96msudo python3 app.py\033[0m")
    print("\n    Then access the Web UI at:")
    print(f"        \033[94mhttp://{ip}:5000\033[0m\n")

if __name__ == "__main__":
    # Ensure they are in the right directory
    if not os.path.exists("app.py"):
        print("\033[91m[!] Please run initials.py from the SharkEye project root directory.\033[0m")
        sys.exit(1)
        
    print_banner()
    ram, disk = check_system()
    model = check_installed_models()
    terms_and_conditions()
    generate_product_key(model)
    finish()
