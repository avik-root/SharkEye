#!/usr/bin/env python3
"""
SharkEye - WebUI Setup Wizard
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
import threading

try:
    from flask import Flask, request, jsonify, render_template_string
except ImportError:
    print("\033[91m[!] Missing dependency: flask. Run: pip install flask\033[0m")
    sys.exit(1)

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SharkEye Setup</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
      --text: #c9d1d9; --muted: #8b949e; --border: #30363d;
      --blue: #58a6ff; --green: #238636; --red: #f85149;
    }
    body {
      background: var(--bg); color: var(--text);
      font-family: 'Inter', -apple-system, sans-serif;
      margin: 0; display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; width: min(500px, 90vw); padding: 2rem;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }
    .header { text-align: center; margin-bottom: 2rem; }
    .header h1 { margin: 0; color: #fff; font-size: 1.8rem; }
    .header p { color: var(--muted); margin: .5rem 0 0; }
    
    .section {
      background: var(--surface2); padding: 1rem;
      border-radius: 8px; margin-bottom: 1rem;
    }
    .section h3 { margin: 0 0 .5rem 0; color: var(--blue); font-size: 1rem; }
    .stats { display: flex; justify-content: space-between; font-size: .9rem; }
    
    .terms {
      font-size: .8rem; color: var(--muted);
      background: var(--bg); padding: .8rem; border-radius: 6px;
      margin-bottom: 1rem; border: 1px solid var(--border);
    }
    .checkbox-wrap {
      display: flex; align-items: center; gap: .5rem; margin-bottom: 1.5rem;
      font-size: .9rem; cursor: pointer;
    }
    button {
      width: 100%; padding: .8rem; background: var(--green); color: #fff;
      border: none; border-radius: 6px; font-weight: 600; font-size: 1rem;
      cursor: pointer; transition: opacity .2s;
    }
    button:hover { opacity: .9; }
    button:disabled { background: var(--border); color: var(--muted); cursor: not-allowed; }
    
    #success { display: none; text-align: center; }
    .key-box {
      background: rgba(88, 166, 255, 0.1); border: 1px solid var(--blue);
      color: var(--blue); padding: 1rem; border-radius: 8px;
      font-family: monospace; font-size: 1.5rem; letter-spacing: 2px;
      margin: 1.5rem 0;
    }
  </style>
</head>
<body>
  <div class="card" id="setupCard">
    <div class="header">
      <h1>SharkEye Setup</h1>
      <p>Network Intrusion Detection System</p>
    </div>
    
    <div class="section">
      <h3>System Resources</h3>
      <div class="stats">
        <span>RAM: <strong id="ramStr">{{ ram }} GB</strong></span>
        <span>Disk: <strong id="diskStr">{{ disk }} GB</strong></span>
      </div>
    </div>
    
    <div class="terms">
      1. SharkEye is for internal use only.<br>
      2. Do not use on networks you do not own.<br>
      3. MintFire is not responsible for misuse.<br>
      4. AI analysis runs 100% locally.
    </div>
    
    <label class="checkbox-wrap">
      <input type="checkbox" id="agreeCb" onchange="document.getElementById('btnGen').disabled = !this.checked">
      I accept the Terms and Conditions
    </label>
    
    <button id="btnGen" disabled onclick="generate()">Generate Product Key</button>
  </div>
  
  <div class="card" id="success" style="display:none;">
    <div class="header">
      <h1 style="color:var(--green)">Setup Complete!</h1>
      <p>Save your Product Key to unlock the dashboard.</p>
    </div>
    <div class="key-box" id="keyDisplay"></div>
    <p style="color:var(--muted); font-size:.9rem; line-height:1.5">
      This setup server will now shut down automatically.<br>
      Return to your terminal and run:<br><br>
      <code style="background:var(--bg);padding:.4rem;border-radius:4px;color:var(--text)">sudo python3 app.py</code>
    </p>
  </div>

  <script>
    async function generate() {
      const btn = document.getElementById('btnGen');
      btn.innerText = 'Generating...';
      btn.disabled = true;
      try {
        const res = await fetch('/api/generate', {method: 'POST'}).then(r => r.json());
        if (res.key) {
          document.getElementById('setupCard').style.display = 'none';
          document.getElementById('success').style.display = 'block';
          document.getElementById('keyDisplay').innerText = res.key;
        } else {
          alert("Error: " + res.error);
        }
      } catch (e) {
        alert("Network error.");
      }
    }
  </script>
</body>
</html>
"""

def get_total_ram_gb():
    try:
        if os.path.exists('/proc/meminfo'):
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemTotal' in line:
                        kb = int(line.split()[1])
                        return kb / (1024 * 1024)
        elif sys.platform == 'darwin':
            out = subprocess.check_output(['sysctl', 'hw.memsize']).decode().strip()
            return int(out.split(':')[1].strip()) / (1024**3)
    except Exception:
        pass
    return 0

def get_free_disk_gb():
    try:
        _, _, free = shutil.disk_usage("/")
        return free / (1024**3)
    except Exception:
        return 0

def _get_secret_dir():
    app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "app.py"))
    script_hash = hashlib.sha256(app_path.encode()).hexdigest()
    dir_name = f".netaudit_meta_{script_hash[:12]}"
    if os.geteuid() == 0:
        base = "/var/cache"
    else:
        base = os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, dir_name)

def generate_product_key():
    chars = string.ascii_uppercase + string.digits
    raw_key = ''.join(random.choice(chars) for _ in range(16))
    formatted = f"{raw_key[:4]}-{raw_key[4:8]}-{raw_key[8:12]}-{raw_key[12:]}"
    key_hash = hashlib.sha256(formatted.encode()).hexdigest()
    
    secret_dir = _get_secret_dir()
    os.makedirs(secret_dir, exist_ok=True)
    
    config_path = os.path.join(secret_dir, "setup_config.json")
    config_data = {
        "model_name": "",  # To be set via WebUI LLM Manager
        "product_key_hash": key_hash,
        "unlocked": False
    }
    with open(config_path, "w") as f:
        json.dump(config_data, f)
        
    try:
        os.chmod(secret_dir, 0o700)
        os.chmod(config_path, 0o600)
    except Exception:
        pass
        
    return formatted

@app.route("/")
def index():
    ram = round(get_total_ram_gb(), 1)
    disk = round(get_free_disk_gb(), 1)
    return render_template_string(HTML, ram=ram, disk=disk)

def shutdown_server():
    time.sleep(3)
    print("\n\033[92m[✓] Setup complete! WebUI shutting down.\033[0m")
    print("    You can now run: \033[96msudo python3 app.py\033[0m\n")
    os._exit(0)

@app.route("/api/generate", methods=["POST"])
def api_generate():
    try:
        key = generate_product_key()
        threading.Thread(target=shutdown_server, daemon=True).start()
        return jsonify({"key": key})
    except Exception as e:
        return jsonify({"error": str(e)})

def get_local_ip():
    try:
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

if __name__ == "__main__":
    if not os.path.exists("app.py"):
        print("\033[91m[!] Please run initials.py from the SharkEye project root directory.\033[0m")
        sys.exit(1)
        
    print_banner()
    ip = get_local_ip()
    print("\033[1m[Setup Server Started]\033[0m")
    print(f"\n    Open this link in your browser to complete setup:")
    print(f"        \033[1m\033[94mhttp://{ip}:5000\033[0m\n")
    
    # Run silently
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app.run(host="0.0.0.0", port=5000, debug=False)
