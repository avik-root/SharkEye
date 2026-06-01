#!/usr/bin/env python3
"""
SharkEye – Network Intrusion Detection System (NIDS)
Raspberry Pi 5  |  Real-Time Incremental Packet Analysis
"""
import os, sys, subprocess, json, hashlib, threading, time, collections, re, queue
from datetime import datetime
from functools import wraps
from flask import Flask, render_template_string, jsonify, request, Response, session, redirect, url_for

try:
    import bcrypt as _bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False
    print("[BOOT] bcrypt not installed. Run: pip install bcrypt", flush=True)

try:
    import ollama
    from ollama import chat as ollama_chat
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

app = Flask(__name__)

# ── Flask session secret (deterministic per installation, not guessable) ─────
def _derive_secret(tag: str) -> str:
    # Hardcode to app.py so V2 shares the exact same product key and credentials as V1
    base_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    seed = base_file + tag + "SharkEye_salt_2025"
    return hashlib.sha256(seed.encode()).hexdigest()

app.secret_key = _derive_secret("session_key")

# ========================= GLOBAL CONFIG =========================
MODEL_NAME           = "qwen2.5-coder:3b"
INTERFACE            = ""          # set by Web UI before capture starts
SUB_CAPTURE_DURATION = 30          # seconds per tshark batch
MAX_PACKETS_LLM      = 180
HISTORY_LENGTH       = 30
LOG_MAXLEN           = 600
HISTORY_DIR          = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sharkeye_history")
# =================================================================

# ── State ─────────────────────────────────────────────────────────
latest_report  = {}
is_capturing   = False
capture_thread = None
history        = []
incident_log   = []
state_lock     = threading.Lock()
_start_lock    = threading.Lock()

# ── Session tracking ──────────────────────────────────────────────
SESSION_ID    = datetime.now().strftime("%Y%m%d_%H%M%S")   # unique per run
_session_start: datetime | None = None
_session_end:   datetime | None = None

# ── Log bus (SSE) ─────────────────────────────────────────────────
_log_lines  = collections.deque(maxlen=LOG_MAXLEN)
_log_lock   = threading.Lock()
_sse_queues = []
_sse_q_lock = threading.Lock()

_ollama_ok  = False
_tshark_ok  = False

# ========================= AUTH / CREDENTIAL STORE =========================

def _get_secret_dir() -> str:
    """
    Compute a deterministic but non-obvious directory path to store
    hashed credentials.  The path is derived from a SHA-256 of this
    script’s absolute path so it changes if the file is moved.
    Stored under /var/cache (running as root) or ~/.cache otherwise,
    inside a directory named after a plausible-looking system artefact.
    """
    # Hardcode to app.py so V2 shares the exact same secret dir as V1
    base_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    script_hash = hashlib.sha256(base_file.encode()).hexdigest()
    dir_name    = f".netaudit_meta_{script_hash[:12]}"   # looks like a cache dir
    return os.path.join("/var/tmp", dir_name)


def _creds_path() -> str:
    return os.path.join(_get_secret_dir(), "idxmap.bin")   # innocuous filename


def _setup_config_path() -> str:
    return os.path.join(_get_secret_dir(), "setup_config.json")

def load_setup_config() -> dict:
    try:
        with open(_setup_config_path(), "r") as fh:
            return json.load(fh)
    except Exception:
        return {}

def save_setup_config(cfg: dict):
    with open(_setup_config_path(), "w") as fh:
        json.dump(cfg, fh)


def init_credentials():
    """
    Create the secret directory and write bcrypt-hashed credentials
    if the credentials file does not yet exist.
    Default credentials: sharkeye / mintfire
    """
    if not BCRYPT_OK:
        print("[AUTH] bcrypt unavailable – cannot init credentials.", flush=True)
        return
    secret_dir = _get_secret_dir()
    os.makedirs(secret_dir, exist_ok=True)
    # Hide the directory on Linux
    try:
        os.chmod(secret_dir, 0o700)
    except Exception:
        pass

    creds_file = _creds_path()
    needs_init = False
    
    if not os.path.exists(creds_file):
        needs_init = True
    else:
        # Check if the store has the old 'sharkEYE' format and update it
        try:
            with open(creds_file, "r") as fh:
                store = json.load(fh)
            if "sharkeye" not in store:
                needs_init = True
        except Exception:
            needs_init = True

    if needs_init:
        # Hash the default password (handle both string and bytes requirements for bcrypt)
        try:
            pw_hash = _bcrypt.hashpw(b"mintfire", _bcrypt.gensalt(12))
        except TypeError:
            pw_hash = _bcrypt.hashpw("mintfire", _bcrypt.gensalt(12))
            
        hash_str = pw_hash.decode() if isinstance(pw_hash, bytes) else pw_hash
        store   = {"sharkeye": hash_str}
        with open(creds_file, "w") as fh:
            json.dump(store, fh)
        try:
            os.chmod(creds_file, 0o600)
        except Exception:
            pass
        print(f"[AUTH] Credentials initialised at {creds_file}", flush=True)
    else:
        print(f"[AUTH] Credentials loaded from secret store.", flush=True)
        
    # Load settings from initials.py setup
    cfg = load_setup_config()
    global MODEL_NAME
    if "model_name" in cfg and cfg["model_name"]:
        MODEL_NAME = cfg["model_name"]
    else:
        # If blank or missing, try to auto-detect from installed models
        try:
            if OLLAMA_AVAILABLE:
                import ollama
                models_resp = ollama.list()
                if hasattr(models_resp, 'models'):
                    models_list = [getattr(m, 'model', getattr(m, 'name', '')) for m in models_resp.models]
                else:
                    models_list = [m.get("name", m.get("model", "")) for m in models_resp.get("models", [])]
                
                models_list = [m for m in models_list if m]
                if models_list:
                    MODEL_NAME = models_list[0]
                    cfg["model_name"] = MODEL_NAME
                    save_setup_config(cfg)
                    print(f"[BOOT] Auto-selected active LLM: {MODEL_NAME}", flush=True)
                else:
                    MODEL_NAME = ""
        except Exception:
            MODEL_NAME = ""
            
        if "model_name" not in cfg:
            print("[BOOT] \033[93mWarning: setup_config.json not found. Did you run initials.py?\033[0m", flush=True)


def _load_store() -> dict:
    """Load the credentials JSON from the secret file."""
    try:
        with open(_creds_path(), "r") as fh:
            return json.load(fh)
    except Exception:
        return {}


def verify_login(username: str, password: str) -> bool:
    """Return True if username/password match the stored bcrypt hash."""
    if not BCRYPT_OK:
        return False
    store = _load_store()
    if username not in store:
        return False
    try:
        return _bcrypt.checkpw(password.encode(), store[username].encode())
    except TypeError:
        return _bcrypt.checkpw(password, store[username])
    except Exception:
        return False


# ── Login-required decorator ───────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")
            
        cfg = load_setup_config()
        if not cfg.get("unlocked", False) and request.endpoint not in ["unlock_page", "logout"]:
            return redirect("/unlock")
            
        return f(*args, **kwargs)
    return decorated
def log(msg: str, level: str = "info"):
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}][{level.upper():5s}] {msg}"
    print(line, flush=True)
    with _log_lock:
        _log_lines.append(line)
    with _sse_q_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(q)
        for q in dead:
            try: _sse_queues.remove(q)
            except ValueError: pass

def _pipe_to_log(stream, label, level="info"):
    try:
        for raw in iter(stream.readline, b''):
            text = raw.decode(errors='replace').rstrip()
            if text:
                log(f"[{label}] {text}", level)
    except Exception:
        pass

# ========================= HTML =========================
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SharkEye V2 - Premium NIDS</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    :root {
      --bg: #09090b;
      --surface: #18181b;
      --surface2: #27272a;
      --border: #3f3f46;
      --text: #f4f4f5;
      --muted: #a1a1aa;
      
      --blue: #3b82f6;
      --blue-glow: rgba(59, 130, 246, 0.4);
      --green: #10b981;
      --green-glow: rgba(16, 185, 129, 0.4);
      --red: #f43f5e;
      --red-glow: rgba(244, 63, 94, 0.4);
      --yellow: #f59e0b;
      
      --sidebar-width: 250px;
    }
    
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 0;
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    
    /* ── Scrollbars ── */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--muted); }
    
    /* ── Sidebar ── */
    .sidebar {
      width: var(--sidebar-width);
      background: var(--surface);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      padding: 1.5rem 1rem;
      z-index: 10;
    }
    .brand {
      display: flex; align-items: center; gap: .75rem;
      margin-bottom: 2.5rem; padding: 0 .5rem;
    }
    .brand-icon {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, var(--blue), #60a5fa);
      border-radius: 8px;
      box-shadow: 0 0 15px var(--blue-glow);
      display: flex; align-items: center; justify-content: center;
      font-weight: 700; font-size: 1.2rem; color: #fff;
    }
    .brand-text {
      font-size: 1.25rem; font-weight: 700; letter-spacing: 1px;
    }
    .brand-text span { color: var(--blue); }
    
    .nav-btn {
      background: transparent; border: none;
      color: var(--muted); font-size: 1rem; font-weight: 500;
      text-align: left; padding: .8rem 1rem; border-radius: 8px;
      margin-bottom: .5rem; cursor: pointer;
      transition: all 0.2s;
      display: flex; justify-content: space-between; align-items: center;
    }
    .nav-btn:hover { background: rgba(255,255,255,0.05); color: var(--text); }
    .nav-btn.active {
      background: var(--blue-glow); color: #fff;
      box-shadow: inset 4px 0 0 var(--blue);
    }
    .nav-badge {
      background: var(--red); color: #fff;
      font-size: .7rem; padding: .1rem .4rem; border-radius: 12px;
      display: none; font-weight: 600;
    }
    
    .sidebar-footer {
      margin-top: auto; padding-top: 1rem;
      border-top: 1px solid var(--border);
      font-size: .8rem; color: var(--muted); text-align: center;
    }
    
    /* ── Main Content ── */
    .main-content {
      flex: 1; display: flex; flex-direction: column;
      position: relative; overflow-y: auto; overflow-x: hidden;
    }
    .topbar {
      height: 70px; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 2rem; background: rgba(24, 24, 27, 0.8);
      backdrop-filter: blur(10px); position: sticky; top: 0; z-index: 9;
    }
    .status-badges { display: flex; gap: 1rem; }
    .badge {
      padding: .4rem .8rem; border-radius: 20px; font-size: .75rem; font-weight: 600;
      display: flex; align-items: center; gap: .5rem; background: var(--surface2);
      border: 1px solid var(--border);
    }
    .badge .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
    .badge.ok .dot { background: var(--green); box-shadow: 0 0 8px var(--green-glow); }
    .badge.err .dot { background: var(--red); box-shadow: 0 0 8px var(--red-glow); }
    .badge.busy .dot { background: var(--yellow); box-shadow: 0 0 8px var(--yellow); animation: pulse 1s infinite; }
    
    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.6; transform: scale(1.2); }
      100% { opacity: 1; transform: scale(1); }
    }
    
    .tab-content { display: none; padding: 2rem; animation: fadein 0.3s; }
    .tab-content.active { display: block; }
    @keyframes fadein { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    
    /* ── Grid Layouts ── */
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.5rem; margin-bottom: 1.5rem; }
    .grid-2 { display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
    
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 1.5rem;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      position: relative; overflow: hidden;
    }
    .card.glow-red { border-color: rgba(244,63,94,0.5); box-shadow: 0 0 20px var(--red-glow); }
    
    .stat-title { font-size: .85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-bottom: .5rem; }
    .stat-val { font-size: 2.5rem; font-weight: 700; line-height: 1; margin-bottom: .5rem; color: #fff; }
    .stat-sub { font-size: .8rem; color: var(--muted); }
    
    .card-title { font-size: 1.1rem; font-weight: 600; margin: 0 0 1rem 0; color: #fff; display: flex; justify-content: space-between; align-items: center; }
    
    /* ── Buttons & Inputs ── */
    .btn {
      background: var(--surface2); color: #fff; border: 1px solid var(--border);
      padding: .6rem 1.2rem; border-radius: 8px; font-weight: 500; cursor: pointer;
      transition: all 0.2s; display: inline-flex; align-items: center; gap: .5rem;
    }
    .btn:hover:not(:disabled) { background: var(--border); }
    .btn.primary { background: var(--blue); border-color: var(--blue); box-shadow: 0 0 10px var(--blue-glow); }
    .btn.primary:hover:not(:disabled) { background: #2563eb; }
    .btn.danger { background: rgba(244,63,94,0.1); color: var(--red); border-color: rgba(244,63,94,0.3); }
    .btn.danger:hover:not(:disabled) { background: rgba(244,63,94,0.2); }
    .btn.success { background: rgba(16,185,129,0.1); color: var(--green); border-color: rgba(16,185,129,0.3); }
    .btn.success:hover:not(:disabled) { background: rgba(16,185,129,0.2); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    
    select.form-ctrl {
      background: var(--bg); color: var(--text); border: 1px solid var(--border);
      padding: .6rem 1rem; border-radius: 8px; font-size: 1rem; width: 100%;
    }
    
    /* ── Terminal ── */
    .term {
      background: #000; font-family: 'Fira Code', monospace; font-size: .85rem;
      padding: 1rem; border-radius: 8px; height: 400px; overflow-y: auto;
      border: 1px solid var(--border);
    }
    .term .t-ok { color: var(--green); }
    .term .t-err { color: var(--red); }
    .term .t-warn { color: var(--yellow); }
    .term .t-info { color: var(--blue); }
    .term .t-ts { color: var(--muted); margin-right: .5rem; }
    
    /* ── Incidents UI ── */
    .inc-card {
      background: var(--bg); border: 1px solid rgba(244,63,94,0.3);
      border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem;
      border-left: 4px solid var(--red);
    }
    .inc-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: .8rem; }
    .inc-badge { background: rgba(244,63,94,0.15); color: var(--red); padding: .2rem .6rem; border-radius: 4px; font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }
    .inc-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
    .inc-title { font-size: .8rem; text-transform: uppercase; color: var(--muted); letter-spacing: 1px; margin-bottom: .5rem; font-weight: 600; }
    .inc-list { margin: 0; padding-left: 1.2rem; color: #fff; font-size: .95rem; line-height: 1.6; }
    .inc-list li { margin-bottom: .4rem; }
    
    /* ── Settings / LLM ── */
    .llm-item {
      display: flex; justify-content: space-between; align-items: center;
      padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: .8rem;
      background: var(--bg);
    }
    .llm-item:hover { border-color: var(--muted); }
    
    /* ── History UI ── */
    .hist-grid { display: grid; grid-template-columns: 300px 1fr; gap: 1.5rem; height: calc(100vh - 150px); }
    .hist-dates { overflow-y: auto; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; }
    .hist-main { overflow-y: auto; padding-right: .5rem; }
    .hist-date-btn {
      width: 100%; text-align: left; background: none; border: none; border-bottom: 1px solid var(--border);
      padding: 1rem; color: var(--text); cursor: pointer; transition: all .2s; display: flex; align-items: center; gap: 1rem;
    }
    .hist-date-btn:hover { background: rgba(255,255,255,0.05); }
    .hist-date-btn.active { background: var(--blue-glow); box-shadow: inset 3px 0 0 var(--blue); }
    .hist-date-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--green); }
    .hist-date-dot.warn { background: var(--red); box-shadow: 0 0 8px var(--red-glow); }
    
    .sess-card {
      background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
      margin-bottom: 1.5rem; overflow: hidden;
    }
    .sess-head { padding: 1rem; background: var(--surface2); display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }
    .sess-stats { display: grid; grid-template-columns: repeat(4, 1fr); padding: 1rem; gap: 1rem; }
    .sess-stat { text-align: center; padding: .5rem; background: var(--surface); border-radius: 8px; border: 1px solid var(--border); }
    .sess-stat-label { font-size: .7rem; color: var(--muted); text-transform: uppercase; }
    .sess-stat-val { font-size: 1.2rem; font-weight: 700; color: #fff; margin-top: .3rem; }
    
    /* Toast */
    .toast-area { position: fixed; bottom: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
    .toast { background: var(--surface2); color: #fff; padding: 12px 20px; border-radius: 8px; border-left: 4px solid var(--blue); box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: slideIn 0.3s forwards; }
    @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  </style>
</head>
<body>

  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="brand">
      <div class="brand-icon">S</div>
      <div class="brand-text">Shark<span>Eye</span><span style="font-size:.7rem;color:var(--muted);vertical-align:top;margin-left:4px">v2</span></div>
    </div>
    
    <button class="nav-btn active" data-tab="dashboard">
      <span>📊 Overview</span>
    </button>
    <button class="nav-btn" data-tab="live">
      <span>📡 Live Capture</span>
    </button>
    <button class="nav-btn" data-tab="incidents">
      <span>🚨 Incidents <span class="nav-badge" id="navIncBadge">0</span></span>
    </button>
    <button class="nav-btn" data-tab="history">
      <span>📅 History</span>
    </button>
    <button class="nav-btn" data-tab="settings">
      <span>⚙️ Settings & LLM</span>
    </button>
    
    <div class="sidebar-footer">
      <div>MintFire Security</div>
      <div style="font-size:.7rem;margin-top:.3rem">Connected to Core</div>
    </div>
  </div>

  <!-- MAIN WRAPPER -->
  <div class="main-content">
    
    <!-- TOPBAR -->
    <div class="topbar">
      <div class="status-badges">
        <div class="badge" id="bCapture"><div class="dot"></div> Capture: Idle</div>
        <div class="badge" id="bOllama"><div class="dot"></div> Ollama</div>
        <div class="badge" id="bTshark"><div class="dot"></div> tshark</div>
      </div>
      <div>
        <a href="/logout" style="color:var(--muted);text-decoration:none;font-size:.9rem;font-weight:500;transition:color .2s" onmouseover="this.style.color='#fff'" onmouseout="this.style.color='var(--muted)'">Log Out →</a>
      </div>
    </div>

    <!-- TAB: DASHBOARD -->
    <div class="tab-content active" id="tab-dashboard">
      <div class="card-title" style="font-size:1.5rem;margin-bottom:1.5rem">Security Overview</div>
      
      <div class="grid-4">
        <div class="card">
          <div class="stat-title">Packets (Batch)</div>
          <div class="stat-val" id="dPackets">0</div>
          <div class="stat-sub">Live traffic volume</div>
        </div>
        <div class="card">
          <div class="stat-title">Unique IPs</div>
          <div class="stat-val" id="dIPs">0</div>
          <div class="stat-sub">Communicating hosts</div>
        </div>
        <div class="card" id="cardAnom">
          <div class="stat-title">Anomalies</div>
          <div class="stat-val" id="dAnom" style="color:var(--yellow)">0</div>
          <div class="stat-sub">Suspicious behaviors</div>
        </div>
        <div class="card" id="cardMal">
          <div class="stat-title">Malicious</div>
          <div class="stat-val" id="dMal" style="color:var(--red)">0</div>
          <div class="stat-sub">Critical threats</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="card-title">Traffic Volume History</div>
          <canvas id="volChart" height="250"></canvas>
        </div>
        <div class="card">
          <div class="card-title">Protocol Distribution</div>
          <canvas id="protoChart" height="250"></canvas>
        </div>
      </div>
      
      <div class="card">
        <div class="card-title">Latest AI Analysis Summary</div>
        <pre id="dSummary" style="background:var(--bg);padding:1rem;border-radius:8px;border:1px solid var(--border);color:var(--muted);font-family:monospace;white-space:pre-wrap;font-size:.85rem;min-height:100px;">Waiting for capture batch...</pre>
      </div>
    </div>

    <!-- TAB: LIVE CAPTURE -->
    <div class="tab-content" id="tab-live">
      <div class="card" style="margin-bottom:1.5rem">
        <div class="card-title">Capture Controls</div>
        <div style="display:flex;gap:1rem;align-items:center">
          <select id="ifaceSel" class="form-ctrl" style="max-width:300px">
            <option value="">Loading interfaces...</option>
          </select>
          <button class="btn success" id="startBtn" onclick="startCapture()">▶ Start</button>
          <button class="btn danger" id="stopBtn" onclick="stopCapture()" disabled>⏹ Stop</button>
          <button class="btn" onclick="document.getElementById('termLog').innerHTML=''">🗑 Clear</button>
        </div>
      </div>
      
      <div class="card">
        <div class="card-title">Real-Time Log <span id="sseStatus" style="font-size:.8rem;color:var(--muted);font-weight:400">connecting...</span></div>
        <div class="term" id="termLog"></div>
      </div>
    </div>

    <!-- TAB: INCIDENTS -->
    <div class="tab-content" id="tab-incidents">
      <div class="card-title" style="font-size:1.5rem;margin-bottom:1.5rem">Incident & Recommendation Log</div>
      <div id="incidentsList">
        <div style="text-align:center;color:var(--muted);padding:4rem 0;background:var(--surface);border-radius:12px;border:1px dashed var(--border)">
          <div style="font-size:3rem;margin-bottom:1rem">🛡️</div>
          <div style="font-size:1.1rem;font-weight:500;color:#fff">System Secure</div>
          <p>No malicious events detected during this session.</p>
        </div>
      </div>
    </div>

    <!-- TAB: HISTORY -->
    <div class="tab-content" id="tab-history">
      <div class="card-title" style="font-size:1.5rem;margin-bottom:1.5rem">Historical Audits</div>
      <div class="hist-grid">
        <div class="hist-dates">
          <div style="padding:1rem;border-bottom:1px solid var(--border);font-weight:600;color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:1px">Saved Dates</div>
          <div id="histDateList">Loading...</div>
        </div>
        <div class="hist-main" id="histMain">
          <div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted)">Select a date from the left to view details.</div>
        </div>
      </div>
    </div>

    <!-- TAB: SETTINGS -->
    <div class="tab-content" id="tab-settings">
      <div class="grid-2">
        <div class="card">
          <div class="card-title">LLM Manager</div>
          <p style="color:var(--muted);font-size:.9rem;margin-bottom:1.5rem;line-height:1.5">Manage local AI models via Ollama. SharkEye requires a model to analyze packet batches. We recommend <code style="color:var(--blue)">qwen2.5-coder:3b</code> or <code style="color:var(--blue)">mistral:7b</code>.</p>
          
          <div style="margin-bottom:1.5rem;background:var(--bg);padding:1rem;border-radius:8px;border:1px solid var(--border)">
            <div class="stat-title">Currently Active</div>
            <div style="font-size:1.2rem;font-weight:600;color:var(--green)">{{ active_model }}</div>
          </div>
          
          <div class="stat-title" style="margin-bottom:.8rem">Installed Models</div>
          <div id="installedModelsList">Loading...</div>
        </div>
        
        <div class="card">
          <div class="card-title">Install New Model</div>
          <div style="display:flex;gap:.5rem;margin-bottom:1.5rem">
            <input type="text" id="pullName" class="form-ctrl" placeholder="e.g. qwen2.5-coder:3b" style="background:var(--bg);border:1px solid var(--border);color:#fff;padding:.6rem 1rem;border-radius:8px;width:100%">
            <button class="btn primary" onclick="pullLlm(document.getElementById('pullName').value)">Pull</button>
          </div>
          
          <div id="llmProgressArea" style="display:none;background:var(--bg);padding:1.5rem;border-radius:8px;border:1px solid var(--border)">
            <div style="display:flex;justify-content:space-between;margin-bottom:.8rem;font-size:.9rem;font-weight:500">
              <span id="llmProgressText">Starting...</span>
              <span id="llmProgressPct" style="color:var(--blue)">0%</span>
            </div>
            <div style="height:8px;background:var(--surface);border-radius:4px;overflow:hidden">
              <div id="llmProgressBar" style="height:100%;background:var(--blue);width:0%;transition:width .2s"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
  </div><!-- /main-content -->

  <div class="toast-area" id="toastArea"></div>

  <script>
    /* ── UI Logic ──────────────────────────────────────────────── */
    const tabs = document.querySelectorAll('.nav-btn');
    const contents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(t => {
      t.addEventListener('click', () => {
        tabs.forEach(btn => btn.classList.remove('active'));
        contents.forEach(cnt => cnt.classList.remove('active'));
        t.classList.add('active');
        document.getElementById('tab-' + t.dataset.tab).classList.add('active');
        
        if(t.dataset.tab === 'history') openHistory();
      });
    });

    function showToast(msg, type='info') {
      const area = document.getElementById('toastArea');
      const el = document.createElement('div');
      el.className = 'toast';
      if(type==='err') el.style.borderLeftColor = 'var(--red)';
      if(type==='ok')  el.style.borderLeftColor = 'var(--green)';
      if(type==='warn') el.style.borderLeftColor = 'var(--yellow)';
      el.innerText = msg;
      area.appendChild(el);
      setTimeout(()=>el.remove(), 4000);
    }
    
    function logTerm(text, lvl) {
      const b = document.getElementById('termLog');
      const ts = new Date().toLocaleTimeString('en-GB',{hour12:false});
      let cls = 't-info';
      if(lvl==='ok') cls='t-ok'; if(lvl==='err') cls='t-err'; if(lvl==='warn') cls='t-warn';
      const row = document.createElement('div');
      row.innerHTML = \`<span class="t-ts">[\${ts}]</span><span class="\${cls}">\${text}</span>\`;
      b.appendChild(row);
      if(b.childNodes.length > 600) b.firstChild.remove();
      b.scrollTop = b.scrollHeight;
    }

    /* ── State & Charts ────────────────────────────────────────── */
    let isCapturing = false;
    let selectedIface = '';
    let incidentsData = [];
    let volChart, protoChart;
    
    function initCharts() {
      Chart.defaults.color = '#a1a1aa';
      Chart.defaults.font.family = 'Inter';
      
      const ctxV = document.getElementById('volChart').getContext('2d');
      const grad = ctxV.createLinearGradient(0,0,0,250);
      grad.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
      grad.addColorStop(1, 'rgba(59, 130, 246, 0.0)');
      
      volChart = new Chart(ctxV, {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Packets', data: [], borderColor: '#3b82f6', backgroundColor: grad, fill: true, tension: 0.4, pointRadius: 0 }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: {display:false} }, scales: { y: {beginAtZero:true, grid:{color:'#3f3f46'}}, x:{grid:{display:false}} } }
      });
      
      protoChart = new Chart(document.getElementById('protoChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['TCP','UDP','Other'], datasets: [{ data: [1,1,1], backgroundColor: ['#3b82f6','#10b981','#f59e0b'], borderWidth:0 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { position: 'right' } } }
      });
    }

    /* ── Polling & SSE ─────────────────────────────────────────── */
    async function fetchStats() {
      try {
        const d = await fetch('/stats').then(r=>r.json());
        
        // Badges
        const bc = document.getElementById('bCapture');
        bc.className = 'badge ' + (d.capturing ? 'busy' : '');
        bc.innerHTML = \`<div class="dot"></div> \${d.capturing ? 'Capture: Active' : 'Capture: Idle'}\`;
        
        const bo = document.getElementById('bOllama');
        bo.className = 'badge ' + (d.ollama_ok ? 'ok' : 'err');
        bo.innerHTML = \`<div class="dot"></div> \${d.ollama_ok ? 'Ollama: Running' : 'Ollama: Down'}\`;
        
        const bt = document.getElementById('bTshark');
        bt.className = 'badge ' + (d.tshark_ok ? 'ok' : 'err');
        bt.innerHTML = \`<div class="dot"></div> \${d.tshark_ok ? 'tshark: Ready' : 'tshark: Error'}\`;
        
        // Buttons
        isCapturing = d.capturing;
        document.getElementById('startBtn').disabled = isCapturing;
        document.getElementById('stopBtn').disabled = !isCapturing;
        
        // Stats
        document.getElementById('dPackets').innerText = d.total_packets.toLocaleString();
        document.getElementById('dIPs').innerText = d.unique_src_ips.toLocaleString();
        document.getElementById('dAnom').innerText = d.anomalies_detected.toLocaleString();
        document.getElementById('dMal').innerText = (d.analysis?.malicious_activities || []).length;
        
        if (d.analysis?.malicious_activities?.length > 0) {
          document.getElementById('cardMal').classList.add('glow-red');
        } else {
          document.getElementById('cardMal').classList.remove('glow-red');
        }
        
        // Charts
        if(d.history && d.history.length) {
          volChart.data.labels = d.history.map(x=>x.timestamp);
          volChart.data.datasets[0].data = d.history.map(x=>x.packet_count);
          volChart.update('none');
        }
        const p = d.proto || {};
        if((p.tcp||0)+(p.udp||0)+(p.other||0) > 0) {
          protoChart.data.datasets[0].data = [p.tcp||0, p.udp||0, p.other||0];
          protoChart.update('none');
        }
        
        // Summary
        if(Object.keys(d.analysis||{}).length) {
          const an = d.analysis;
          let txt = '';
          if(an.summary) txt += \`[ SUMMARY ]\\n\${an.summary}\\n\\n\`;
          if(an.malicious_activities && an.malicious_activities.length) txt += \`[ 🚨 MALICIOUS ]\\n\${an.malicious_activities.join('\\n')}\\n\\n\`;
          if(an.recommendations && an.recommendations.length) txt += \`[ 💡 RECOMMENDATIONS ]\\n\${an.recommendations.join('\\n')}\\n\`;
          if(an.error) txt = \`[ ERROR ]\\n\${an.error}\`;
          document.getElementById('dSummary').textContent = txt.trim();
        }
        
        // Incidents
        if (d.incident_log) {
          incidentsData = d.incident_log;
          const badg = document.getElementById('navIncBadge');
          if(incidentsData.length > 0) {
            badg.style.display = 'inline-block';
            badg.innerText = incidentsData.length;
          } else {
            badg.style.display = 'none';
          }
          renderIncidents();
        }

      } catch(e) { console.error('fetchStats error', e); }
    }

    function renderIncidents() {
      const container = document.getElementById('incidentsList');
      if (!incidentsData || incidentsData.length === 0) return;
      
      const reversed = [...incidentsData].reverse();
      container.innerHTML = reversed.map(inc => {
        return \`
          <div class="inc-card">
            <div class="inc-head">
              <div class="inc-badge">Incident Detected</div>
              <div style="font-size:.8rem;color:var(--muted)">\${inc.timestamp}</div>
            </div>
            <div class="inc-grid">
              <div>
                <div class="inc-title" style="color:var(--red)">Identified Issues</div>
                <ul class="inc-list">
                  \${inc.issues.map(i => \`<li>\${i}</li>\`).join('')}
                </ul>
              </div>
              <div>
                <div class="inc-title" style="color:var(--green)">AI Recommendations</div>
                <ul class="inc-list">
                  \${inc.implementations && inc.implementations.length ? inc.implementations.map(r => \`<li>\${r}</li>\`).join('') : '<li style="color:var(--muted)">No recommendations provided.</li>'}
                </ul>
              </div>
            </div>
          </div>
        \`;
      }).join('');
    }

    /* ── Controls ──────────────────────────────────────────────── */
    async function loadIfaces() {
      const sel = document.getElementById('ifaceSel');
      try {
        const d = await fetch('/api/interfaces').then(r=>r.json());
        sel.innerHTML = d.interfaces.map(i=>\`<option value="\${i}">\${i}</option>\`).join('');
      } catch(e) { sel.innerHTML = '<option>Error loading</option>'; }
    }
    
    async function startCapture() {
      const ifc = document.getElementById('ifaceSel').value;
      if(!ifc) return alert("Select an interface!");
      document.getElementById('startBtn').disabled = true;
      try {
        await fetch('/start', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({interface:ifc})});
        showToast('Capture started', 'ok');
        setTimeout(fetchStats, 1000);
      } catch(e) { showToast('Start failed: '+e, 'err'); document.getElementById('startBtn').disabled = false; }
    }
    
    async function stopCapture() {
      document.getElementById('stopBtn').disabled = true;
      try {
        await fetch('/stop', {method:'POST'});
        showToast('Capture stopped', 'info');
        setTimeout(fetchStats, 1000);
      } catch(e) { showToast('Stop failed: '+e, 'err'); document.getElementById('stopBtn').disabled = false; }
    }
    
    /* ── LLM Management ────────────────────────────────────────── */
    async function refreshLlmList() {
      const container = document.getElementById('installedModelsList');
      container.innerHTML = '<div style="color:var(--muted)">Loading...</div>';
      try {
        const res = await fetch('/api/llm/list').then(r=>r.json());
        if (res.error) {
          container.innerHTML = \`<div style="color:var(--red);margin-bottom:1rem">Error: \${res.error}</div><button class="btn primary" onclick="installOllama()">Auto-Install Ollama</button>\`;
          return;
        }
        const models = res.models || [];
        if (models.length === 0) {
          container.innerHTML = '<div style="color:var(--muted)">No models installed.</div>';
        } else {
          container.innerHTML = models.map(m => \`
            <div class="llm-item">
              <div>
                <div style="font-weight:600;color:var(--text);margin-bottom:.2rem">\${m.name}</div>
                <div style="font-size:.7rem;color:var(--muted)">\${Math.round(m.size/1e9*10)/10} GB</div>
              </div>
              <div style="display:flex;gap:.5rem">
                <button class="btn success" style="padding:.4rem .8rem;font-size:.8rem" onclick="selectLlm('\${m.name}')">Activate</button>
                <button class="btn danger" style="padding:.4rem .8rem;font-size:.8rem" onclick="deleteLlm('\${m.name}')">Delete</button>
              </div>
            </div>
          \`).join('');
        }
      } catch(e) { container.innerHTML = '<div style="color:var(--red)">Error loading models.</div>'; }
    }

    async function installOllama() {
      const btn = event.target;
      btn.innerText = "Starting...";
      btn.disabled = true;
      try {
        const res = await fetch('/api/llm/install_ollama', {method:'POST'}).then(r=>r.json());
        if (res.status === 'manual') { window.open('https://ollama.com/download/mac', '_blank'); alert(res.msg); btn.innerText = "Download for Mac"; btn.disabled = false; }
        else { alert(res.msg); btn.innerText = "Installing (Check terminal)"; }
      } catch(e) { alert(e); btn.innerText = "Error"; }
    }

    async function deleteLlm(name) {
      if(!confirm(\`Delete \${name}?\`)) return;
      await fetch('/api/llm/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({model: name}) });
      refreshLlmList(); showToast('Model deleted', 'ok');
    }

    async function selectLlm(name) {
      await fetch('/api/llm/select', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({model: name}) });
      showToast(\`Active model set to \${name}. Refreshing page...\`, 'ok');
      setTimeout(()=>location.reload(), 1000);
    }
    
    let llmEvtSource = null;
    function pullLlm(name) {
      if(!name) return alert("Enter model name");
      if (llmEvtSource) llmEvtSource.close();
      document.getElementById('llmProgressArea').style.display = 'block';
      document.getElementById('llmProgressText').innerText = \`Pulling \${name}...\`;
      document.getElementById('llmProgressText').style.color = 'var(--text)';
      document.getElementById('llmProgressBar').style.width = '0%';
      document.getElementById('llmProgressPct').innerText = '0%';
      
      llmEvtSource = new EventSource(\`/api/llm/pull?model=\${name}\`);
      llmEvtSource.onmessage = function(e) {
        const data = JSON.parse(e.data);
        if (data.error) { document.getElementById('llmProgressText').innerText = \`Error: \${data.error}\`; document.getElementById('llmProgressText').style.color = 'var(--red)'; llmEvtSource.close(); return; }
        if (data.status) document.getElementById('llmProgressText').innerText = data.status;
        if (data.total && data.completed) {
          const pct = Math.round((data.completed / data.total) * 100);
          document.getElementById('llmProgressBar').style.width = pct + '%';
          document.getElementById('llmProgressPct').innerText = pct + '%';
        }
        if (data.status === 'success') {
          document.getElementById('llmProgressText').innerText = "Download complete!";
          document.getElementById('llmProgressText').style.color = 'var(--green)';
          llmEvtSource.close();
          refreshLlmList();
          showToast('Model downloaded successfully', 'ok');
        }
      };
      llmEvtSource.onerror = function() { llmEvtSource.close(); };
    }

    /* ── History Logic ─────────────────────────────────────────── */
    async function openHistory() {
      const list = document.getElementById('histDateList');
      list.innerHTML = '<div style="padding:1rem;color:var(--muted)">Loading...</div>';
      try {
        const data = await fetch('/api/history').then(r=>r.json());
        const dates = data.dates || [];
        if(!dates.length) { list.innerHTML = '<div style="padding:1rem;color:var(--muted)">No history saved.</div>'; return; }
        list.innerHTML = dates.map(d => {
          const hasMal = d.total_malicious > 0;
          return \`
            <button class="hist-date-btn" onclick="loadHistoryDay('\${d.date}', this)">
              <div class="hist-date-dot \${hasMal ? 'warn' : ''}"></div>
              <div>
                <div style="font-weight:600">\${d.date}</div>
                <div style="font-size:.7rem;color:var(--muted);margin-top:.2rem">\${d.session_count} sess • \${d.total_packets.toLocaleString()} pkts</div>
              </div>
            </button>
          \`;
        }).join('');
        const firstBtn = list.querySelector('.hist-date-btn');
        if (firstBtn) firstBtn.click();
      } catch(e) { list.innerHTML = \`<div style="color:var(--red);padding:1rem">Error: \${e}</div>\`; }
    }
    
    async function loadHistoryDay(date, btn) {
      document.querySelectorAll('.hist-date-btn').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      const main = document.getElementById('histMain');
      main.innerHTML = '<div style="padding:2rem;color:var(--muted);text-align:center">Loading data for ' + date + '...</div>';
      
      try {
        const day = await fetch(\`/api/history/\${date}\`).then(r => r.json());
        const sessions = Object.values(day.sessions || {});
        if (!sessions.length) { main.innerHTML = '<div style="padding:2rem;text-align:center;color:var(--muted)">No sessions.</div>'; return; }
        
        let html = '';
        sessions.forEach((sess, si) => {
          const smal  = sess.batches.reduce((a,b) => a + (b.malicious||[]).length, 0);
          const spkt  = sess.batches.reduce((a,b) => a + b.packet_count, 0);
          html += \`
            <div class="sess-card">
              <div class="sess-head">
                <div>
                  <div style="font-weight:600;color:#fff">📶 Session \${si+1} (\${sess.interface})</div>
                  <div style="font-size:.7rem;color:var(--muted);margin-top:.2rem">ID: \${sess.session_id}</div>
                </div>
                <div style="text-align:right">
                  <div style="font-size:.8rem;color:var(--muted)">\${sess.session_start}</div>
                  <div style="font-size:.7rem;color:var(--muted)">\${sess.duration_s}s duration</div>
                </div>
              </div>
              <div class="sess-stats">
                <div class="sess-stat"><div class="sess-stat-label">Batches</div><div class="sess-stat-val">\${sess.batches.length}</div></div>
                <div class="sess-stat"><div class="sess-stat-label">Packets</div><div class="sess-stat-val">\${spkt.toLocaleString()}</div></div>
                <div class="sess-stat"><div class="sess-stat-label">Malicious</div><div class="sess-stat-val" style="color:\${smal>0?'var(--red)':'var(--green)'}">\${smal}</div></div>
              </div>
              <div style="padding:1rem;border-top:1px solid var(--border);max-height:300px;overflow-y:auto;background:var(--bg)">
                \${sess.batches.map(b => \`
                  <div style="margin-bottom:1rem;border-bottom:1px dashed var(--border);padding-bottom:1rem">
                    <div style="display:flex;justify-content:space-between;margin-bottom:.5rem">
                      <span style="color:var(--blue);font-family:monospace;font-size:.8rem">\${b.timestamp}</span>
                      <span style="font-size:.8rem;color:var(--muted)">\${b.packet_count} pkts</span>
                    </div>
                    <div style="font-size:.85rem;color:var(--muted);line-height:1.4">\${b.summary||b.error||'No summary'}</div>
                  </div>
                \`).join('')}
              </div>
            </div>
          \`;
        });
        main.innerHTML = html;
      } catch(e) { main.innerHTML = \`<div style="color:var(--red);padding:2rem">Error: \${e}</div>\`; }
    }

    /* ── Boot ──────────────────────────────────────────────────── */
    window.onload = () => {
      initCharts();
      loadIfaces();
      fetchStats();
      setInterval(fetchStats, 5000);
      refreshLlmList();
      
      const es = new EventSource('/stream');
      const sts = document.getElementById('sseStatus');
      es.onopen = () => { sts.textContent = '🟢 live'; sts.style.color = 'var(--green)'; };
      es.onerror = () => { sts.textContent = '🔴 disconnected'; sts.style.color = 'var(--red)'; };
      es.onmessage = e => {
        try {
          const logData = JSON.parse(e.data);
          logTerm(logData.message, logData.level);
        } catch(err){}
      };
    };
  </script>
</body>
</html>
"""

# ========================= LOGIN HTML =========================
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SharkEye – Secure Access</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;
  --border:#30363d;--text:#e6edf3;--muted:#8b949e;
  --green:#3fb950;--red:#f85149;--blue:#58a6ff;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Inter',sans-serif}
body{
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;
  background: radial-gradient(ellipse at 50% 0%, rgba(88,166,255,.08) 0%, transparent 70%),
              var(--bg);
}

/* CARD */
.card{
  width:100%;max-width:400px;padding:0 1.25rem;
}
.logo{
  text-align:center;margin-bottom:2rem;
}
.logo-icon{font-size:2.8rem;display:block;margin-bottom:.5rem}
.logo-title{
  font-size:1.3rem;font-weight:700;letter-spacing:-.01em;
}
.logo-sub{font-size:.75rem;color:var(--muted);margin-top:.2rem}

.form-box{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:2rem;
  box-shadow:0 8px 40px rgba(0,0,0,.55);
}
.form-group{margin-bottom:1.1rem}
label{
  display:block;font-size:.72rem;font-weight:600;
  color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em;margin-bottom:.45rem;
}
input[type=text],input[type=password]{
  width:100%;padding:.6rem .85rem;
  background:var(--surface2);border:1px solid var(--border);
  border-radius:7px;color:var(--text);
  font-family:'JetBrains Mono',monospace;font-size:.85rem;
  outline:none;transition:.2s;
}
input:focus{
  border-color:rgba(88,166,255,.6);
  box-shadow:0 0 0 3px rgba(88,166,255,.12);
}
.btn-login{
  width:100%;padding:.7rem;border:none;border-radius:7px;
  background:linear-gradient(135deg,#1f6feb,#388bfd);
  color:#fff;font-size:.88rem;font-weight:600;
  cursor:pointer;transition:.2s;letter-spacing:.01em;
  margin-top:.35rem;
}
.btn-login:hover{filter:brightness(1.12);transform:translateY(-1px)}
.btn-login:active{transform:none;filter:none}

.error-msg{
  background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.35);
  border-radius:6px;padding:.55rem .85rem;
  font-size:.78rem;color:var(--red);margin-bottom:.9rem;
  display:flex;align-items:center;gap:.45rem;
}

.footer{
  text-align:center;margin-top:1.3rem;
  font-size:.68rem;color:var(--muted);opacity:.55;
}

/* Eye toggle */
.pw-wrap{position:relative}
.pw-toggle{
  position:absolute;right:.7rem;top:50%;transform:translateY(-50%);
  background:none;border:none;cursor:pointer;
  color:var(--muted);font-size:.9rem;line-height:1;
  padding:.2rem;
}
.pw-toggle:hover{color:var(--text)}

/* Scan line animation on load */
@keyframes scan{
  0%{transform:translateY(-100%)}
  100%{transform:translateY(100vh)}
}
.scanline{
  position:fixed;inset:0;pointer-events:none;z-index:1000;
  overflow:hidden;
}
.scanline::after{
  content:'';
  position:absolute;left:0;right:0;height:2px;
  background:linear-gradient(to right,transparent,rgba(88,166,255,.3),transparent);
  animation:scan 1.8s ease-out forwards;
}
</style>
</head>
<body>
<div class="scanline"></div>
<div class="card">
  <div class="logo">
    <span class="logo-icon">🛡️</span>
    <div class="logo-title">SharkEye</div>
    <div class="logo-sub">Network Intrusion Detection System</div>
  </div>

  <div class="form-box">
    {% if error %}
    <div class="error-msg">⚠ {{ error }}</div>
    {% endif %}

    <form method="POST" action="/login" autocomplete="off">
      <div class="form-group">
        <label for="uid">User ID</label>
        <input type="text" id="uid" name="username"
               placeholder="Enter user ID"
               value="{{ username }}" required autofocus>
      </div>
      <div class="form-group">
        <label for="pwd">Password</label>
        <div class="pw-wrap">
          <input type="password" id="pwd" name="password"
                 placeholder="••••••••" required>
          <button type="button" class="pw-toggle" onclick="
            const i=document.getElementById('pwd');
            i.type=i.type==='password'?'text':'password';
            this.textContent=i.type==='password'?'👁':'🚫';
          ">👁</button>
        </div>
      </div>
      <button type="submit" class="btn-login">▶&nbsp; Authenticate</button>
    </form>
  </div>

  <div class="footer">Raspberry Pi 5 &bull; Secure Access &bull; All activity is logged</div>
</div>
</body>
</html>
"""

# ========================= UNLOCK HTML =========================
UNLOCK_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SharkEye – Product Unlock</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;
  --border:#30363d;--text:#e6edf3;--muted:#8b949e;
  --green:#3fb950;--red:#f85149;--blue:#58a6ff;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Inter',sans-serif}
body{
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;
  background: radial-gradient(ellipse at 50% 0%, rgba(88,166,255,.08) 0%, transparent 70%),
              var(--bg);
}
.card{ width:100%;max-width:400px;padding:0 1.25rem; }
.logo{ text-align:center;margin-bottom:2rem; }
.logo-icon{font-size:2.8rem;display:block;margin-bottom:.5rem}
.logo-title{ font-size:1.3rem;font-weight:700;letter-spacing:-.01em; }
.logo-sub{font-size:.75rem;color:var(--muted);margin-top:.2rem}
.form-box{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:2rem;
  box-shadow:0 8px 40px rgba(0,0,0,.55);
}
.form-group{margin-bottom:1.1rem}
label{
  display:block;font-size:.72rem;font-weight:600;
  color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em;margin-bottom:.45rem;
}
input[type=text]{
  width:100%;padding:.6rem .85rem;
  background:var(--surface2);border:1px solid var(--border);
  border-radius:7px;color:var(--text);
  font-family:'JetBrains Mono',monospace;font-size:.85rem;
  outline:none;transition:.2s;text-align:center;letter-spacing:1px;
}
input:focus{
  border-color:rgba(88,166,255,.6);
  box-shadow:0 0 0 3px rgba(88,166,255,.12);
}
.btn-login{
  width:100%;padding:.7rem;border:none;border-radius:7px;
  background:linear-gradient(135deg,#1f6feb,#388bfd);
  color:#fff;font-size:.88rem;font-weight:600;
  cursor:pointer;transition:.2s;letter-spacing:.01em;
  margin-top:.35rem;
}
.btn-login:hover{filter:brightness(1.12);transform:translateY(-1px)}
.btn-login:active{transform:none;filter:none}
.error-msg{
  background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.35);
  border-radius:6px;padding:.55rem .85rem;
  font-size:.78rem;color:var(--red);margin-bottom:.9rem;
  display:flex;align-items:center;gap:.45rem;
}
.footer{
  text-align:center;margin-top:1.3rem;
  font-size:.68rem;color:var(--muted);opacity:.55;
}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-icon">🔐</span>
    <div class="logo-title">Activate SharkEye</div>
    <div class="logo-sub">First-Time Setup Verification</div>
  </div>

  <div class="form-box">
    {% if error %}
    <div class="error-msg">⚠ {{ error }}</div>
    {% endif %}

    <form method="POST" action="/unlock" autocomplete="off">
      <div class="form-group">
        <label for="pkey">Product Key</label>
        <input type="text" id="pkey" name="product_key"
               placeholder="XXXX-XXXX-XXXX-XXXX" required autofocus>
      </div>
      <button type="submit" class="btn-login">Unlock Dashboard</button>
    </form>
  </div>

  <div class="footer">Enter the SHA-256 Product Key generated by initials.py</div>
</div>
</body>
</html>
"""

# ========================= BACKEND =========================

def check_root():
    if os.geteuid() != 0:
        print("ERROR: Run as root:  sudo python3 app.py")
        sys.exit(1)

def default_stats():
    return {"packet_count": 0,
            "protocol_distribution": {"tcp": 0, "udp": 0, "other": 0},
            "unique_src_ips": 0, "top_src_ips": {}}

# ── Ollama serve ───────────────────────────────────────────────────

def _wait_ollama(max_wait=30):
    global _ollama_ok
    for _ in range(max_wait):
        try:
            r = subprocess.run(["ollama", "list"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=3)
            if r.returncode == 0:
                _ollama_ok = True
                log("Ollama is responsive.", "ok")
                return
        except Exception:
            pass
        time.sleep(1)
    log("Ollama did not respond in time.", "warn")

def start_ollama_serve():
    log("Starting ollama serve…")
    try:
        proc = subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        threading.Thread(target=_pipe_to_log, args=(proc.stdout, "ollama", "info"), daemon=True).start()
        threading.Thread(target=_pipe_to_log, args=(proc.stderr, "ollama", "warn"), daemon=True).start()
        time.sleep(2)
        if proc.poll() is not None:
            log("ollama serve exited immediately — likely already running.", "warn")
        else:
            log(f"ollama serve started (pid={proc.pid})", "ok")
        _wait_ollama(30)
    except FileNotFoundError:
        log("'ollama' not found. Install from https://ollama.com", "error")
    except Exception as e:
        log(f"Error starting ollama: {e}", "error")

# ── Interface discovery ────────────────────────────────────────────

def get_interfaces():
    """Return list of interface dicts with name/state/ip/mac/has_internet."""
    result = []
    try:
        raw = subprocess.check_output(["ip", "-br", "addr"], stderr=subprocess.DEVNULL).decode()
    except Exception:
        return result

    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        name  = parts[0]
        state = (parts[1] if len(parts) > 1 else "UNKNOWN").upper()
        if name == "lo":
            continue

        # First IPv4
        ip = ""
        for tok in parts[2:]:
            if "." in tok and ":" not in tok:
                ip = tok.split("/")[0]
                break

        # MAC
        mac = ""
        try:
            m = subprocess.check_output(["cat", f"/sys/class/net/{name}/address"],
                                        stderr=subprocess.DEVNULL).decode().strip()
            if m and m != "00:00:00:00:00:00":
                mac = m
        except Exception:
            pass

        result.append({"name": name, "state": state, "ip": ip, "mac": mac, "has_internet": False})

    # Connectivity check (parallel to keep it fast)
    def check_inet(ifc):
        if ifc["state"] not in ("UP", "UNKNOWN") or not ifc["ip"]:
            return
        try:
            ret = subprocess.call(
                ["ping", "-I", ifc["name"], "-c", "1", "-W", "2", "8.8.8.8"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            ifc["has_internet"] = (ret == 0)
        except Exception:
            pass

    threads = [threading.Thread(target=check_inet, args=(i,), daemon=True) for i in result]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)

    return result

# ── Packet parsing ─────────────────────────────────────────────────

def parse_ek_output(raw: str):
    """Parse tshark -T ek NDJSON. Packet lines have a 'layers' key."""
    packets = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] != '{':
            continue
        try:
            obj = json.loads(line)
            if "layers" in obj:
                packets.append(obj)
        except json.JSONDecodeError:
            continue
    return packets

def _f(layers, key, default=""):
    """Get field from EK layers dict (value may be str or list)."""
    v = layers.get(key, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v if v is not None else default

def compute_stats(packets):
    if not packets:
        return default_stats()
    proto = {"tcp": 0, "udp": 0, "other": 0}
    src   = collections.Counter()
    for p in packets:
        try:
            l = p.get("layers", {})
            pr = _f(l, "frame_protocols", "").lower()
            if   "tcp" in pr: proto["tcp"] += 1
            elif "udp" in pr: proto["udp"] += 1
            else:              proto["other"] += 1
            ip = _f(l, "ip_src", "")
            if ip: src[ip] += 1
        except Exception:
            proto["other"] += 1
    return {"packet_count": len(packets),
            "protocol_distribution": proto,
            "unique_src_ips": len(src),
            "top_src_ips": dict(src.most_common(10))}

def dedup(packets):
    seen, out = set(), []
    for p in packets:
        try:
            l = p.get("layers", {})
            h = hashlib.md5(f"{_f(l,'ip_src')}|{_f(l,'ip_dst')}|{_f(l,'frame_len')}".encode()).hexdigest()
            if h not in seen:
                seen.add(h); out.append(p)
        except Exception:
            out.append(p)
    return out

def make_prompt(packets):
    lines = []
    for i, p in enumerate(packets[:MAX_PACKETS_LLM]):
        try:
            l = p.get("layers", {})
            lines.append(f"P{i+1}: {_f(l,'ip_src','?')} -> {_f(l,'ip_dst','?')} "
                         f"len={_f(l,'frame_len','?')} proto={_f(l,'frame_protocols','?')}")
        except Exception:
            pass
    return ("Analyze this network traffic from a Raspberry Pi 5. "
            "Reply ONLY with valid JSON (no markdown). "
            "Keys: total_packets_analyzed(int), anomalies_detected(int), "
            "malicious_activities(list[str]), summary(str), recommendations(list[str]).\n\n"
            + "\n".join(lines))

def strip_fences(text):
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s*```$', '', text)
    return text.strip()

def analyze(prompt):
    if not OLLAMA_AVAILABLE:
        return {"error": "Ollama Python library not installed (pip install ollama)"}
    if not MODEL_NAME:
        return {"error": "No active LLM found. Please open the LLM Manager to select or install a model."}
    content = ""
    try:
        resp    = ollama_chat(model=MODEL_NAME,
                              messages=[{"role": "user", "content": prompt}],
                              format="json")
        content = strip_fences(resp.message.content)
        return json.loads(content)
    except json.JSONDecodeError as e:
        return {"error": f"LLM returned invalid JSON: {e}", "raw": content[:300]}
    except Exception as e:
        return {"error": str(e)}

# ── Capture loop ───────────────────────────────────────────────────

def capture_and_analyze():
    global latest_report, history, incident_log, is_capturing, _tshark_ok, _session_start, _session_end
    batch = 0
    _session_start = datetime.now()
    _session_end   = None

    log(f"Capture loop started on interface '{INTERFACE}'", "ok")

    while is_capturing:
        batch += 1
        raw_file = f"/tmp/sharkeye_{os.getpid()}_{batch}.ek"
        log(f"Batch {batch}: capturing {SUB_CAPTURE_DURATION}s on '{INTERFACE}'…")

        cmd = [
            "tshark", "-i", INTERFACE,
            "-T", "ek",
            "-e", "frame.time_epoch", "-e", "frame.len", "-e", "frame.protocols",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport",
            "-a", f"duration:{SUB_CAPTURE_DURATION}"
        ]
        log("CMD: " + " ".join(cmd))

        try:
            fout = open(raw_file, "w")
            proc = subprocess.Popen(cmd, stdout=fout, stderr=subprocess.PIPE)

            # Stream tshark stderr to log panel live
            stderr_thread = threading.Thread(
                target=_pipe_to_log, args=(proc.stderr, "tshark", "warn"), daemon=True
            )
            stderr_thread.start()

            # Wait with safety timeout
            try:
                proc.wait(timeout=SUB_CAPTURE_DURATION + 20)
            except subprocess.TimeoutExpired:
                log("tshark timed out — killing.", "warn")
                proc.kill()
                proc.wait()

            fout.close()
            rc = proc.returncode
            _tshark_ok = (rc == 0)

            if rc != 0:
                log(f"tshark exited with code {rc}.", "error")
                stats_    = default_stats()
                analysis_ = {"error": f"tshark exit code {rc}"}

            elif not os.path.exists(raw_file) or os.path.getsize(raw_file) == 0:
                log("Capture file empty — no packets on this interface.", "warn")
                stats_    = default_stats()
                analysis_ = {"error": "No packets captured. Wrong interface?"}

            else:
                with open(raw_file, "r", errors="replace") as fh:
                    raw_text = fh.read()

                packets = parse_ek_output(raw_text)
                log(f"Parsed {len(packets)} packets.")

                if not packets:
                    stats_    = default_stats()
                    analysis_ = {"error": "0 valid packet lines in EK output."}
                else:
                    stats_    = compute_stats(packets)
                    deduped   = dedup(packets)
                    log(f"Stats: {stats_['packet_count']} pkts, "
                        f"{stats_['unique_src_ips']} unique IPs. "
                        f"Sending {len(deduped)} to LLM…")
                    analysis_ = analyze(make_prompt(deduped))
                    if "error" in analysis_:
                        log(f"LLM error: {analysis_['error']}", "warn")
                    else:
                        log(f"Analysis done. Anomalies: {analysis_.get('anomalies_detected',0)}", "ok")

            now_dt = datetime.now()
            _session_end = now_dt
            report = {
                "timestamp": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "analysis":  analysis_,
                **stats_
            }
            with state_lock:
                latest_report = report
                history.append({
                    "timestamp":    report["timestamp"][-8:],
                    "packet_count": stats_["packet_count"]
                })
                if len(history) > HISTORY_LENGTH:
                    history = history[-HISTORY_LENGTH:]
                
                # Append to incident log if malicious
                malicious = analysis_.get("malicious_activities", [])
                if malicious:
                    incident_log.append({
                        "timestamp": report["timestamp"],
                        "issues": malicious,
                        "implementations": analysis_.get("recommendations", [])
                    })

            # ── Persist to disk ──
            save_batch_to_history(report, batch)

            log(f"Batch {batch} complete. "
                f"Pkts={stats_['packet_count']}, IPs={stats_['unique_src_ips']}", "ok")

        except Exception as e:
            log(f"Unexpected error in batch {batch}: {e}", "error")

        finally:
            try:
                if 'fout' in dir() and not fout.closed:
                    fout.close()
                if os.path.exists(raw_file):
                    os.remove(raw_file)
            except Exception:
                pass

    # Mark session end time when loop exits
    _session_end = datetime.now()
    _update_session_end_on_disk()
    log("Capture loop ended.", "ok")

# ========================= HISTORY PERSISTENCE =========================

os.makedirs(HISTORY_DIR, exist_ok=True)


def _day_file(date_str: str) -> str:
    """Return the JSON file path for a given date (YYYY-MM-DD)."""
    return os.path.join(HISTORY_DIR, f"sharkeye_{date_str}.json")


def _load_day(date_str: str) -> dict:
    """Load (or create) the day's JSON record."""
    path = _day_file(date_str)
    if os.path.exists(path):
        try:
            with open(path, "r") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {"date": date_str, "sessions": {}}


def _save_day(date_str: str, day_data: dict):
    """Atomically write the day's JSON record."""
    path = _day_file(date_str)
    tmp  = path + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(day_data, fh, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        log(f"History write error: {e}", "warn")


def save_batch_to_history(report: dict, batch_num: int):
    """
    Append one batch record to today's history file.
    Structure:
      day_file.json
        sessions:
          SESSION_ID:
            session_id, interface, session_start, session_end, duration_s, batches: []
    """
    date_str = report["timestamp"][:10]          # "YYYY-MM-DD"
    day      = _load_day(date_str)

    # Ensure this session exists in the day record
    if SESSION_ID not in day["sessions"]:
        day["sessions"][SESSION_ID] = {
            "session_id":    SESSION_ID,
            "interface":     INTERFACE,
            "session_start": _session_start.strftime("%Y-%m-%d %H:%M:%S") if _session_start else "",
            "session_end":   "",
            "duration_s":    0,
            "batches":       []
        }

    sess = day["sessions"][SESSION_ID]

    # Update end time and duration every batch
    now = datetime.now()
    sess["session_end"] = now.strftime("%Y-%m-%d %H:%M:%S")
    if _session_start:
        sess["duration_s"] = int((now - _session_start).total_seconds())

    # Slim down analysis for storage (don't store raw LLM junk)
    an = report.get("analysis", {})
    batch_record = {
        "batch_num":       batch_num,
        "timestamp":       report["timestamp"],
        "interface":       INTERFACE,
        "packet_count":    report.get("packet_count", 0),
        "unique_src_ips":  report.get("unique_src_ips", 0),
        "protocol_dist":   report.get("protocol_distribution", {}),
        "top_src_ips":     report.get("top_src_ips", {}),
        "anomalies":       an.get("anomalies_detected", 0),
        "malicious":       an.get("malicious_activities", []),
        "summary":         an.get("summary", ""),
        "recommendations": an.get("recommendations", []),
        "error":           an.get("error", "")
    }
    sess["batches"].append(batch_record)
    _save_day(date_str, day)


def _update_session_end_on_disk():
    """Write the final session_end + duration when capture stops."""
    if not _session_start:
        return
    date_str = _session_start.strftime("%Y-%m-%d")
    day      = _load_day(date_str)
    if SESSION_ID in day["sessions"]:
        now = _session_end or datetime.now()
        day["sessions"][SESSION_ID]["session_end"] = now.strftime("%Y-%m-%d %H:%M:%S")
        day["sessions"][SESSION_ID]["duration_s"]  = int((now - _session_start).total_seconds())
        _save_day(date_str, day)


# ========================= FLASK ROUTES =========================

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("logged_in"):
        return redirect("/")
    error    = ""
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_login(username, password):
            session["logged_in"] = True
            session["user"]      = username
            log(f"Login: user '{username}' authenticated.", "ok")
            return redirect("/")
        else:
            log(f"Login FAILED for user '{username}'.", "warn")
            error = "Invalid user ID or password."
    return render_template_string(LOGIN_HTML, error=error, username=username)

@app.route("/unlock", methods=["GET", "POST"])
@login_required
def unlock_page():
    cfg = load_setup_config()
    if cfg.get("unlocked", False):
        return redirect("/")
        
    error = ""
    if request.method == "POST":
        key = request.form.get("product_key", "").strip()
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        if key_hash == cfg.get("product_key_hash", ""):
            cfg["unlocked"] = True
            save_setup_config(cfg)
            log("App unlocked successfully via Product Key.", "ok")
            return redirect("/")
        else:
            log("Invalid Product Key attempt.", "warn")
            error = "Invalid Product Key. Please check your initials.py output."
            
    return render_template_string(UNLOCK_HTML, error=error)


@app.route("/logout")
def logout():
    user = session.get("user", "?")
    session.clear()
    log(f"User '{user}' logged out.", "info")
    return redirect("/login")


@app.route("/")
@login_required
def index():
    return render_template_string(HTML)

@app.route("/api/llm/list")
@login_required
def llm_list():
    if not OLLAMA_AVAILABLE:
        return jsonify({"error": "Ollama library not installed."})
    try:
        models_resp = ollama.list()
        models_list = []
        if hasattr(models_resp, 'models'):
            for m in models_resp.models:
                name = getattr(m, 'model', getattr(m, 'name', ''))
                size = getattr(m, 'size', 0)
                models_list.append({"name": name, "size": size})
        else:
            models_list = models_resp.get('models', [])
        return jsonify({"models": models_list})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/api/llm/delete", methods=["POST"])
@login_required
def llm_delete():
    if not OLLAMA_AVAILABLE:
        return jsonify({"error": "Ollama library not installed."})
    model_name = request.json.get("model")
    try:
        ollama.delete(model_name)
        log(f"Deleted LLM model: {model_name}", "ok")
        return jsonify({"status": "ok"})
    except Exception as e:
        log(f"Failed to delete model {model_name}: {e}", "error")
        return jsonify({"error": str(e)})

@app.route("/api/llm/select", methods=["POST"])
@login_required
def llm_select():
    model_name = request.json.get("model")
    cfg = load_setup_config()
    cfg["model_name"] = model_name
    save_setup_config(cfg)
    global MODEL_NAME
    MODEL_NAME = model_name
    log(f"Active LLM model set to: {model_name}", "ok")
    return jsonify({"status": "ok"})

@app.route("/api/llm/pull")
@login_required
def llm_pull():
    model_name = request.args.get("model")
    if not model_name:
        return "Missing model name", 400

    def generate():
        try:
            for progress in ollama.pull(model_name, stream=True):
                # Convert ProgressResponse to dict safely
                if hasattr(progress, "model_dump"):
                    p_data = progress.model_dump()
                elif hasattr(progress, "dict"):
                    p_data = progress.dict()
                elif isinstance(progress, dict):
                    p_data = progress
                else:
                    p_data = {k: v for k, v in vars(progress).items() if not k.startswith('_')}
                yield f"data: {json.dumps(p_data)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            
    return Response(generate(), mimetype="text/event-stream")

@app.route("/api/llm/install_ollama", methods=["POST"])
@login_required
def api_install_ollama():
    platform = sys.platform
    try:
        if platform == "linux" or platform == "linux2":
            # Start background install
            subprocess.Popen("curl -fsSL https://ollama.com/install.sh | sh", shell=True)
            return jsonify({"status": "started", "msg": "Linux installation started in the background. Please wait a few minutes and refresh."})
        elif platform == "win32":
            # Start background install
            subprocess.Popen('powershell -Command "iex \\"& {Invoke-WebRequest -Uri https://ollama.com/install.ps1 -UseBasicParsing} | Invoke-Expression\\""', shell=True)
            return jsonify({"status": "started", "msg": "Windows installation started in the background. Please wait a few minutes and refresh."})
        elif platform == "darwin":
            return jsonify({"status": "manual", "msg": "macOS requires manual installation via the official app: https://ollama.com/download/mac"})
        else:
            return jsonify({"status": "error", "msg": f"Unsupported OS: {platform}"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route("/api/interfaces")
@login_required
def api_interfaces():
    ifaces = get_interfaces()
    return jsonify({"interfaces": ifaces})

@app.route("/stats")
@login_required
def stats_route():
    with state_lock:
        rep  = latest_report.copy() if latest_report else {}
        hist = list(history)
        incidents = list(incident_log)

    an = rep.get("analysis", {})
    anomalies = an.get("anomalies_detected", 0)
    try:   anomalies = int(anomalies)
    except: anomalies = 0

    return jsonify({
        "capturing":            is_capturing,
        "ollama_ok":            _ollama_ok,
        "tshark_ok":            _tshark_ok,
        "total_packets":        rep.get("packet_count", 0),
        "unique_src_ips":       rep.get("unique_src_ips", 0),
        "anomalies_detected":   anomalies,
        "malicious_activities": an.get("malicious_activities", []),
        "analysis":             an,
        "proto":                rep.get("protocol_distribution", {"tcp":0,"udp":0,"other":0}),
        "top_src_ips":          rep.get("top_src_ips", {}),
        "history":              hist,
        "incident_log":         incidents
    })

@app.route("/start", methods=["POST"])
@login_required
def start_route():
    global is_capturing, capture_thread, INTERFACE

    body = request.get_json(silent=True) or {}
    iface = body.get("interface", "").strip()

    if not iface:
        return jsonify({"status": "error", "message": "No interface specified"}), 400

    with _start_lock:
        if is_capturing:
            return jsonify({"status": "already_running"})

        INTERFACE      = iface
        is_capturing   = True
        capture_thread = threading.Thread(target=capture_and_analyze, daemon=True)
        capture_thread.start()
        log(f"Capture started on '{INTERFACE}'.", "ok")
        return jsonify({"status": "started", "interface": INTERFACE})

@app.route("/stop", methods=["POST"])
@login_required
def stop_route():
    global is_capturing
    is_capturing = False
    # Persist the final session end timestamp
    threading.Thread(target=_update_session_end_on_disk, daemon=True).start()
    log("Capture stopped.")
    return jsonify({"status": "stopped"})


@app.route("/api/history")
@login_required
def api_history_list():
    """Return summary list of all available history dates."""
    dates = []
    if os.path.isdir(HISTORY_DIR):
        for fname in sorted(os.listdir(HISTORY_DIR), reverse=True):
            if not fname.startswith("sharkeye_") or not fname.endswith(".json"):
                continue
            date_str = fname[len("sharkeye_"):-len(".json")]
            try:
                with open(os.path.join(HISTORY_DIR, fname)) as fh:
                    day = json.load(fh)
                sessions   = list(day.get("sessions", {}).values())
                total_pkts = sum(b.get("packet_count", 0) for s in sessions for b in s.get("batches", []))
                total_mal  = sum(len(b.get("malicious", [])) for s in sessions for b in s.get("batches", []))
                total_anom = sum(b.get("anomalies", 0) for s in sessions for b in s.get("batches", []))
                dates.append({
                    "date":          date_str,
                    "session_count": len(sessions),
                    "batch_count":   sum(len(s["batches"]) for s in sessions),
                    "total_packets": total_pkts,
                    "total_anomalies": total_anom,
                    "total_malicious": total_mal,
                })
            except Exception:
                continue
    return jsonify({"dates": dates})


@app.route("/api/history/<date_str>")
@login_required
def api_history_day(date_str):
    """Return full data for a specific date (YYYY-MM-DD)."""
    # Validate format
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    path = _day_file(date_str)
    if not os.path.exists(path):
        return jsonify({"date": date_str, "sessions": {}})
    try:
        with open(path) as fh:
            return jsonify(json.load(fh))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logs/stream")
@login_required
def logs_stream():
    def event_stream():
        # Replay existing history for new client
        try:
            with _log_lock:
                snapshot = list(_log_lines)
            for line in snapshot:
                yield f"data: {line}\n\n"
        except Exception as e:
            yield f"data: [SSE] History replay error: {e}\n\n"

        q = queue.Queue(maxsize=500)
        with _sse_q_lock:
            _sse_queues.append(q)
        try:
            while True:
                try:
                    line = q.get(timeout=15)
                    # Escape newlines inside log lines so SSE framing is never broken
                    safe = line.replace("\n", " ").replace("\r", "")
                    yield f"data: {safe}\n\n"
                except queue.Empty:
                    # SSE comment heartbeat — keeps the TCP connection alive.
                    # A line starting with ': ' is an SSE comment; browsers ignore it
                    # and it will NOT trigger onmessage, so no client-side filtering needed.
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        except Exception as e:
            # Log but don't let uncaught errors crash the generator silently
            try:
                yield f"data: [SSE] Stream error: {e}\n\n"
            except Exception:
                pass
        finally:
            with _sse_q_lock:
                try: _sse_queues.remove(q)
                except ValueError: pass

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
            "Transfer-Encoding": "chunked",
        }
    )

# ========================= MAIN =========================
if __name__ == "__main__":
    print("\033[96m" + "=" * 55 + "\033[0m")
    print("\033[1m  SharkEye \u2013 Network Intrusion Detection System\033[0m")
    print("\033[90m  Raspberry Pi 5  |  Real-Time Packet Analysis\033[0m")
    print("\033[96m" + "=" * 55 + "\033[0m\n")

    check_root()

    # ── Dependency check ─────────────────────────────────────
    DEPS_OK = True
    def chk(pkg, import_name=None, install_cmd=None):
        global DEPS_OK
        try:
            __import__(import_name or pkg)
            print(f"\033[92m  [✓] {pkg}\033[0m", flush=True)
        except ImportError:
            print(f"\033[91m  [!] {pkg} NOT FOUND  →  {install_cmd or ('pip install ' + pkg)}\033[0m", flush=True)
            DEPS_OK = False

    print("\033[1m  Dependency check:\033[0m")
    chk("flask",  "flask")
    chk("bcrypt", "bcrypt", "pip install bcrypt")
    chk("ollama", "ollama", "pip install ollama  (optional – LLM analysis)")

    if not DEPS_OK:
        print("\n\033[91m  Required dependencies missing. Install them and retry.\033[0m\n")
        sys.exit(1)

    print()

    # ── Auth init ──────────────────────────────────────────
    init_credentials()      # create/load bcrypt creds in secret dir

    # ── tshark check ──────────────────────────────────────
    if subprocess.call(["which", "tshark"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print("\033[91mERROR: tshark not found.  sudo apt install tshark\033[0m")
        sys.exit(1)

    _tshark_ok = True
    log("tshark found.", "ok")

    # ── Ollama serve ──────────────────────────────────────
    threading.Thread(target=start_ollama_serve, daemon=True).start()

    log(f"LLM model : {MODEL_NAME}", "info")
    log(f"Batch     : {SUB_CAPTURE_DURATION}s per cycle", "info")
    log(f"Auth store: {_get_secret_dir()}", "info")
    log("Dashboard : http://0.0.0.0:5000 — login required", "ok")
    print("\033[96m" + "=" * 55 + "\033[0m\n")

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
