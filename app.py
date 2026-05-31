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
    seed = os.path.abspath(__file__) + tag + "SharkEye_salt_2025"
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
    script_hash = hashlib.sha256(os.path.abspath(__file__).encode()).hexdigest()
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
    if "model_name" in cfg:
        MODEL_NAME = cfg["model_name"]
    else:
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SharkEye – NIDS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;
  --border:#30363d;--text:#e6edf3;--muted:#8b949e;
  --green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--purple:#a371f7;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh}

/* NAV */
.nav{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:.7rem 1.4rem;display:flex;align-items:center;
  justify-content:space-between;position:sticky;top:0;z-index:200;
}
.brand{display:flex;align-items:center;gap:.5rem;font-weight:700;font-size:1rem}
.brand-icon{font-size:1.3rem}
.nav-right{display:flex;align-items:center;gap:.75rem}
.pill{
  display:inline-flex;align-items:center;gap:.3rem;
  padding:.2rem .7rem;border-radius:999px;font-size:.73rem;
  font-weight:600;border:1px solid var(--border);
  background:var(--surface2);color:var(--muted);transition:.25s;
}
.pill.live{border-color:rgba(248,81,73,.5);color:var(--red);background:rgba(248,81,73,.08)}
.pill .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.live .dot{animation:blink 1s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.15}}

/* MAIN */
.wrap{padding:1.2rem 1.4rem;max-width:1400px;margin:0 auto}

/* INTERFACE PICKER CARD */
.iface-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:1.1rem 1.2rem;margin-bottom:1.1rem;
}
.iface-card h2{font-size:.82rem;color:var(--muted);text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:.8rem}
.iface-table-wrap{overflow-x:auto}
table.iface-table{width:100%;border-collapse:collapse;font-size:.82rem}
.iface-table th{
  text-align:left;padding:.35rem .7rem;
  color:var(--muted);font-size:.7rem;text-transform:uppercase;
  letter-spacing:.05em;border-bottom:1px solid var(--border);font-weight:600;
}
.iface-table td{padding:.4rem .7rem;border-bottom:1px solid var(--surface2)}
.iface-table tbody tr{cursor:pointer;transition:.15s}
.iface-table tbody tr:hover{background:var(--surface2)}
.iface-table tbody tr.selected{background:rgba(88,166,255,.1);
  outline:1px solid rgba(88,166,255,.35)}
.badge{
  display:inline-flex;align-items:center;gap:.25rem;
  padding:.15rem .55rem;border-radius:4px;font-size:.7rem;font-weight:600;
}
.badge.up   {background:rgba(63,185,80,.15); color:var(--green)}
.badge.down {background:rgba(248,81,73,.12); color:var(--red)}
.badge.unk  {background:rgba(210,153,34,.12);color:var(--yellow)}
.badge.inet {background:rgba(63,185,80,.15); color:var(--green)}
.badge.lan  {background:rgba(210,153,34,.12);color:var(--yellow)}
.badge.none {background:rgba(30,36,44,1);    color:var(--muted)}
.mono{font-family:'JetBrains Mono',monospace;font-size:.76rem}

/* CONTROLS */
.controls{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center;margin-bottom:1.1rem}
.btn{
  padding:.38rem .95rem;border-radius:6px;border:1px solid var(--border);
  background:transparent;color:var(--text);font-size:.8rem;font-weight:500;
  cursor:pointer;transition:.18s;display:inline-flex;align-items:center;gap:.3rem;
  font-family:'Inter',sans-serif;
}
.btn:hover{background:var(--surface2)}
.btn.green{border-color:rgba(63,185,80,.6);color:var(--green)}
.btn.green:hover{background:rgba(63,185,80,.1)}
.btn.red  {border-color:rgba(248,81,73,.6); color:var(--red)}
.btn.red:hover  {background:rgba(248,81,73,.1)}
.btn:disabled{opacity:.35;cursor:not-allowed}
.hint{font-size:.73rem;color:var(--muted)}

/* SERVICE BADGES */
.svc-row{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1.1rem}
.svc{
  display:inline-flex;align-items:center;gap:.3rem;
  padding:.22rem .65rem;border-radius:5px;font-size:.72rem;font-weight:600;
  border:1px solid var(--border);background:var(--surface2);color:var(--muted);
}
.svc .sdot{width:5px;height:5px;border-radius:50%;background:var(--muted)}
.svc.ok {border-color:rgba(63,185,80,.4); color:var(--green)}
.svc.ok .sdot {background:var(--green)}
.svc.err{border-color:rgba(248,81,73,.4); color:var(--red)}
.svc.err .sdot{background:var(--red)}
.svc.busy{border-color:rgba(210,153,34,.4);color:var(--yellow)}
.svc.busy .sdot{background:var(--yellow);animation:blink 1s infinite}

/* ALERT STRIP */
.alert-strip{
  background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);
  border-radius:6px;padding:.45rem .85rem;font-size:.78rem;color:var(--red);
  margin-bottom:1rem;display:none;
}
.alert-strip.show{display:block}

/* STAT CARDS */
.stat-grid{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));
  gap:.9rem;margin-bottom:1.1rem;
}
.stat{
  background:var(--surface);border:1px solid var(--border);
  border-radius:9px;padding:.9rem 1.1rem;transition:.2s;
}
.stat:hover{border-color:rgba(88,166,255,.3)}
.stat-label{font-size:.68rem;color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em;margin-bottom:.35rem}
.stat-val{font-size:1.8rem;font-weight:700;line-height:1}
.stat.p{border-left:3px solid var(--purple)}
.stat.b{border-left:3px solid var(--blue)}
.stat.y{border-left:3px solid var(--yellow)}
.stat.r{border-left:3px solid var(--red)}
.stat.g{border-left:3px solid var(--green)}

/* CHARTS */
.chart-row{display:grid;grid-template-columns:2fr 1fr;gap:.9rem;margin-bottom:1.1rem}
@media(max-width:700px){.chart-row{grid-template-columns:1fr}}

/* PANELS */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:9px;overflow:hidden}
.panel-hdr{
  padding:.6rem 1rem;border-bottom:1px solid var(--border);
  font-size:.72rem;font-weight:600;color:var(--muted);
  text-transform:uppercase;letter-spacing:.07em;
  display:flex;align-items:center;justify-content:space-between;
}
.panel-body{padding:.9rem}
.chart-wrap{position:relative;height:195px}

/* BOTTOM ROW */
.bottom-row{display:grid;grid-template-columns:1fr 1fr;gap:.9rem;margin-bottom:1.1rem}
@media(max-width:700px){.bottom-row{grid-template-columns:1fr}}

/* LOG BOX */
.logbox{
  background:#0d1117;border:1px solid var(--border);border-radius:5px;
  padding:.7rem;font-family:'JetBrains Mono',monospace;font-size:.72rem;
  line-height:1.6;max-height:280px;overflow-y:auto;white-space:pre-wrap;
  word-break:break-all;color:var(--muted);
}
.logbox::-webkit-scrollbar{width:4px}
.logbox::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.lg-ok{color:var(--green)}.lg-err{color:var(--red)}.lg-warn{color:var(--yellow)}.lg-info{color:var(--muted)}

/* IP TABLE */
table.ip-t{width:100%;border-collapse:collapse;font-size:.8rem}
.ip-t th{color:var(--muted);padding:.35rem .55rem;border-bottom:1px solid var(--border);
  font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;text-align:left}
.ip-t td{padding:.35rem .55rem;border-bottom:1px solid var(--surface2);
  font-family:'JetBrains Mono',monospace;font-size:.74rem}
.ip-t tbody tr:hover{background:var(--surface2)}
.cnt{display:inline-block;background:var(--blue);color:#fff;
  border-radius:3px;padding:.03rem .3rem;font-size:.68rem;font-weight:600}

/* STAT CARDS – clickable */
.stat{cursor:pointer}
.stat:hover{border-color:rgba(88,166,255,.45);transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,0,0,.35)}
.stat-sub{font-size:.7rem;color:var(--muted);margin-top:.3rem}
.stat-click-hint{font-size:.62rem;color:var(--muted);opacity:.55;margin-top:.25rem;display:flex;align-items:center;gap:.2rem}

/* MODAL */
.modal-overlay{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);
  backdrop-filter:blur(4px);z-index:1000;align-items:center;justify-content:center;
}
.modal-overlay.open{display:flex}
.modal{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  width:min(700px,95vw);max-height:85vh;display:flex;flex-direction:column;
  box-shadow:0 20px 60px rgba(0,0,0,.6);overflow:hidden;
}
.modal-head{
  padding:.85rem 1.1rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}
.modal-title{font-weight:700;font-size:.95rem}
.modal-close{
  background:none;border:none;color:var(--muted);cursor:pointer;
  font-size:1.2rem;line-height:1;padding:.2rem .4rem;border-radius:4px;
  transition:.15s;
}
.modal-close:hover{background:var(--surface2);color:var(--text)}
.modal-tabs{
  display:flex;border-bottom:1px solid var(--border);background:var(--surface);
  overflow-x:auto;flex-shrink:0;
}
.mtab{
  padding:.55rem 1rem;font-size:.76rem;font-weight:600;
  color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;
  white-space:nowrap;transition:.18s;background:none;border-top:none;
  border-left:none;border-right:none;
}
.mtab.active{color:var(--blue);border-bottom-color:var(--blue)}
.mtab:hover:not(.active){color:var(--text)}
.modal-body{flex:1;overflow-y:auto;padding:1.1rem}
.modal-body::-webkit-scrollbar{width:5px}
.modal-body::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.tab-pane{display:none}
.tab-pane.active{display:block}
.detail-row{
  display:flex;align-items:baseline;justify-content:space-between;
  padding:.4rem 0;border-bottom:1px solid var(--surface2);font-size:.82rem;
}
.detail-row:last-child{border-bottom:none}
.detail-key{color:var(--muted);font-size:.75rem}
.detail-val{font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text)}
.mal-item{
  background:rgba(248,81,73,.07);border:1px solid rgba(248,81,73,.22);
  border-radius:6px;padding:.6rem .85rem;margin-bottom:.5rem;
  font-size:.81rem;line-height:1.55;
}
.mal-item:last-child{margin-bottom:0}
.mal-num{display:inline-block;background:var(--red);color:#fff;border-radius:3px;
  padding:.05rem .35rem;font-size:.68rem;font-weight:700;margin-right:.5rem}
.anom-item{
  background:rgba(210,153,34,.07);border:1px solid rgba(210,153,34,.22);
  border-radius:6px;padding:.55rem .85rem;margin-bottom:.5rem;font-size:.81rem;
}
.rec-item{
  display:flex;gap:.6rem;padding:.4rem 0;
  border-bottom:1px solid var(--surface2);font-size:.81rem;
}
.rec-num{color:var(--blue);font-weight:700;min-width:1.4rem}
.batch-row{
  display:grid;grid-template-columns:2.5rem 1fr 5rem 5rem;
  gap:.5rem;align-items:center;padding:.4rem .2rem;
  border-bottom:1px solid var(--surface2);font-size:.78rem;
}
.batch-bar-wrap{background:var(--surface2);border-radius:2px;height:6px;overflow:hidden}
.batch-bar{background:var(--blue);height:100%;border-radius:2px;transition:width .4s}
.empty-state{
  text-align:center;color:var(--muted);padding:2.5rem 1rem;
  font-size:.82rem;
}

/* HISTORY MODAL */
.hist-layout{display:grid;grid-template-columns:200px 1fr;gap:0;height:100%;min-height:400px}
.hist-sidebar{
  border-right:1px solid var(--border);overflow-y:auto;padding:.5rem 0;
}
.hist-sidebar::-webkit-scrollbar{width:4px}
.hist-sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.hist-date-btn{
  width:100%;text-align:left;padding:.5rem .85rem;
  border:none;background:none;color:var(--muted);
  font-size:.78rem;cursor:pointer;transition:.15s;
  border-left:2px solid transparent;
}
.hist-date-btn:hover{background:var(--surface2);color:var(--text)}
.hist-date-btn.active{background:rgba(88,166,255,.1);color:var(--blue);border-left-color:var(--blue)}
.hist-date-main{overflow-y:auto;padding:1rem}
.hist-date-main::-webkit-scrollbar{width:4px}
.hist-date-main::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.sess-card{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:8px;margin-bottom:1rem;overflow:hidden;
}
.sess-head{
  padding:.65rem 1rem;display:flex;align-items:center;
  justify-content:space-between;flex-wrap:wrap;gap:.5rem;
  border-bottom:1px solid var(--border);
}
.sess-meta{display:flex;gap:1rem;flex-wrap:wrap}
.sess-meta-item{font-size:.72rem;color:var(--muted)}
.sess-meta-item strong{color:var(--text);font-weight:600}
.sess-stat-row{
  display:flex;gap:.5rem;padding:.5rem 1rem;
  border-bottom:1px solid var(--border);
  flex-wrap:wrap;
}
.sess-stat{
  background:var(--surface);border:1px solid var(--border);
  border-radius:5px;padding:.3rem .65rem;font-size:.72rem;
  display:flex;gap:.35rem;align-items:center;
}
.sess-stat .sv{font-weight:700;color:var(--text)}
.batch-list{padding:.5rem 1rem .75rem}
.batch-item{
  border:1px solid var(--border);border-radius:6px;
  margin-bottom:.5rem;overflow:hidden;
  transition:.15s;
}
.batch-hdr{
  display:grid;
  grid-template-columns:2rem 9rem 5rem 5rem 5rem 5rem 1fr;
  gap:.4rem;align-items:center;padding:.4rem .6rem;
  cursor:pointer;background:var(--surface);
  font-size:.75rem;transition:.15s;
}
.batch-hdr:hover{background:var(--surface2)}
.batch-detail-body{
  display:none;padding:.65rem .85rem;
  background:#0d1117;font-size:.78rem;
  border-top:1px solid var(--border);
}
.batch-detail-body.open{display:block}
.hist-empty{text-align:center;color:var(--muted);padding:3rem 1rem;font-size:.82rem}
.date-dot{
  display:inline-block;width:6px;height:6px;
  border-radius:50%;margin-right:.35rem;
  background:var(--green);
}
.date-dot.warn{background:var(--red)}

/* TOAST */
.toast-area{position:fixed;bottom:1.1rem;right:1.1rem;z-index:9999;
  display:flex;flex-direction:column;gap:.4rem}
.toast{
  background:var(--surface);border:1px solid var(--border);border-radius:7px;
  padding:.55rem .9rem;font-size:.78rem;color:var(--text);
  opacity:0;transform:translateY(8px);transition:.28s;max-width:280px;
}
.toast.show{opacity:1;transform:none}
</style>
</head>
<body>

<!-- NAV -->
<nav class="nav">
  <div class="brand">
    <span class="brand-icon">🛡️</span>
    SharkEye <span style="opacity:.35;font-weight:400;margin-left:.25rem">/ NIDS</span>
  </div>
  <div class="nav-right">
    <span id="capPill" class="pill">
      <span class="dot"></span><span id="capText">Idle</span>
    </span>
    <span id="tsUpdated" style="font-size:.7rem;color:var(--muted)">—</span>
    <button onclick="openLlmManager()" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:5px;padding:.2rem .6rem;cursor:pointer;font-size:.72rem;transition:.2s;font-family:'Inter',sans-serif;font-weight:500" onmouseover="this.style.background='var(--border)'" onmouseout="this.style.background='var(--surface2)'">🤖 LLM Manager</button>
    <span style="font-size:.72rem;color:var(--muted);font-family:'JetBrains Mono',monospace;margin-left:.25rem">🔑 sharkeye</span>
    <a href="/logout" style="font-size:.72rem;color:var(--muted);text-decoration:none;
       border:1px solid var(--border);border-radius:5px;padding:.2rem .6rem;transition:.18s"
       onmouseover="this.style.color='var(--red)';this.style.borderColor='rgba(248,81,73,.5)'"
       onmouseout="this.style.color='var(--muted)';this.style.borderColor='var(--border)'">⏏ Logout</a>
  </div>
</nav>

<div class="wrap">

  <!-- LLM Warning Banner -->
  <div id="llmWarningBanner" style="display:none;background:rgba(248,81,73,.15);border:1px solid rgba(248,81,73,.4);color:var(--text);padding:1rem;border-radius:12px;margin-bottom:1.5rem;align-items:center;gap:1rem;box-shadow:0 4px 15px rgba(0,0,0,.2)">
    <span style="font-size:1.8rem">⚠️</span>
    <div style="flex:1">
      <h3 style="margin-bottom:.2rem;color:var(--red)">No LLM Installed</h3>
      <p style="font-size:.85rem;color:var(--muted)">AI Analysis will not work. Please open the LLM Manager to install a model.</p>
    </div>
    <button onclick="openLlmManager()" style="background:var(--red);color:#fff;border:none;padding:.6rem 1rem;border-radius:6px;font-weight:600;cursor:pointer">Open Manager</button>
  </div>

  <!-- INTERFACE PICKER -->
  <div class="iface-card">
    <h2>📡 Network Interfaces — select one to capture</h2>
    <div class="iface-table-wrap">
      <table class="iface-table" id="ifaceTable">
        <thead><tr>
          <th></th>
          <th>Interface</th>
          <th>State</th>
          <th>IP Address</th>
          <th>Internet</th>
          <th>MAC</th>
        </tr></thead>
        <tbody id="ifaceBody">
          <tr><td colspan="6" style="color:var(--muted);padding:1rem .7rem">Scanning interfaces…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- CONTROLS -->
  <div class="controls">
    <button class="btn green" id="startBtn" onclick="startCapture()" disabled>▶ Start Capture</button>
    <button class="btn red"   id="stopBtn"  onclick="stopCapture()"  disabled>⏹ Stop</button>
    <button class="btn"       id="clrBtn"   onclick="clearLog()">🗑 Clear Log</button>
    <button class="btn"       id="scrollBtn" onclick="toggleScroll()">📌 Auto-scroll: ON</button>
    <button class="btn"       onclick="openHistory()">📅 History</button>
    <span class="hint">Stats refresh every 5 s</span>
  </div>

  <!-- SERVICE BADGES -->
  <div class="svc-row">
    <span class="svc" id="svcOllama"><span class="sdot"></span>Ollama</span>
    <span class="svc" id="svcTshark"><span class="sdot"></span>tshark</span>
    <span class="svc" id="svcCapture"><span class="sdot"></span>Capture</span>
    <span class="svc" id="svcIface"><span class="sdot"></span>No interface selected</span>
  </div>

  <!-- ALERT -->
  <div class="alert-strip" id="alertStrip">⚠ Malicious activity detected in latest batch.</div>

  <!-- STAT CARDS -->
  <div class="stat-grid">
    <div class="stat p" onclick="openModal('packets')" title="Click for details">
      <div class="stat-label">📦 Packets (batch)</div>
      <div class="stat-val" id="sPackets">0</div>
      <div class="stat-sub" id="sPacketsSub">—</div>
      <div class="stat-click-hint">↗ click for details</div>
    </div>
    <div class="stat b" onclick="openModal('ips')" title="Click for details">
      <div class="stat-label">🌐 Unique Src IPs</div>
      <div class="stat-val" id="sIPs">0</div>
      <div class="stat-sub" id="sIPsSub">—</div>
      <div class="stat-click-hint">↗ click for details</div>
    </div>
    <div class="stat y" onclick="openModal('anomalies')" title="Click for details">
      <div class="stat-label">⚡ Anomalies</div>
      <div class="stat-val" id="sAnom">0</div>
      <div class="stat-sub" id="sAnomSub">—</div>
      <div class="stat-click-hint">↗ click for details</div>
    </div>
    <div class="stat r" onclick="openModal('malicious')" title="Click for details">
      <div class="stat-label">🚨 Malicious</div>
      <div class="stat-val" id="sMal">0</div>
      <div class="stat-sub" id="sMalSub">—</div>
      <div class="stat-click-hint">↗ click for details</div>
    </div>
    <div class="stat g" onclick="openModal('batches')" title="Click for details">
      <div class="stat-label">📊 Batches</div>
      <div class="stat-val" id="sBatch">0</div>
      <div class="stat-sub" id="sBatchSub">—</div>
      <div class="stat-click-hint">↗ click for details</div>
    </div>
  </div>

  <!-- DETAIL MODAL -->
  <div class="modal-overlay" id="modalOverlay" onclick="if(event.target===this)closeModal()">
    <div class="modal">
      <div class="modal-head">
        <span class="modal-title" id="modalTitle">Details</span>
        <button class="modal-close" onclick="closeModal()">✕</button>
      </div>
      <div class="modal-tabs">
        <button class="mtab" data-tab="packets"  onclick="switchTab('packets')">📦 Packets</button>
        <button class="mtab" data-tab="ips"      onclick="switchTab('ips')">🌐 Source IPs</button>
        <button class="mtab" data-tab="anomalies" onclick="switchTab('anomalies')">⚡ Anomalies</button>
        <button class="mtab" data-tab="malicious" onclick="switchTab('malicious')">🚨 Malicious</button>
        <button class="mtab" data-tab="batches"  onclick="switchTab('batches')">📊 Batch History</button>
      </div>
      <div class="modal-body">
        <!-- Packets tab -->
        <div class="tab-pane" id="tab-packets">
          <div id="packetDetail"></div>
        </div>
        <!-- IPs tab -->
        <div class="tab-pane" id="tab-ips">
          <div id="ipDetail"></div>
        </div>
        <!-- Anomalies tab -->
        <div class="tab-pane" id="tab-anomalies">
          <div id="anomDetail"></div>
        </div>
        <!-- Malicious tab -->
        <div class="tab-pane" id="tab-malicious">
          <div id="malDetail"></div>
        </div>
        <!-- Batches tab -->
        <div class="tab-pane" id="tab-batches">
          <div id="batchDetail"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- CHARTS -->
  <div class="chart-row">
    <div class="panel">
      <div class="panel-hdr">📈 Packets per Cycle</div>
      <div class="panel-body"><div class="chart-wrap"><canvas id="lineChart"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="panel-hdr">🍩 Protocol Distribution</div>
      <div class="panel-body"><div class="chart-wrap"><canvas id="donutChart"></canvas></div></div>
    </div>
  </div>

  <!-- BOTTOM ROW -->
  <div class="bottom-row">
    <div class="panel">
      <div class="panel-hdr">📋 Latest Analysis</div>
      <div class="panel-body">
        <pre class="logbox" id="analysisBox">No analysis yet. Start a capture to begin.</pre>
      </div>
    </div>
    <div class="panel">
      <div class="panel-hdr">🌐 Top Source IPs</div>
      <div class="panel-body" style="padding:.4rem">
        <div style="max-height:270px;overflow-y:auto">
          <table class="ip-t">
            <thead><tr><th>IP Address</th><th>Packets</th></tr></thead>
            <tbody id="ipBody"><tr><td colspan="2" style="color:var(--muted);padding:1rem .55rem">No data yet</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- TERMINAL LOG -->
  <div class="panel" style="margin-bottom:1.1rem">
    <div class="panel-hdr">
      🖥 Real-Time Log
      <span id="sseStatus" style="font-size:.68rem;color:var(--muted)">connecting…</span>
    </div>
    <div class="panel-body" style="padding:.5rem">
      <div class="logbox" id="termLog" style="max-height:300px"></div>
    </div>
  </div>

  <!-- HISTORY MODAL -->
  <div class="modal-overlay" id="historyOverlay" onclick="if(event.target===this)closeHistory()">
    <div class="modal" style="width:min(860px,97vw);max-height:88vh">
      <div class="modal-head">
        <span class="modal-title">📅 Activity History</span>
        <div style="display:flex;align-items:center;gap:.75rem">
          <span id="histStatus" style="font-size:.72rem;color:var(--muted)"></span>
          <button class="modal-close" onclick="closeHistory()">✕</button>
        </div>
      </div>
      <div class="hist-layout" style="flex:1;overflow:hidden">
        <!-- Date sidebar -->
        <div class="hist-sidebar" id="histSidebar">
          <div style="padding:.4rem .85rem;font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Dates</div>
          <div id="histDateList"><div style="padding:.75rem .85rem;font-size:.75rem;color:var(--muted)">Loading…</div></div>
        </div>
        <!-- Day detail pane -->
        <div class="hist-date-main" id="histMain">
          <div class="hist-empty">📂 Select a date from the left to view activity.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- LLM MODAL -->
  <div class="modal-overlay" id="llmOverlay" onclick="if(event.target===this)closeLlmManager()">
    <div class="modal" style="width:min(600px,95vw)">
      <div class="modal-head">
        <span class="modal-title">🤖 LLM Manager</span>
        <button class="modal-close" onclick="closeLlmManager()">✕</button>
      </div>
      <div style="padding:1.5rem">
        <h3 style="margin-bottom:.5rem;color:var(--blue)">Installed Models</h3>
        <div id="installedModelsList" style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:1.5rem;font-size:.85rem;color:var(--muted)">Loading...</div>
        
        <h3 style="margin-bottom:.5rem;color:var(--green)">Available Models</h3>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;padding:.5rem 0;border-bottom:1px solid var(--border)">
            <div>
              <div style="font-weight:600;color:var(--text)">qwen2.5-coder:3b</div>
              <div style="font-size:.75rem;color:var(--muted)">Fast & Smart (~2GB) - Recommended</div>
            </div>
            <button onclick="pullLlm('qwen2.5-coder:3b')" style="background:var(--green);color:#000;border:none;padding:.4rem .8rem;border-radius:4px;font-weight:600;cursor:pointer">Install</button>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;padding:.5rem 0;border-bottom:1px solid var(--border)">
            <div>
              <div style="font-weight:600;color:var(--text)">llama3.2:3b</div>
              <div style="font-size:.75rem;color:var(--muted)">General reasoning (~2GB)</div>
            </div>
            <button onclick="pullLlm('llama3.2:3b')" style="background:var(--green);color:#000;border:none;padding:.4rem .8rem;border-radius:4px;font-weight:600;cursor:pointer">Install</button>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;padding:.5rem 0">
            <div>
              <div style="font-weight:600;color:var(--text)">mistral:7b</div>
              <div style="font-size:.75rem;color:var(--muted)">High accuracy (~4GB)</div>
            </div>
            <button onclick="pullLlm('mistral:7b')" style="background:var(--green);color:#000;border:none;padding:.4rem .8rem;border-radius:4px;font-weight:600;cursor:pointer">Install</button>
          </div>
        </div>
        
        <div id="llmProgressArea" style="display:none;margin-top:1.5rem">
          <div style="display:flex;justify-content:space-between;font-size:.8rem;margin-bottom:.3rem">
            <span id="llmProgressText" style="color:var(--text)">Downloading...</span>
            <span id="llmProgressPct" style="color:var(--blue)">0%</span>
          </div>
          <div style="width:100%;background:var(--surface2);border-radius:4px;height:8px;overflow:hidden">
            <div id="llmProgressBar" style="width:0%;height:100%;background:var(--blue);transition:width .2s"></div>
          </div>
        </div>
      </div>
    </div>
  </div>

</div><!-- /wrap -->

<div class="toast-area" id="toastArea"></div>

<script>
/* ── State ────────────────────────────────────────────────── */
let selectedIface = '';
let autoScroll    = true;
let batchCount    = 0;
let lineChart, donutChart;
let lastData      = null;   // stores latest /stats response for modal
let batchHistory  = [];     // [{ts, packets, ips, anom, mal}]

/* ── LLM Manager ───────────────────────────────────────────── */
function openLlmManager() {
  document.getElementById('llmOverlay').style.display = 'flex';
  refreshLlmList();
}
function closeLlmManager() {
  document.getElementById('llmOverlay').style.display = 'none';
}
async function refreshLlmList() {
  const container = document.getElementById('installedModelsList');
  container.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/llm/list').then(r=>r.json());
    if (res.error) {
      container.innerHTML = `
        <div style="color:var(--red);margin-bottom:1rem">Error: ${res.error}</div>
        <div style="margin-bottom:1rem;color:var(--muted);font-size:.9rem">Ollama engine might not be installed or running on this machine.</div>
        <button onclick="installOllama()" style="background:var(--blue);color:#fff;border:none;padding:.6rem 1rem;border-radius:6px;cursor:pointer;font-weight:600">Install Ollama</button>
      `;
      return;
    }
    const models = res.models || [];
    if (models.length === 0) {
      container.innerHTML = 'No models installed.';
      document.getElementById('llmWarningBanner').style.display = 'flex';
    } else {
      document.getElementById('llmWarningBanner').style.display = 'none';
      container.innerHTML = models.map(m => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:.4rem 0;border-bottom:1px solid var(--surface2)">
          <div>
            <span style="font-weight:600;color:var(--text)">${m.name}</span>
            <span style="font-size:.7rem;color:var(--muted);margin-left:.5rem">${Math.round(m.size/1e9*10)/10} GB</span>
          </div>
          <div style="display:flex;gap:.5rem">
            <button onclick="selectLlm('${m.name}')" style="background:var(--surface2);color:var(--blue);border:1px solid var(--border);padding:.3rem .6rem;border-radius:4px;cursor:pointer">Use</button>
            <button onclick="deleteLlm('${m.name}')" style="background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.3);padding:.3rem .6rem;border-radius:4px;cursor:pointer">Delete</button>
          </div>
        </div>
      `).join('');
    }
  } catch(e) {
    container.innerHTML = 'Error loading models.';
  }
}

async function installOllama() {
  const btn = event.target;
  btn.innerText = "Starting Install...";
  btn.disabled = true;
  try {
    const res = await fetch('/api/llm/install_ollama', {method:'POST'}).then(r=>r.json());
    if (res.status === 'manual') {
      btn.innerText = "Download for Mac";
      btn.disabled = false;
      btn.onclick = () => window.open('https://ollama.com/download/mac', '_blank');
      alert(res.msg);
    } else if (res.status === 'started') {
      btn.innerText = "Installing... Please Wait";
      alert(res.msg);
    } else {
      btn.innerText = "Install Failed";
      alert(res.msg);
    }
  } catch(e) {
    btn.innerText = "Error";
    alert(e);
  }
}

async function deleteLlm(name) {
  if(!confirm(`Delete model ${name}?`)) return;
  await fetch('/api/llm/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({model: name})
  });
  refreshLlmList();
}

async function selectLlm(name) {
  await fetch('/api/llm/select', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({model: name})
  });
  showToast(`Active model set to ${name}`, 'ok');
}

let llmEvtSource = null;
function pullLlm(name) {
  if (llmEvtSource) llmEvtSource.close();
  document.getElementById('llmProgressArea').style.display = 'block';
  document.getElementById('llmProgressText').innerText = `Pulling ${name}...`;
  document.getElementById('llmProgressText').style.color = 'var(--text)';
  const bar = document.getElementById('llmProgressBar');
  const pct = document.getElementById('llmProgressPct');
  bar.style.width = '0%';
  pct.innerText = '0%';
  
  llmEvtSource = new EventSource(`/api/llm/pull?model=${name}`);
  llmEvtSource.onmessage = function(e) {
    const data = JSON.parse(e.data);
    if (data.error) {
      document.getElementById('llmProgressText').innerText = `Error: ${data.error}`;
      document.getElementById('llmProgressText').style.color = 'var(--red)';
      llmEvtSource.close();
      return;
    }
    document.getElementById('llmProgressText').innerText = data.status || 'Downloading...';
    if (data.total && data.completed) {
      const p = Math.round((data.completed / data.total) * 100);
      bar.style.width = p + '%';
      pct.innerText = p + '%';
    }
    if (data.status === 'success') {
      document.getElementById('llmProgressText').innerText = 'Complete!';
      document.getElementById('llmProgressText').style.color = 'var(--green)';
      bar.style.width = '100%';
      pct.innerText = '100%';
      llmEvtSource.close();
      setTimeout(() => {
        document.getElementById('llmProgressArea').style.display = 'none';
        document.getElementById('llmProgressText').style.color = 'var(--text)';
        refreshLlmList();
      }, 2000);
    }
  };
}

setTimeout(refreshLlmList, 1000);

/* ── Chart init ───────────────────────────────────────────── */
if (typeof Chart === 'undefined') {
  document.body.innerHTML = '<p style="padding:2rem;color:var(--red);font-family:monospace">Chart.js failed to load from CDN.</p>';
}
Chart.defaults.color       = '#8b949e';
Chart.defaults.borderColor = '#30363d';

function initCharts() {
  lineChart = new Chart(document.getElementById('lineChart'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets', data: [],
        borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,.07)',
        fill: true, tension: .35, pointRadius: 3, pointBackgroundColor: '#58a6ff'
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid:{color:'#21262d'}, ticks:{font:{family:'JetBrains Mono',size:10}} },
        y: { beginAtZero: true, grid:{color:'#21262d'} }
      }
    }
  });

  donutChart = new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
      labels: ['TCP','UDP','Other'],
      datasets: [{
        data: [0,0,1],
        backgroundColor: ['#1f6feb','#238636','#30363d'],
        borderColor: ['#58a6ff','#3fb950','#484f58'],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      plugins: { legend: { position:'bottom', labels:{ padding:10, font:{size:11} } } }
    }
  });
}

/* ── Interface table ──────────────────────────────────────── */
async function loadInterfaces() {
  try {
    const data = await fetch('/api/interfaces').then(r => r.json());
    const tbody = document.getElementById('ifaceBody');
    if (!data.interfaces || !data.interfaces.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);padding:1rem .7rem">No interfaces found.</td></tr>';
      return;
    }
    tbody.innerHTML = data.interfaces.map((ifc, i) => {
      const stateCls = ifc.state === 'UP' ? 'up' : ifc.state === 'DOWN' ? 'down' : 'unk';
      const inetCls  = ifc.has_internet ? 'inet' : (ifc.state === 'UP' && ifc.ip ? 'lan' : 'none');
      const inetTxt  = ifc.has_internet ? '● Online' : (ifc.state === 'UP' && ifc.ip ? '○ LAN only' : '✗ None');
      return `<tr onclick="selectIface('${ifc.name}')" id="ifr-${ifc.name}">
        <td><input type="radio" name="iface" value="${ifc.name}" style="accent-color:var(--blue)"></td>
        <td style="font-weight:600">${ifc.name}</td>
        <td><span class="badge ${stateCls}">${ifc.state}</span></td>
        <td class="mono">${ifc.ip || '—'}</td>
        <td><span class="badge ${inetCls}">${inetTxt}</span></td>
        <td class="mono" style="color:var(--muted)">${ifc.mac || '—'}</td>
      </tr>`;
    }).join('');

    // Auto-select first internet-connected interface
    const best = data.interfaces.find(i => i.has_internet) || data.interfaces[0];
    if (best) selectIface(best.name);

  } catch(e) {
    console.error('loadInterfaces error:', e);
  }
}

function selectIface(name) {
  selectedIface = name;
  // Update radio + highlight
  document.querySelectorAll('.iface-table tbody tr').forEach(tr => tr.classList.remove('selected'));
  const row = document.getElementById('ifr-' + name);
  if (row) {
    row.classList.add('selected');
    row.querySelector('input[type=radio]').checked = true;
  }
  // Enable start button
  document.getElementById('startBtn').disabled = false;
  // Update svc badge
  setSvc('svcIface', 'ok', `Interface: ${name}`);
}

/* ── Service badges ───────────────────────────────────────── */
function setSvc(id, state, label) {
  const el = document.getElementById(id);
  el.className = 'svc' + (state ? ' ' + state : '');
  if (label) el.innerHTML = `<span class="sdot"></span>${label}`;
}

/* ── Stats update ─────────────────────────────────────────── */
function updateUI(d) {
  const capturing = d.capturing;

  // Cap pill
  const pill = document.getElementById('capPill');
  document.getElementById('capText').textContent = capturing ? 'Capturing' : 'Idle';
  pill.className = 'pill' + (capturing ? ' live' : '');

  // Buttons
  document.getElementById('startBtn').disabled = capturing || !selectedIface;
  document.getElementById('stopBtn').disabled  = !capturing;

  document.getElementById('tsUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();

  // Save for modal
  lastData = d;

  // Stat cards + sub-labels
  const mal   = Array.isArray(d.malicious_activities) ? d.malicious_activities.length : 0;
  const proto = d.proto || {tcp:0,udp:0,other:0};
  const tot   = (proto.tcp||0)+(proto.udp||0)+(proto.other||0);

  document.getElementById('sPackets').textContent  = d.total_packets      || 0;
  document.getElementById('sPacketsSub').textContent =
    tot > 0 ? `TCP ${proto.tcp||0}  UDP ${proto.udp||0}  Other ${proto.other||0}` : '—';

  document.getElementById('sIPs').textContent      = d.unique_src_ips    || 0;
  const topIpEntries = Object.entries(d.top_src_ips || {});
  document.getElementById('sIPsSub').textContent   =
    topIpEntries.length ? `Top: ${topIpEntries[0][0]}` : '—';

  document.getElementById('sAnom').textContent     = d.anomalies_detected || 0;
  document.getElementById('sAnomSub').textContent  =
    d.analysis && d.analysis.summary
      ? d.analysis.summary.slice(0, 40) + (d.analysis.summary.length > 40 ? '…' : '')
      : '—';

  document.getElementById('sMal').textContent      = mal;
  document.getElementById('sMalSub').textContent   =
    mal > 0 ? (d.malicious_activities[0] || '').slice(0, 38) + '…' : 'None detected';

  // Batch history tracking
  if (d.total_packets > 0) {
    const now = new Date().toLocaleTimeString();
    // Only add if this looks like a new batch (different packet count or new ts)
    const last = batchHistory[batchHistory.length - 1];
    if (!last || last.ts !== now) {
      batchHistory.push({
        ts: now, num: batchHistory.length + 1,
        packets: d.total_packets, ips: d.unique_src_ips,
        anom: d.anomalies_detected, mal: mal
      });
      if (batchHistory.length > 50) batchHistory.shift();
    }
    batchCount = batchHistory.length;
  }
  document.getElementById('sBatch').textContent    = batchCount;
  document.getElementById('sBatchSub').textContent =
    batchHistory.length ? `Last: ${batchHistory[batchHistory.length-1].ts}` : '—';

  document.getElementById('alertStrip').classList.toggle('show', mal > 0);
  if (mal > 0) {
    document.getElementById('alertStrip').innerHTML =
      `⚠ ${mal} malicious event${mal>1?'s':''} detected — <a href="#" style="color:var(--red)" onclick="openModal('malicious');return false">View details →</a>`;
  }

  // Service badges
  setSvc('svcOllama',  d.ollama_ok ? 'ok' : 'err', d.ollama_ok ? 'Ollama: Running' : 'Ollama: Down');
  setSvc('svcTshark',  d.tshark_ok ? 'ok' : 'err', d.tshark_ok ? 'tshark: Ready'   : 'tshark: Error');
  setSvc('svcCapture', capturing   ? 'busy' : '',   capturing   ? 'Capture: Active'  : 'Capture: Idle');

  // Analysis box
  const an = d.analysis || {};
  if (Object.keys(an).length) {
    let t = '';
    if (an.summary)         t += '[ Summary ]\n' + an.summary + '\n\n';
    if (an.anomalies_detected !== undefined) t += '[ Anomalies ]  ' + an.anomalies_detected + '\n\n';
    if (Array.isArray(an.malicious_activities) && an.malicious_activities.length)
      t += '[ Malicious Activity ]\n' + an.malicious_activities.join('\n') + '\n\n';
    if (Array.isArray(an.recommendations) && an.recommendations.length)
      t += '[ Recommendations ]\n' + an.recommendations.map((r,i)=>`${i+1}. ${r}`).join('\n');
    if (an.error) t = '[ Error ]\n' + an.error;
    document.getElementById('analysisBox').textContent = t.trim() || JSON.stringify(an, null, 2);
  }

  // Line chart
  if (lineChart && Array.isArray(d.history) && d.history.length) {
    lineChart.data.labels           = d.history.map(e => e.timestamp);
    lineChart.data.datasets[0].data = d.history.map(e => e.packet_count);
    lineChart.update('none');
  }

  // Donut chart
  if (donutChart) {
    donutChart.data.datasets[0].data =
      tot > 0 ? [proto.tcp||0,proto.udp||0,proto.other||0] : [0,0,1];
    donutChart.update('none');
  }

  // IP table (sidebar)
  const entries = Object.entries(d.top_src_ips || {});
  document.getElementById('ipBody').innerHTML = entries.length
    ? entries.map(([ip,c]) => `<tr><td>${ip}</td><td><span class="cnt">${c}</span></td></tr>`).join('')
    : '<tr><td colspan="2" style="color:var(--muted);padding:1rem .55rem">No data yet</td></tr>';
}

/* ── Modal ────────────────────────────────────────────────── */
function openModal(tab) {
  buildModalContent();
  document.getElementById('modalOverlay').classList.add('open');
  switchTab(tab);
  // Title
  const titles = {
    packets:   '📦 Packet Details',
    ips:       '🌐 Source IP Details',
    anomalies: '⚡ Anomaly Details',
    malicious: '🚨 Malicious Activity Details',
    batches:   '📊 Batch History'
  };
  document.getElementById('modalTitle').textContent = titles[tab] || 'Details';
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
}

function switchTab(name) {
  document.querySelectorAll('.mtab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  const titles = {
    packets:   '📦 Packet Details',
    ips:       '🌐 Source IP Details',
    anomalies: '⚡ Anomaly Details',
    malicious: '🚨 Malicious Activity Details',
    batches:   '📊 Batch History'
  };
  document.getElementById('modalTitle').textContent = titles[name] || 'Details';
}

function buildModalContent() {
  if (!lastData) return;
  const d  = lastData;
  const an = d.analysis || {};
  const p  = d.proto     || {tcp:0,udp:0,other:0};
  const tot = (p.tcp||0)+(p.udp||0)+(p.other||0);

  /* ── Packets tab ── */
  document.getElementById('packetDetail').innerHTML = `
    <div class="detail-row"><span class="detail-key">Total Packets (batch)</span><span class="detail-val">${d.total_packets||0}</span></div>
    <div class="detail-row"><span class="detail-key">TCP Packets</span><span class="detail-val">${p.tcp||0} ${tot?'('+Math.round((p.tcp||0)/tot*100)+'%)':''}</span></div>
    <div class="detail-row"><span class="detail-key">UDP Packets</span><span class="detail-val">${p.udp||0} ${tot?'('+Math.round((p.udp||0)/tot*100)+'%)':''}</span></div>
    <div class="detail-row"><span class="detail-key">Other Packets</span><span class="detail-val">${p.other||0} ${tot?'('+Math.round((p.other||0)/tot*100)+'%)':''}</span></div>
    <div class="detail-row"><span class="detail-key">Unique Source IPs</span><span class="detail-val">${d.unique_src_ips||0}</span></div>
    <div class="detail-row"><span class="detail-key">Batches Completed</span><span class="detail-val">${batchCount}</span></div>
    ${an.summary ? `<div style="margin-top:1rem;padding:.7rem;background:var(--surface2);border-radius:6px;font-size:.8rem;line-height:1.6">${an.summary}</div>` : ''}
  `;

  /* ── IPs tab ── */
  const ips = Object.entries(d.top_src_ips || {});
  const maxCnt = ips.length ? ips[0][1] : 1;
  document.getElementById('ipDetail').innerHTML = ips.length
    ? `<table class="ip-t" style="width:100%">
        <thead><tr><th>#</th><th>IP Address</th><th>Packets</th><th style="width:35%">Volume</th></tr></thead>
        <tbody>${ips.map(([ip,c],i) => `
          <tr>
            <td style="color:var(--muted)">${i+1}</td>
            <td style="font-family:'JetBrains Mono',monospace">${ip}</td>
            <td><span class="cnt">${c}</span></td>
            <td><div class="batch-bar-wrap"><div class="batch-bar" style="width:${Math.round(c/maxCnt*100)}%"></div></div></td>
          </tr>`).join('')}
        </tbody></table>`
    : '<div class="empty-state">No IP data available yet.</div>';

  /* ── Anomalies tab ── */
  const anomCount = an.anomalies_detected || 0;
  let anomHtml = `<div class="detail-row"><span class="detail-key">Anomalies Detected</span><span class="detail-val" style="color:var(--yellow)">${anomCount}</span></div>`;
  if (an.summary) anomHtml += `<div class="anom-item" style="margin-top:.8rem">
    <div style="font-size:.7rem;color:var(--yellow);font-weight:600;margin-bottom:.3rem">SUMMARY</div>
    ${an.summary}</div>`;
  if (Array.isArray(an.recommendations) && an.recommendations.length) {
    anomHtml += '<div style="margin-top:.9rem;font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.4rem">Recommendations</div>';
    anomHtml += an.recommendations.map((r,i) =>
      `<div class="rec-item"><span class="rec-num">${i+1}.</span><span>${r}</span></div>`).join('');
  }
  if (an.error) anomHtml += `<div class="anom-item" style="border-color:rgba(248,81,73,.3)"><span style="color:var(--red)">Error: </span>${an.error}</div>`;
  if (!anomCount && !an.summary && !an.error) anomHtml += '<div class="empty-state">No anomalies recorded in this batch.</div>';
  document.getElementById('anomDetail').innerHTML = anomHtml;

  /* ── Malicious tab ── */
  const malist = Array.isArray(an.malicious_activities) ? an.malicious_activities : [];
  document.getElementById('malDetail').innerHTML = malist.length
    ? malist.map((m,i) => `
        <div class="mal-item">
          <span class="mal-num">#${i+1}</span>${m}
        </div>`).join('')
    : '<div class="empty-state" style="color:var(--green)">✓ No malicious activity detected in latest batch.</div>';

  /* ── Batches tab ── */
  const maxP = batchHistory.length ? Math.max(...batchHistory.map(b => b.packets)) : 1;
  document.getElementById('batchDetail').innerHTML = batchHistory.length
    ? `<div style="font-size:.7rem;color:var(--muted);margin-bottom:.6rem">${batchHistory.length} batch${batchHistory.length>1?'es':''} recorded this session</div>
       <div style="display:grid;grid-template-columns:2rem 6rem 1fr 4.5rem 4.5rem 4rem;gap:.4rem;font-size:.68rem;color:var(--muted);padding:.2rem;text-transform:uppercase;letter-spacing:.05em">
         <span>#</span><span>Time</span><span>Packets</span><span>Unique IPs</span><span>Anomalies</span><span>Malicious</span>
       </div>
       ${batchHistory.slice().reverse().map(b => `
         <div style="display:grid;grid-template-columns:2rem 6rem 1fr 4.5rem 4.5rem 4rem;gap:.4rem;align-items:center;padding:.35rem .2rem;border-bottom:1px solid var(--surface2);font-size:.77rem">
           <span style="color:var(--muted)">${b.num}</span>
           <span class="mono">${b.ts}</span>
           <div>
             <div class="batch-bar-wrap"><div class="batch-bar" style="width:${maxP?Math.round(b.packets/maxP*100):0}%"></div></div>
             <span style="font-size:.68rem;color:var(--muted)">${b.packets} pkts</span>
           </div>
           <span>${b.ips}</span>
           <span style="color:${b.anom>0?'var(--yellow)':'var(--muted)'}">${b.anom}</span>
           <span style="color:${b.mal>0?'var(--red)':'var(--green)'}">${b.mal}</span>
         </div>`).join('')}
      `
    : '<div class="empty-state">No batches completed yet. Start a capture to begin.</div>';
}

/* ── Polling ──────────────────────────────────────────────── */
async function refresh() {
  try {
    const r = await fetch('/stats');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    updateUI(await r.json());
  } catch(e) { console.warn('refresh:', e); }
}

/* ── Capture control ──────────────────────────────────────── */
async function startCapture() {
  if (!selectedIface) { toast('Select an interface first.', true); return; }
  document.getElementById('startBtn').disabled = true;
  try {
    const r = await fetch('/start', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({interface: selectedIface})
    });
    const d = await r.json();
    if (d.status === 'started') {
      toast('Capture started on ' + selectedIface);
    } else {
      toast(d.status || 'Unknown response', true);
      document.getElementById('startBtn').disabled = false;
    }
    refresh();
  } catch(e) {
    toast('Failed: ' + e.message, true);
    document.getElementById('startBtn').disabled = false;
  }
}

async function stopCapture() {
  document.getElementById('stopBtn').disabled = true;
  try {
    await fetch('/stop', {method:'POST'});
    toast('Capture stopped');
    refresh();
  } catch(e) {
    toast('Failed: ' + e.message, true);
    document.getElementById('stopBtn').disabled = false;
  }
}

/* ── Terminal log ─────────────────────────────────────────── */
const termLog = document.getElementById('termLog');

function appendLine(line) {
  const span = document.createElement('span');
  const low  = line.toLowerCase();
  let cls = 'lg-info';
  if (low.includes('[error]') || low.includes('error:'))  cls = 'lg-err';
  else if (low.includes('[warn') || low.includes('warning')) cls = 'lg-warn';
  else if (low.includes('[ok]') || low.includes('started') ||
           low.includes('complete') || low.includes('found'))  cls = 'lg-ok';
  span.className   = cls;
  span.textContent = line + '\n';
  termLog.appendChild(span);
  if (autoScroll) termLog.scrollTop = termLog.scrollHeight;
  while (termLog.childNodes.length > 800) termLog.removeChild(termLog.firstChild);
}

function clearLog() { termLog.innerHTML = ''; }

function toggleScroll() {
  autoScroll = !autoScroll;
  document.getElementById('scrollBtn').textContent = '📌 Auto-scroll: ' + (autoScroll ? 'ON' : 'OFF');
}

/* ── History modal ──────────────────────────────────────────── */
async function openHistory() {
  document.getElementById('historyOverlay').classList.add('open');
  await loadHistoryDates();
}

function closeHistory() {
  document.getElementById('historyOverlay').classList.remove('open');
}

async function loadHistoryDates() {
  const list   = document.getElementById('histDateList');
  const status = document.getElementById('histStatus');
  list.innerHTML = '<div style="padding:.75rem .85rem;font-size:.75rem;color:var(--muted)">Loading…</div>';
  try {
    const data = await fetch('/api/history').then(r => r.json());
    const dates = data.dates || [];
    if (!dates.length) {
      list.innerHTML = '<div style="padding:.75rem .85rem;font-size:.75rem;color:var(--muted)">No history yet.</div>';
      status.textContent = '0 dates';
      return;
    }
    status.textContent = `${dates.length} date${dates.length > 1 ? 's' : ''} saved`;
    list.innerHTML = dates.map(d => {
      const hasMal = d.total_malicious > 0;
      return `<button class="hist-date-btn" onclick="loadHistoryDay('${d.date}', this)">
        <span class="date-dot ${hasMal ? 'warn' : ''}"></span>
        <strong>${d.date}</strong>
        <div style="font-size:.68rem;color:var(--muted);margin-top:.15rem">
          ${d.session_count} session•${d.batch_count} batch•${d.total_packets.toLocaleString()} pkt
          ${hasMal ? `<span style="color:var(--red)">•${d.total_malicious} mal</span>` : ''}
        </div>
      </button>`;
    }).join('');

    // Auto-load first (most recent) date
    const firstBtn = list.querySelector('.hist-date-btn');
    if (firstBtn) firstBtn.click();
  } catch(e) {
    list.innerHTML = `<div style="padding:.75rem .85rem;font-size:.75rem;color:var(--red)">Error: ${e.message}</div>`;
  }
}

async function loadHistoryDay(date, btn) {
  // Highlight selected date
  document.querySelectorAll('.hist-date-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  const main = document.getElementById('histMain');
  main.innerHTML = '<div class="hist-empty">Loading…</div>';

  try {
    const day = await fetch(`/api/history/${date}`).then(r => r.json());
    const sessions = Object.values(day.sessions || {});

    if (!sessions.length) {
      main.innerHTML = '<div class="hist-empty">No sessions recorded for this date.</div>';
      return;
    }

    // Day summary header
    const totalPkts  = sessions.reduce((a,s) => a + s.batches.reduce((x,b) => x + b.packet_count, 0), 0);
    const totalMal   = sessions.reduce((a,s) => a + s.batches.reduce((x,b) => x + (b.malicious||[]).length, 0), 0);
    const totalAnom  = sessions.reduce((a,s) => a + s.batches.reduce((x,b) => x + (b.anomalies||0), 0), 0);
    const totalBatch = sessions.reduce((a,s) => a + s.batches.length, 0);

    let html = `
      <div style="margin-bottom:1rem">
        <div style="font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:.35rem">${date} — Day Summary</div>
        <div style="display:flex;gap:.55rem;flex-wrap:wrap">
          <span class="sess-stat"><span>Sessions</span><span class="sv">${sessions.length}</span></span>
          <span class="sess-stat"><span>Batches</span><span class="sv">${totalBatch}</span></span>
          <span class="sess-stat"><span>Packets</span><span class="sv">${totalPkts.toLocaleString()}</span></span>
          <span class="sess-stat" style="${totalAnom>0?'border-color:rgba(210,153,34,.4)':''}"><span>Anomalies</span><span class="sv" style="color:${totalAnom>0?'var(--yellow)':'var(--text)'}">${totalAnom}</span></span>
          <span class="sess-stat" style="${totalMal>0?'border-color:rgba(248,81,73,.4)':''}"><span>Malicious</span><span class="sv" style="color:${totalMal>0?'var(--red)':'var(--text)'}">${totalMal}</span></span>
        </div>
      </div>`;

    // Render each session
    sessions.forEach((sess, si) => {
      const dur   = fmtDuration(sess.duration_s);
      const smal  = sess.batches.reduce((a,b) => a + (b.malicious||[]).length, 0);
      const sanom = sess.batches.reduce((a,b) => a + (b.anomalies||0), 0);
      const spkt  = sess.batches.reduce((a,b) => a + b.packet_count, 0);

      html += `
        <div class="sess-card">
          <div class="sess-head">
            <div>
              <div style="font-weight:700;font-size:.82rem">📶 Session ${si+1} — ${sess.interface || 'N/A'}</div>
              <div style="font-size:.68rem;color:var(--muted);margin-top:.15rem">ID: ${sess.session_id}</div>
            </div>
            <div class="sess-meta">
              <div class="sess-meta-item"><strong>Start</strong><br>${sess.session_start || '—'}</div>
              <div class="sess-meta-item"><strong>End</strong><br>${sess.session_end || 'running…'}</div>
              <div class="sess-meta-item"><strong>Duration</strong><br>${dur}</div>
            </div>
          </div>
          <div class="sess-stat-row">
            <span class="sess-stat"><span>Batches</span><span class="sv">${sess.batches.length}</span></span>
            <span class="sess-stat"><span>Packets</span><span class="sv">${spkt.toLocaleString()}</span></span>
            <span class="sess-stat"><span>Anomalies</span><span class="sv" style="color:${sanom>0?'var(--yellow)':'inherit'}">${sanom}</span></span>
            <span class="sess-stat"><span>Malicious</span><span class="sv" style="color:${smal>0?'var(--red)':'var(--green)'}">${smal}</span></span>
          </div>
          <div class="batch-list">
            <div style="font-size:.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.4rem;padding:.2rem 0">
              # &nbsp;&nbsp;&nbsp;Timestamp &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Packets &nbsp;IPs &nbsp;&nbsp;Anom &nbsp;Mal &nbsp;Summary
            </div>
            ${sess.batches.map((b, bi) => {
              const mal = (b.malicious||[]);
              const bId = `bdet-${sess.session_id}-${bi}`;
              return `
              <div class="batch-item">
                <div class="batch-hdr" onclick="toggleBatch('${bId}')">
                  <span style="color:var(--muted)">${b.batch_num}</span>
                  <span class="mono">${b.timestamp ? b.timestamp.slice(11) : ''}</span>
                  <span>${b.packet_count}</span>
                  <span>${b.unique_src_ips}</span>
                  <span style="color:${(b.anomalies||0)>0?'var(--yellow)':'var(--muted)'}">${b.anomalies||0}</span>
                  <span style="color:${mal.length>0?'var(--red)':'var(--green)'}">${mal.length}</span>
                  <span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.7rem">${(b.summary||b.error||'').slice(0,60)}</span>
                </div>
                <div class="batch-detail-body" id="${bId}">
                  ${b.summary ? `<div style="color:var(--text);margin-bottom:.5rem">${b.summary}</div>` : ''}
                  ${b.error   ? `<div style="color:var(--red);margin-bottom:.5rem">⚠ ${b.error}</div>` : ''}
                  ${mal.length ? `<div style="font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:.4rem 0 .25rem">🚨 Malicious Activity</div>
                    ${mal.map((m,mi) => `<div class="mal-item"><span class="mal-num">#${mi+1}</span>${m}</div>`).join('')}`
                    : '<div style="font-size:.75rem;color:var(--green)">✓ No malicious activity</div>'}
                  ${(b.recommendations||[]).length ? `<div style="font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:.6rem 0 .25rem">Recommendations</div>
                    ${(b.recommendations||[]).map((r,ri) => `<div class="rec-item"><span class="rec-num">${ri+1}.</span><span>${r}</span></div>`).join('')}` : ''}
                  ${Object.keys(b.top_src_ips||{}).length ? `<div style="font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:.6rem 0 .25rem">Top Source IPs</div>
                    <table class="ip-t" style="width:100%"><thead><tr><th>IP</th><th>Packets</th></tr></thead><tbody>
                    ${Object.entries(b.top_src_ips).map(([ip,c]) => `<tr><td class="mono">${ip}</td><td><span class="cnt">${c}</span></td></tr>`).join('')}
                    </tbody></table>` : ''}
                </div>
              </div>`;
            }).join('')}
          </div>
        </div>`;
    });

    main.innerHTML = html;
  } catch(e) {
    main.innerHTML = `<div class="hist-empty" style="color:var(--red)">Error loading data: ${e.message}</div>`;
  }
}

function toggleBatch(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

function fmtDuration(s) {
  if (!s) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

/* ── SSE ──────────────────────────────────────────────────── */
let _sseDelay = 1000;   // exponential back-off delay (ms)

function connectSSE() {
  const status = document.getElementById('sseStatus');
  status.textContent = '● connecting…';
  status.style.color = 'var(--muted)';

  const es = new EventSource('/logs/stream');

  es.onopen = () => {
    _sseDelay = 1000;   // reset back-off on successful connect
    status.textContent = '● connected';
    status.style.color = 'var(--green)';
  };

  // Default message handler — SSE comment lines (': ping') never reach here,
  // so no filtering needed on the client side.
  es.onmessage = (e) => {
    appendLine(e.data);
  };

  es.onerror = () => {
    status.textContent = `● disconnected — retrying in ${Math.round(_sseDelay/1000)}s…`;
    status.style.color = 'var(--red)';
    es.close();
    setTimeout(connectSSE, _sseDelay);
    // Exponential back-off capped at 15 s
    _sseDelay = Math.min(_sseDelay * 1.5, 15000);
  };
}

/* ── Toast ────────────────────────────────────────────────── */
function toast(msg, err=false) {
  const area = document.getElementById('toastArea');
  const div  = document.createElement('div');
  div.className = 'toast';
  div.textContent = (err ? '✗ ' : '✓ ') + msg;
  div.style.borderColor = err ? 'var(--red)' : 'var(--green)';
  area.appendChild(div);
  requestAnimationFrame(() => div.classList.add('show'));
  setTimeout(() => { div.classList.remove('show'); setTimeout(() => div.remove(), 300); }, 3500);
}

/* ── Init ─────────────────────────────────────────────────── */
window.onload = () => {
  initCharts();
  loadInterfaces();
  refresh();
  setInterval(refresh, 5000);
  connectSSE();
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
    global latest_report, history, is_capturing, _tshark_ok, _session_start, _session_end
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
        models = ollama.list()
        return jsonify({"models": models.get('models', [])})
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
        "history":              hist
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
                total_pkts = sum(b["packet_count"] for s in sessions for b in s["batches"])
                total_mal  = sum(len(b.get("malicious", [])) for s in sessions for b in s["batches"])
                total_anom = sum(b.get("anomalies", 0) for s in sessions for b in s["batches"])
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