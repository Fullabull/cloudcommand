import json
import os
from pathlib import Path
import secrets
import time
from datetime import timedelta

from flask import session, redirect, render_template_string, Response, jsonify, send_file, request

from werkzeug.security import check_password_hash

PERSISTENT_ROOT = Path("/var/disk")
LOG_DIR = PERSISTENT_ROOT / "logs"
ADMIN_DIR = PERSISTENT_ROOT / "admin"

ADMIN_SECURITY_LOG = ADMIN_DIR / "security.log"
ADMIN_AUDIT_LOG = ADMIN_DIR / "audit.log"
BLOCKED_IPS_FILE = ADMIN_DIR / "blocked_ips.json"
MONITOR_STATE_FILE = ADMIN_DIR / "file_monitor_state.json"

OBSERVE_ALLOWED_DIRS = {
    "logs": LOG_DIR,
    "admin": ADMIN_DIR,
}

UA_GROUPS = {
    "search": (
        "googlebot",
        "googlebot-image",
        "google-inspectiontool",
        "bingbot",
        "duckduckbot",
        "baiduspider",
        "yandexbot",
    ),
    "preview": (
        "twitterbot",
        "linkedinbot",
        "slackbot",
        "facebookexternalhit",
    ),
    "seo": (
        "ahrefsbot",
        "semrushbot",
        "majesticbot",
    ),
    "monitoring": (
        "uptimerobot",
        "pingdom",
    ),
}

UA_GROUP_DESCRIPTIONS = {
    "search": {
        "name": "Search Engines",
        "description": "Search engine crawlers that index your site for search results.",
        "examples": ("Googlebot", "Googlebot-Image", "Google-InspectionTool", "bingbot", "DuckDuckBot", "Baiduspider", "YandexBot"),
        "warning": "Disabling this may prevent your site from appearing in search engines like Google and Bing."
    },
    "preview": {
        "name": "Social / Preview Bots",
        "description": "Bots used by social media and messaging platforms to generate link previews when your site is shared.",
        "examples": ("facebookexternalhit", "Twitterbot", "LinkedInBot", "Slackbot"),
        "warning": "Disabling this may prevent link previews from appearing when your site is shared."
    },
    "seo": {
        "name": "SEO Analysis Bots",
        "description": "Third-party tools that scan your site for SEO insights and competitive analysis.",
        "examples": ("AhrefsBot", "SemrushBot", "MajesticBot"),
        "warning": "Disabling this may block SEO tools that you or your marketing team rely on."
    },
    "monitoring": {
        "name": "Uptime Monitoring",
        "description": "Services that periodically check if your website is online and responding.",
        "examples": ("UptimeRobot", "Pingdom"),
        "warning": "Disabling this may prevent uptime monitoring alerts and hide outages."
    },
}

CONFIG = {
    "allow_search": True,
    "allow_preview": True,
    "allow_seo": False,
    "allow_monitoring": False,
}

BAD_UA = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "wpscan",
    "acunetix",
    "nessus",
    "openvas",
)

SIGNATURE_GROUPS = {
    "wordpress_php": (
        "wp-login.php",
        "/wp-admin",
        "/wp-includes",
        "/wp-content",
        "/wp-config.php",
        "/wp-json/wp/v2/users",
        "/wp-trackback.php",
        "/wp-signup.php",
        "/wp-cron.php",
        "/wp-content/debug.log",
        "/xmlrpc.php",
        "wlwmanifest.xml",
        "/phpmyadmin",
        "/pma",
        "/mysql",
        "/myadmin",
        "/adminer.php",
        "/adminer/",
        "/php-info.php",
        "/info.php",
        "/test.php",
    ),

    "config_credentials": (
        "/.env",
        ".env.",
        "/.env.local",
        "/.env.production",
        "/.env.backup",
        "/.env.staging",
        "/.env.dev",
        "/.git",
        "/.svn",
        "/.hg",
        "/.ssh/",
        "/id_rsa",
        "/server.key",
        "/private_key.pem",
        "docker-compose",
        "dockerfile",
        "web.config",
        ".htaccess",
        ".htpasswd",
        "config.php",
        "config.yml",
        "config.json",
        "database.yml",
        "database.php",
        "settings.py",
        "settings.php",
        "secrets.yml",
        "secrets.json",
        "credentials.json",
        "/credentials",
        "/secrets",
        "/.aws",
    ),

    "infrastructure": (
        "/server-status",
        "/server-info",
        "/nginx_status",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/dump",
        "/metrics",
        "/prometheus",
        "/grafana",
        "/solr",
        "/elasticsearch",
        "/_cat/",
        "/_cat/indices",
        "/jolokia/",
        "/heapdump",
        "/latest/meta-data",
        "/console",
        "/debug/",
        "/trace",
        "/v2/",
        "appsettings.json",
    ),

    "cms": (
        "/administrator/",
        "/sites/default/settings.php",
        "/typo3/",
        "/bitrix/",
        "/umbraco/",
        "/concrete/",
        "/app/etc/local.xml",
        "/downloader/",
    ),

    "webshells": (
        "shell.php",
        "cmd.php",
        "c99.php",
        "r57.php",
        "b374k.php",
        "webshell.php",
        "backdoor.php",
        "eval.php",
        "system.php",
        "exec.php",
        "upload.php",
        "filemanager.php",
        "webadmin.php",
    ),

    "basic_attack_patterns": (
        "/cgi-bin/",
        "test-cgi",
        "printenv",
        "%00",
        "/etc/passwd",
        "/etc/shadow",
    ),
    "device_router_iot": (
        "/boaform",
        "/hnap1",
    ),
}

TRAVERSAL_MARKERS = (
    "../",
    "%2e%2e/",
    "%2e%2e%2f",
)


ADMIN_USERNAME = None
ADMIN_PASSWORD_HASH = None
SESSION_MINUTES = 20

LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 900

CSRF_SESSION_KEY = "_cloudcmd_csrf"


def iter_signature_matches(target):
    target = (target or "").lower()

    for group, signatures in SIGNATURE_GROUPS.items():
        for sig in signatures:
            sig = sig.lower()
            if sig and sig in target:
                return group, sig

    return None, None


def init_app(app):

    global ADMIN_USERNAME, ADMIN_PASSWORD_HASH

    app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_MINUTES)

    ADMIN_USERNAME = os.environ.get("CLOUDCMD_ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD_HASH = os.environ["CLOUDCMD_ADMIN_PASSWORD_HASH"]

    ensure_admin_dirs()

def get_ip(req):
    xff = req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return xff or req.remote_addr or ""


def is_allowed_ua(ua):
    for group, sigs in UA_GROUPS.items():
        if any(sig in ua for sig in sigs):
            return CONFIG.get(f"allow_{group}", False)
    return None


def log_request(req):
    ip = get_ip(req)
    ua = req.headers.get("User-Agent", "").replace("\t", " ")
    line = f"{ip}\t{req.method}\t{req.path}\t{ua}"
    print(line)


def log_security_event(tag, req, detail=""):
    ip = get_ip(req)
    ua = req.headers.get("User-Agent", "").replace("\t", " ")
    path = req.path
    print(f"{tag}\t{ip}\t{req.method}\t{path}\t{detail}\t{ua}")


def is_locked(ip):
    rec = LOGIN_ATTEMPTS.get(ip)
    if not rec:
        return False
    return rec.get("locked_until", 0) > time.time()


def record_fail(ip):
    now = time.time()
    rec = LOGIN_ATTEMPTS.get(ip, {"count": 0, "locked_until": 0})

    if rec["locked_until"] > now:
        return

    rec["count"] += 1
    if rec["count"] >= MAX_ATTEMPTS:
        rec["locked_until"] = now + LOCKOUT_SECONDS
        rec["count"] = 0

    LOGIN_ATTEMPTS[ip] = rec


def clear_fail(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


def ensure_admin_dirs():
    PERSISTENT_ROOT.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ADMIN_DIR.mkdir(parents=True, exist_ok=True)


def load_monitor_state():
    if not MONITOR_STATE_FILE.exists():
        return {}

    try:
        with open(MONITOR_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    return data if isinstance(data, dict) else {}


def save_monitor_state(state):
    MONITOR_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(MONITOR_STATE_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def sort_observe_files(files, order):
    if order == "unix":
        files.sort(
            key=lambda x: (x["is_dir"], x["size"], x["mtime"], x["name"].lower()),
            reverse=True
        )
    else:
        files.sort(
            key=lambda x: (x["is_dir"], x["mtime"], x["size"], x["name"].lower()),
            reverse=True
        )
    return files


def is_admin():
    user = session.get("user")
    return bool(user and user.get("role") == "admin")


def new_csrf_token():
    token = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = token
    return token


def valid_csrf(form_token):
    sess_token = session.get(CSRF_SESSION_KEY, "")
    return bool(form_token and sess_token and secrets.compare_digest(form_token, sess_token))


def handle(req):

    ip = get_ip(req)

    if is_blocked_ip(ip):
        log_security_event("BLOCK_IP", req, ip)
        return "", 410

    path = req.path.lower()
    ua = req.headers.get("User-Agent", "").strip().lower()

    # 1) ADMIN FIRST
    # !!! NO NO NO: if path.startswith("/admin"): BAD BAD BAD !!!
    if path == "/admin" or path.startswith("/admin/"):
        result = handle_admin(req)
        if result is not None:
            return result

    # 2) EXISTING SECURITY LOGIC
    if not ua:
        log_security_event("BLOCK_EMPTY_UA", req)
        return "", 410

    allowed = is_allowed_ua(ua)
    if allowed is True:
        return None
    if allowed is False:
        log_security_event("BLOCK_UA_GROUP", req)
        return "", 410

    if any(sig in ua for sig in BAD_UA):
        log_security_event("BLOCK_BAD_UA", req)
        return "", 410

    if any(marker in path for marker in TRAVERSAL_MARKERS):
        log_security_event("BLOCK_TRAVERSAL", req)
        return "", 410

    query = req.query_string.decode(errors="replace").lower()
    target = path if not query else path + "?" + query

    sig_group, sig = iter_signature_matches(target)
    if sig:
        log_security_event("BLOCK_SIGNATURE", req, f"{sig_group}:{sig}")
        return "", 410

    return None


def handle_admin(req):
    path = req.path.lower()

    if path == "/admin/login":
        return admin_login(req)

    if path == "/admin/logout":
        session.clear()
        log_security_event("ADMIN_LOGOUT", req)
        return redirect("/admin/login")

    if not is_admin():
        session.clear()
        log_security_event("ADMIN_DENY", req)
        return redirect("/admin/login?expired=1")

    session.permanent = True

    if path == "/admin":
        return display_admin_panel()

    if path == "/admin/observe":
        return handle_admin_observe(req)

    if path == "/admin/read":
        return handle_admin_read(req)

    if path == "/admin/download":
        return handle_admin_download(req)

    if path == "/admin/block-ip" and req.method == "POST":
        form_token = req.form.get("csrf_token", "")
        if not valid_csrf(form_token):
            log_security_event("ADMIN_BAD_CSRF", req)
            return "", 400

        ip = req.form.get("ip", "").strip()
        if not ip:
            return "", 400

        # TODO: replace with your real blocklist write/update
        log_security_event("ADMIN_BLOCK_IP", req, ip)
        return redirect("/admin")

    return None

def display_admin_logged_in():
    user = session.get("user", {})
    username = user.get("username", "")
    role = user.get("role", "")

    return render_template_string(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login</title>
  <style>
    body {
      font-family: Arial, Helvetica, sans-serif;
      max-width: 420px;
      margin: 4rem auto;
      padding: 0 1rem;
      line-height: 1.4;
    }
    .card {
      border: 1px solid #ccc;
      padding: 1rem;
      border-radius: 8px;
    }
    .msg {
      margin-bottom: 1rem;
      padding: 0.75rem;
      border-radius: 6px;
      background: #eef5ff;
      border: 1px solid #99b8e8;
    }
    .row {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }
    button, a.btn {
      padding: 0.65rem 1rem;
      text-decoration: none;
      border: 1px solid #999;
      border-radius: 6px;
      background: #f5f5f5;
      color: #111;
      display: inline-block;
    }
    button[disabled] {
      opacity: 0.6;
      cursor: not-allowed;
    }
  </style>
</head>
<body>
  <h1>Admin Login</h1>

  <div class="card">
    <div class="msg">
      Already signed in as: <strong>{{ username }}</strong>{% if role and role != username %} - role: {{ role }}{% endif %}
    </div>

    <div class="row">
      <button type="button" disabled>Sign in</button>
      <a class="btn" href="/admin">Admin Panel</a>
      <a class="btn" href="/admin/logout">Log out</a>
    </div>
  </div>
</body>
</html>
        """,
        username=username,
        role=role,
    )

def admin_login(req):
    ip = get_ip(req)
    error = ""
    expired = req.args.get("expired") == "1"

    if is_admin():
        return display_admin_logged_in()

    if req.method == "POST":
        if is_locked(ip):
            error = "Too many attempts. Try later."
            log_security_event("ADMIN_LOGIN_LOCKED", req)
        else:
            username = req.form.get("username", "").strip()
            password = req.form.get("password", "")

            username_ok = secrets.compare_digest(username, ADMIN_USERNAME)
            password_ok = check_password_hash(ADMIN_PASSWORD_HASH, password)

            if username_ok and password_ok:
                clear_fail(ip)
                session.clear()
                session.permanent = True
                session["user"] = {
                    "username": ADMIN_USERNAME,
                    "role": "admin",
                }
                log_security_event("ADMIN_LOGIN_OK", req)
                return redirect("/admin")

            record_fail(ip)
            error = "Invalid credentials."
            log_security_event("ADMIN_LOGIN_FAIL", req)

    return display_admin_login(error, expired)


def display_admin_login(error, expired):
    return render_template_string(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login</title>
  <style>
    body {
      font-family: Arial, Helvetica, sans-serif;
      max-width: 420px;
      margin: 4rem auto;
      padding: 0 1rem;
      line-height: 1.4;
    }
    form {
      border: 1px solid #ccc;
      padding: 1rem;
      border-radius: 8px;
    }
    label {
      display: block;
      margin-top: 0.75rem;
      font-weight: bold;
    }
    input {
      width: 100%;
      padding: 0.55rem;
      margin-top: 0.25rem;
      box-sizing: border-box;
    }
    button {
      margin-top: 1rem;
      padding: 0.65rem 1rem;
      cursor: pointer;
    }
    .msg {
      margin-bottom: 1rem;
      padding: 0.75rem;
      border-radius: 6px;
    }
    .msg-error {
      background: #ffe8e8;
      border: 1px solid #d88;
    }
    .msg-info {
      background: #eef5ff;
      border: 1px solid #99b8e8;
    }
  </style>
</head>
<body>
  <h1>Admin Login</h1>

  {% if expired %}
    <div class="msg msg-info">Session expired. Please sign in again.</div>
  {% endif %}

  {% if error %}
    <div class="msg msg-error">{{ error }}</div>
  {% endif %}

  <form method="post" action="/admin/login" autocomplete="off">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" required autofocus>

    <label for="password">Password</label>
    <div style="display:flex; gap:0.5rem; align-items:stretch;">
      <input id="password" name="password" type="password" required style="flex:1;">
      <button type="button" id="togglePassword" style="height:100%;">Show</button>
    </div>

    <button type="submit">Sign in</button>
  </form>

  <script>
    (function () {
      const password = document.getElementById("password");
      const toggle = document.getElementById("togglePassword");
  
      if (!password || !toggle) return;
  
      toggle.addEventListener("click", function () {
        const showing = password.type === "text";
        password.type = showing ? "password" : "text";
        toggle.textContent = showing ? "Show" : "Hide";
      });
    })();
  </script>

</body>
</html>
        """,
        error=error,
        expired=expired,
    )


def display_admin_panel():
    csrf_token = new_csrf_token()

    return render_template_string(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel</title>
  <style>
    * { box-sizing: border-box; }

    body {
      font-family: Arial, Helvetica, sans-serif;
      margin: 1.5rem;
      line-height: 1.4;
      color: #111;
      background: #f6f6f6;
    }

    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .panel {
      border: 1px solid #ccc;
      border-radius: 8px;
      background: #fff;
      padding: 1rem;
      margin-bottom: 1rem;
    }

    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: end;
      margin-bottom: 1rem;
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }

    label {
      font-size: 13px;
      font-weight: bold;
    }

    input, select, button {
      font: inherit;
      padding: 0.5rem 0.65rem;
    }

    button {
      cursor: pointer;
    }

    .status {
      font-size: 14px;
      color: #444;
      margin-bottom: 0.75rem;
    }

    .error {
      color: #a40000;
      font-weight: bold;
      margin-top: 0.75rem;
    }

    .table-wrap {
      border: 1px solid #ccc;
      overflow: auto;
      background: #fff;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 760px;
    }

    th, td {
      text-align: left;
      padding: 0.65rem 0.8rem;
      border-bottom: 1px solid #e5e5e5;
      white-space: nowrap;
    }

    th {
      background: #f0f0f0;
      position: sticky;
      top: 0;
      z-index: 1;
    }

    td.name {
      white-space: normal;
      word-break: break-word;
    }

    .link-btn {
      background: none;
      border: none;
      color: #0645ad;
      text-decoration: underline;
      padding: 0;
      cursor: pointer;
      font: inherit;
    }

    .dir-btn {
      font-weight: bold;
    }

    .file-selected td {
      background: #dfefff !important;
    }

    .changed-row td {
      background: #fff6d6;
    }

    .viewer {
      margin-top: 1rem;
      border: 1px solid #ccc;
      background: #fff;
      padding: 0.75rem;
    }

    .viewer-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 0.75rem;
      border-bottom: 1px solid #ddd;
      padding-bottom: 0.5rem;
    }

    .viewer-title {
      font-weight: bold;
    }

    pre {
      margin: 0;
      white-space: pre;
      overflow-x: auto;
      overflow-y: auto;
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      max-height: 520px;
    }

    .muted {
      color: #666;
    }

    .clickable {
      cursor: pointer;
      text-decoration: underline;
    }

    .clickable:hover {
      color: #000;
    }

    .sus-line {
      display: block;
      background: #fff3cd;
      color: #7a4b00;
    }

    .sus-line-high {
      display: block;
      background: #fde2e2;
      color: #8a0000;
      font-weight: bold;
    }

    .sus-line-bot {
      display: block;
      background: #e8f3ff;
      color: #0b57d0;
    }

    .sus-key {
      font-weight: bold;
      text-decoration: underline;
    }

    .sus-current {
      outline: 2px solid #000;
      animation: susFlash 0.8s ease-out;
    }

    @keyframes susFlash {
      0%   { background-color: #ffff99; }
      100% { background-color: inherit; }
    }

    @keyframes susFlash {
      0%   { background-color: #b7e4c7; }
      100% { background-color: inherit; }
    }


    .viewer-head {
      position: sticky;
      top: 0;
      z-index: 2;
      background: #fff;
      padding-bottom: 0.5rem;
    }

  </style>
</head>
<body>
  <div class="topbar">
    <div>
      <strong>Admin Panel</strong><br>
      Signed in as: {{ user["username"] }}{% if user["role"] and user["role"] != user["username"] %} ({{ user["role"] }}){% endif %}
    </div>
    <div>
      <a href="/admin/logout">Log out</a>
    </div>
  </div>

  <div class="panel">
    <h2 style="margin-top:0;">Files</h2>

    <div class="toolbar">
      <div class="field">
        <label for="dirSelect">Directory</label>
        <select id="dirSelect">
          <option value="logs">logs</option>
          <option value="admin">admin</option>
        </select>
      </div>

      <div class="field">
        <label for="orderSelect">Order</label>
        <select id="orderSelect">
          <option value="windows">windows</option>
          <option value="unix">unix</option>
        </select>
      </div>

      <div class="field">
        <label for="refreshSelect">Auto Refresh</label>
        <select id="refreshSelect">
          <option value="0">off</option>
          <option value="5">5 sec</option>
          <option value="10" selected>10 sec</option>
          <option value="30">30 sec</option>
          <option value="60">60 sec</option>
        </select>
      </div>

      <div class="field">
        <button id="refreshBtn" type="button">Refresh</button>
      </div>

      <div class="field">
        <button id="closeFileBtn" type="button" style="display:none;">Close File</button>
      </div>

      <div class="field">
        <button id="downloadFileBtn" type="button" style="display:none;">Download File</button>
      </div>
    </div>

    <div id="status" class="status">Ready.</div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th id="col1">Date Modified</th>
            <th>Age</th>
            <th id="col2">Size</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>

    <div id="viewer" class="viewer" style="display:none;">

      <div class="viewer-head">
        <div>
          <div id="viewerTitle" class="viewer-title">File Viewer</div>
          <div class="muted clickable" id="viewerMeta"></div>
        </div>
  
        <form method="post" action="/admin/block-ip" style="display:flex; gap:8px; align-items:center; margin:0;">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <input id="blockIpInput" type="text" name="ip" placeholder="IP address" style="width:140px;">
          <button type="submit">Block</button>
        </form> 
  
        <div id="susControls" style="display:none; gap:8px; align-items:center;">
          <span style="font-size:12px; color:#666;">Level:</span>

          <select id="susLevelSelect">
            <option value="high" selected>High</option>
            <option value="medium">Medium</option>
            <option value="bot">Bot</option>
            <option value="any">Any</option>
          </select>

          <button id="findPrevSusBtn" type="button">Find Prev</button>
          <button id="findSusBtn" type="button">Find Next</button>

          <span id="susCounter" class="muted"></span>
        </div>
      </div>
      <pre id="viewerText"></pre>
    </div>

    <div id="error" class="error"></div>
  </div>

  <div class="panel">
    <h2 style="margin-top:0;">Block IP</h2>
    <form method="post" action="/admin/block-ip">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="text" name="ip" placeholder="IP address" required>
      <button type="submit">Block this IP</button>
    </form>
  </div>

  <script>
    (function () {
      console.log("admin panel script start");
      const dirSelect = document.getElementById("dirSelect");
      const orderSelect = document.getElementById("orderSelect");
      const refreshSelect = document.getElementById("refreshSelect");
      const refreshBtn = document.getElementById("refreshBtn");
      const closeFileBtn = document.getElementById("closeFileBtn");
      const downloadFileBtn = document.getElementById("downloadFileBtn");
      const rowsEl = document.getElementById("rows");
      const statusEl = document.getElementById("status");
      const errorEl = document.getElementById("error");
      const viewerEl = document.getElementById("viewer");
      const viewerTextEl = document.getElementById("viewerText");
      const viewerTitleEl = document.getElementById("viewerTitle");
      const viewerMetaEl = document.getElementById("viewerMeta");
      const col1El = document.getElementById("col1");
      const col2El = document.getElementById("col2");
      const findPrevSusBtn = document.getElementById("findPrevSusBtn");
      const susControls = document.getElementById("susControls");

      let newestFirst = true;
      let currentDir = "logs";
      let currentFileToken = null;
      let currentHighlightedEl = null;
      let fileViewActive = false;
      let refreshTimer = null;
      let susIndex = -1;

      function escapeHtml(value) {
        return String(value)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
      }

      function highlightCurrent(el) {
        // remove from previous
        if (currentHighlightedEl) {
          currentHighlightedEl.classList.remove("sus-current");
        }
      
        // force reflow so animation restarts
        el.classList.remove("sus-current");
        void el.offsetWidth;
        el.classList.add("sus-current");
      
        // store current
        currentHighlightedEl = el;
      }

      function getSusSelector() {
        const level = susLevelSelect.value;
      
        if (level === "high") return ".sus-line-high";
        if (level === "medium") return ".sus-line";
        if (level === "bot") return ".sus-line-bot";
      
        return ".sus-line-high, .sus-line, .sus-line-bot";
      }

      function getSuspiciousPattern(line) {
        const s = line.toLowerCase();
      
        const high = [
          "/wp-admin",
          "wp-login.php",
          "xmlrpc.php",
          "wlwmanifest.xml",
          "/.env",
          "/phpmyadmin",
          "/pma",
          "/mysql",
          "/myadmin",
          "/adminer.php",
          "/adminer/",
          "/cgi-bin/",
          "/boaform",
          "/hnap1",
          "/console",
          "/debug/",
          "/trace",
          "/v2/",
          "appsettings.json"
        ];
      
        const medium = [
          "/wp-",
          "/wordpress",
          "/blog/wp-",
          "/shop/wp-",
          "/site/wp-",
          "/test/wp-",
          "/web/wp-",
          "/cms/wp-"
        ];
      
        const knownBots = [
          "dotbot",
          "oai-searchbot",
          "censysinspect",
          "wordpress cms scanner"
        ];
      
        for (const pattern of high) {
          if (s.includes(pattern)) {
            return { level: "high", pattern: pattern };
          }
        }
      
        for (const pattern of medium) {
          if (s.includes(pattern)) {
            return { level: "medium", pattern: pattern };
          }
        }
      
        for (const pattern of knownBots) {
          if (s.includes(pattern)) {
            return { level: "bot", pattern: pattern };
          }
        }
      
        return null;
      }
      
      function renderViewerLines(lines) {
        return lines.map(line => {
          const hit = getSuspiciousPattern(line);
          const safeLine = escapeHtml(line);
      
          if (!hit) {
            return safeLine;
          }
      
          const safePattern = escapeHtml(hit.pattern);
          const highlighted = safeLine.replaceAll(
            safePattern,
            '<span class="sus-key">' + safePattern + '</span>'
          );
      
          if (hit.level === "high") {
            return '<span class="sus-line-high">' + highlighted + '</span>';
          }
      
          if (hit.level === "bot") {
            return '<span class="sus-line-bot">' + highlighted + '</span>';
          }
      
          return '<span class="sus-line">' + highlighted + '</span>';
        }).join("\\n");
      }

      function formatSize(bytes) {
        if (!bytes) return "";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
      }

      function formatMtime(epochSeconds) {
        return new Intl.DateTimeFormat("en-US", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false
        }).format(new Date(epochSeconds * 1000));
      }

      function updateHeaders() {
        if (orderSelect.value === "unix") {
          col1El.textContent = "Size";
          col2El.textContent = "Date Modified";
        } else {
          col1El.textContent = "Date Modified";
          col2El.textContent = "Size";
        }
      }

      function clearSelectedRow() {
        rowsEl.querySelectorAll(".file-selected").forEach(row => {
          row.classList.remove("file-selected");
        });
      }

      function parentToken(token) {
        const parts = String(token || "").split("/").filter(Boolean);
        if (parts.length <= 1) return parts[0] || "logs";
        parts.pop();
        return parts.join("/");
      }

      function applyRefreshTimer() {
        if (refreshTimer) {
          clearInterval(refreshTimer);
          refreshTimer = null;
        }

        if (fileViewActive) {
          return;
        }

        const seconds = parseInt(refreshSelect.value, 10);
        if (seconds > 0) {
          refreshTimer = setInterval(loadDirectory, seconds * 1000);
        }
      }

      function renderViewerLines(lines) {
        return lines.map(line => {
          const hit = getSuspiciousPattern(line);
          const safeLine = escapeHtml(line);

          if (!hit) {
            return safeLine;
          }

          const safePattern = escapeHtml(hit.pattern);
          const highlighted = safeLine.replaceAll(
            safePattern,
            '<span class="sus-key">' + safePattern + '</span>'
          );

          if (hit.level === "high") {
            return '<span class="sus-line-high">' + highlighted + '</span>';
          }

          if (hit.level === "bot") {
            return '<span class="sus-line-bot">' + highlighted + '</span>';
          }

          return '<span class="sus-line">' + highlighted + '</span>';
        }).join("\\n");
      }

      async function loadDirectory() {
        errorEl.textContent = "";
        rowsEl.innerHTML = "";
        statusEl.textContent = "Loading...";

        updateHeaders();

        const url =
          "/admin/observe?dir=" + encodeURIComponent(currentDir) +
          "&order=" + encodeURIComponent(orderSelect.value);

        try {
          const res = await fetch(url, { cache: "no-store" });
          if (!res.ok) {
            const text = await res.text();
            throw new Error(text || ("HTTP " + res.status));
          }

          const data = await res.json();
          renderRows(data.files || [], data.order || "windows");
          statusEl.textContent =
            "Directory: " + (data.dir || currentDir) +
            " - " + (data.files ? data.files.length : 0) + " item(s)";
        } catch (err) {
          statusEl.textContent = "Load failed.";
          errorEl.textContent = String(err.message || err);
        }
      }

      function renderRows(files, order) {
        rowsEl.innerHTML = "";

        const currentIsRoot = currentDir === "logs" || currentDir === "admin";

        if (!currentIsRoot) {
          const tr = document.createElement("tr");
          const upToken = parentToken(currentDir);

          tr.innerHTML =
            "<td></td><td></td><td></td>" +
            '<td class="name"><button class="link-btn dir-btn" data-dir="' + escapeHtml(upToken) + '">[..]</button></td>';

          rowsEl.appendChild(tr);
        }

        for (const file of files) {
          const tr = document.createElement("tr");
          const token = file.token;

          if (file.changed) {
            tr.classList.add("changed-row");
          }

          if (!file.is_dir && currentFileToken === token) {
            tr.classList.add("file-selected");
          }

          const nameHtml = file.is_dir
            ? '<button class="link-btn dir-btn" data-dir="' + escapeHtml(token) + '">[' + escapeHtml(file.name) + ']</button>'
            : '<button class="link-btn" data-file="' + escapeHtml(token) + '">' + escapeHtml(file.name) + '</button>';

          if (order === "unix") {
            tr.innerHTML =
              "<td>" + escapeHtml(formatSize(file.size || 0)) + "</td>" +
              "<td>" + escapeHtml(file.age_hms || "") + "</td>" +
              "<td>" + escapeHtml(formatMtime(file.mtime)) + "</td>" +
              '<td class="name">' + nameHtml + "</td>";
          } else {
            tr.innerHTML =
              "<td>" + escapeHtml(formatMtime(file.mtime)) + "</td>" +
              "<td>" + escapeHtml(file.age_hms || "") + "</td>" +
              "<td>" + escapeHtml(formatSize(file.size || 0)) + "</td>" +
              '<td class="name">' + nameHtml + "</td>";
          }

          rowsEl.appendChild(tr);
        }

        rowsEl.querySelectorAll("[data-dir]").forEach(btn => {
          btn.addEventListener("click", function () {
            currentDir = this.getAttribute("data-dir");
            currentFileToken = null;
            fileViewActive = false;
            viewerEl.style.display = "none";
            closeFileBtn.style.display = "none";
            downloadFileBtn.style.display = "none";
            clearSelectedRow();
            applyRefreshTimer();
            loadDirectory();
          });
        });

        rowsEl.querySelectorAll("[data-file]").forEach(btn => {
          btn.addEventListener("click", function () {
            clearSelectedRow();
            const tr = this.closest("tr");
            if (tr) {
              tr.classList.add("file-selected");
            }
            loadFile(this.getAttribute("data-file"));
          });
        });
      }

      function updateSuspiciousControls() {
        const hits = viewerTextEl.querySelectorAll(".sus-line-high, .sus-line, .sus-line-bot");
        const hasHits = hits.length > 0;
      
        susControls.style.display = hasHits ? "flex" : "none";
      }
      
      // findSuspicious(direction)
      // direction:  1 = next, -1 = previous
      function findSuspicious(direction) {
        const hits = viewerTextEl.querySelectorAll(getSusSelector());
      
        if (!hits.length) {
          return;
        }
      
        susIndex += direction;
      
        if (susIndex >= hits.length) {
          susIndex = 0;
        }
      
        if (susIndex < 0) {
          susIndex = hits.length - 1;
        }
      
        const el = hits[susIndex];
      
        el.scrollIntoView({
          behavior: "smooth",
          block: "center"
        });
      
        highlightCurrent(el);
      }

      async function loadFile(fileToken) {
        currentFileToken = fileToken;
        fileViewActive = true;
      
        if (refreshTimer) {
          clearInterval(refreshTimer);
          refreshTimer = null;
        }
      
        errorEl.textContent = "";
        viewerEl.style.display = "block";
        closeFileBtn.style.display = "inline-block";
        downloadFileBtn.style.display = "inline-block";
        viewerTitleEl.textContent = fileToken;
        viewerMetaEl.textContent = "Loading...";
        viewerTextEl.textContent = "";
      
        const url =
          "/admin/read?file=" + encodeURIComponent(fileToken);
      
        try {
          const res = await fetch(url, { cache: "no-store" });
          if (!res.ok) {
            const text = await res.text();
            throw new Error(text || ("HTTP " + res.status));
          }
      
          const text = await res.text();
          let lines = text.split("\\n");
      
          if (newestFirst) {
            lines = lines.reverse();
          }
      
          viewerTextEl.innerHTML = renderViewerLines(lines);
          susIndex = -1;
          updateSuspiciousControls();

          viewerMetaEl.textContent = newestFirst ? "Displaying newest first (click to reverse)" : "Displaying oldest first (click to reverse)";
          const yOffset = -80;
          const y = viewerEl.getBoundingClientRect().top + window.pageYOffset + yOffset;
      
          window.scrollTo({
            top: y,
            behavior: "smooth"
          });
      
        } catch (err) {
          viewerTextEl.textContent = "";
          viewerMetaEl.textContent = "";
          errorEl.textContent = String(err.message || err);
        }
      }

      findPrevSusBtn.addEventListener("click", function () {
        findSuspicious(-1);
      });
      
      findSusBtn.addEventListener("click", function () {
        findSuspicious(1);
      });     
      
      susLevelSelect.addEventListener("change", function () {
        susIndex = -1;
      });

      refreshBtn.addEventListener("click", function () {
        if (fileViewActive && currentFileToken) {
          loadFile(currentFileToken);
        } else {
          loadDirectory();
        }
      });

      closeFileBtn.addEventListener("click", function () {
        viewerEl.style.display = "none";
        closeFileBtn.style.display = "none";
        downloadFileBtn.style.display = "none";
        currentFileToken = null;
        currentHighlightedEl = null;
        fileViewActive = false;
        clearSelectedRow();
        susControls.style.display = "none";
        susIndex = -1;

        applyRefreshTimer();
      });

      downloadFileBtn.addEventListener("click", function () {
        if (!currentFileToken) {
          return;
        }

        const url =
          "/admin/download?file=" + encodeURIComponent(currentFileToken);

        window.location.href = url;
      });

      dirSelect.addEventListener("change", function () {
        currentDir = dirSelect.value;
        currentFileToken = null;
        fileViewActive = false;
        viewerEl.style.display = "none";
        closeFileBtn.style.display = "none";
        downloadFileBtn.style.display = "none";
        clearSelectedRow();
        applyRefreshTimer();
        loadDirectory();
      });

      orderSelect.addEventListener("change", function () {
        loadDirectory();
      });

      refreshSelect.addEventListener("change", function () {
        applyRefreshTimer();
      });

      viewerMetaEl.addEventListener("click", function () {
        newestFirst = !newestFirst;
  
        if (currentFileToken) {
          loadFile(currentFileToken);
        }
      });

      (function () {
        const IDLE_LIMIT_MS = 20 * 60 * 1000;
        let timer = null;

        function kickOut() {
          window.location.replace("/admin/logout");
        }

        function resetTimer() {
          if (timer) clearTimeout(timer);
          timer = setTimeout(kickOut, IDLE_LIMIT_MS);
        }

        ["mousemove", "mousedown", "keydown", "scroll", "touchstart", "click"].forEach(function (evt) {
          window.addEventListener(evt, resetTimer, { passive: true });
        });

        resetTimer();
      })();

      updateHeaders();
      applyRefreshTimer();
      loadDirectory();
    })();
  </script>
</body>
</html>
        """,
        user=session["user"],
        csrf_token=csrf_token,
    )

def append_line(path_obj, line):
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    with open(path_obj, "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")


def log_audit_event(tag, req, detail=""):
    ip = get_ip(req)
    user = session.get("user", {}).get("username", "")
    path = req.path
    line = f"{tag}\t{ip}\t{user}\t{req.method}\t{path}\t{detail}"
    print(line)
    append_line(ADMIN_AUDIT_LOG, line)


def load_blocked_ips():
    if not BLOCKED_IPS_FILE.exists():
        return []

    try:
        with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    if not isinstance(data, list):
        return []

    return [str(x).strip() for x in data if str(x).strip()]


def save_blocked_ips(items):
    BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    clean = sorted(set(str(x).strip() for x in items if str(x).strip()))
    with open(BLOCKED_IPS_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(clean, f, indent=2)


def is_blocked_ip(ip):
    if not ip:
        return False
    return ip in load_blocked_ips()


def safe_dir_path(raw_dir):
    raw_dir = (raw_dir or "").strip().replace("\\", "/")
    if not raw_dir:
        return "logs", LOG_DIR

    parts = [p for p in raw_dir.split("/") if p not in ("", ".")]
    if not parts:
        return "logs", LOG_DIR

    root_key = parts[0].lower()
    base = OBSERVE_ALLOWED_DIRS.get(root_key)
    if base is None:
        return "logs", LOG_DIR

    candidate = base
    for piece in parts[1:]:
        if piece == "..":
            return root_key, base
        candidate = candidate / piece

    try:
        candidate = candidate.resolve()
        candidate.relative_to(base.resolve())
    except Exception:
        return root_key, base

    return "/".join([root_key] + parts[1:]), candidate


def safe_file_path(raw_file):
    raw_file = (raw_file or "").strip().replace("\\", "/")
    if not raw_file:
        return None

    parts = [p for p in raw_file.split("/") if p not in ("", ".")]
    if not parts:
        return None

    root_key = parts[0].lower()
    base = OBSERVE_ALLOWED_DIRS.get(root_key)
    if base is None:
        return None

    candidate = base
    for piece in parts[1:]:
        if piece == "..":
            return None
        candidate = candidate / piece

    try:
        candidate = candidate.resolve()
        candidate.relative_to(base.resolve())
    except Exception:
        return None

    return candidate


def format_age_hms(epoch_seconds):
    age = max(0, int(time.time() - epoch_seconds))
    h = age // 3600
    m = (age % 3600) // 60
    s = age % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def list_directory(root_key, dir_path, order):
    files = []
    state = load_monitor_state()

    base = OBSERVE_ALLOWED_DIRS[root_key].resolve()

    try:
        rel_dir = str(dir_path.resolve().relative_to(base)).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
    except Exception:
        rel_dir = ""

    prefix = root_key if not rel_dir else f"{root_key}/{rel_dir}"

    for entry in dir_path.iterdir():
        try:
            stat = entry.stat()
        except OSError:
            continue

        token = f"{prefix}/{entry.name}"
        prev = state.get(token)

        changed = False
        if prev is not None:
            changed = (
                int(prev.get("mtime", 0)) != int(stat.st_mtime)
                or int(prev.get("size", 0)) != (0 if entry.is_dir() else int(stat.st_size))
            )

        row = {
            "name": entry.name,
            "token": token.replace("\\", "/"),
            "is_dir": entry.is_dir(),
            "size": 0 if entry.is_dir() else stat.st_size,
            "mtime": stat.st_mtime,
            "age_hms": format_age_hms(stat.st_mtime),
            "changed": changed,
        }
        files.append(row)

        state[row["token"]] = {
            "mtime": int(stat.st_mtime),
            "size": row["size"],
        }

    save_monitor_state(state)
    sort_observe_files(files, order)
    return files


def handle_admin_observe(req):
    dir_key, dir_path = safe_dir_path(req.args.get("dir", "logs"))
    order = (req.args.get("order", "windows") or "windows").strip().lower()

    if order not in ("windows", "unix"):
        order = "windows"

    if not dir_path.exists() or not dir_path.is_dir():
        return jsonify({
            "dir": dir_key,
            "files": [],
            "order": order,
        })

    files = list_directory(dir_key.split("/")[0], dir_path, order)
    log_audit_event("ADMIN_OBSERVE", req, dir_key)

    return jsonify({
        "dir": dir_key,
        "files": files,
        "order": order,
    })


def handle_admin_read(req):
    file_arg = req.args.get("file", "")
    path_obj = safe_file_path(file_arg)

    if not path_obj or not path_obj.exists() or path_obj.is_dir():
        return Response("File not found", status=404, mimetype="text/plain")

    try:
        text = path_obj.read_text(encoding="utf-8", errors="replace")
    except Exception as ex:
        return Response(str(ex), status=500, mimetype="text/plain")

    log_audit_event("ADMIN_READ", req, file_arg)
    return Response(text, mimetype="text/plain")


def handle_admin_download(req):
    file_arg = req.args.get("file", "")
    path_obj = safe_file_path(file_arg)

    if not path_obj or not path_obj.exists() or path_obj.is_dir():
        return Response("File not found", status=404, mimetype="text/plain")

    log_audit_event("ADMIN_DOWNLOAD", req, file_arg)
    return send_file(path_obj, as_attachment=True, download_name=path_obj.name)
