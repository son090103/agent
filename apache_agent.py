#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apache Configuration & Environment Collector (auto-path + extra scans)

- Auto-detect Apache config root (APACHE_ROOT env or possible paths)
- Collect:
  - modules (LoadModule)
  - includes (Include / IncludeOptional)
  - directives (common ones)
  - <Directory> blocks
  - envvars (/etc/apache2/envvars)
  - document roots (DocumentRoot)
  - runtime paths (pid, lock, scoreboard, core dump)
  - SSL cert/key file paths referenced in config (SSLCertificateFile, SSLCertificateKeyFile)
  - system user info (apache user from envvars, /etc/passwd, /etc/shadow if readable)
  - extra scans: /var/www, /var/log/apache2, /var/run/apache2, /etc/ssl, /etc/pki
  - permissions summary for scanned directories
- Output: JSON (structured facts only, no policy logic)
"""

from pathlib import Path
import os
import re
import json
import stat
import pwd
import grp
import itertools
import subprocess
import re
from datetime import datetime, timedelta
import argparse
import paramiko
import tempfile

# ----------------------------
# Config: detection paths
# ----------------------------
POSSIBLE_PATHS = [
    "/etc/apache2",                 # Debian/Ubuntu
    "/usr/local/apache2/conf",      # compiled from source (default)
    "/usr/local/etc/apache2",
    "/etc/httpd",                   # CentOS/RHEL layout (may contain conf)
    "/usr/pkg/etc/httpd",
    "/opt/apache2/conf",
    "/Applications/MAMP/conf/apache" # macOS MAMP
]

# Extra system paths to scan (if exist) — used for rules in 3.x and 7.x etc.
EXTRA_PATHS = [
    "/var/www",             # document roots
    "/var/log/apache2",     # logs (Debian)
    "/var/log/httpd",       # logs (CentOS)
    "/var/run/apache2",     # pid, scoreboard, runtime dir (Debian)
    "/var/run",             # fallback
    "/var/lock/apache2",    # lock dir
    "/run/apache2",         # runtime dir
    "/etc/ssl",             # SSL certs (common)
    "/etc/pki/tls",         # SSL certs (RHEL/CentOS)
    "/etc/logrotate.d",     # logrotate conf (check for apache2)
    "/home",                # possible userdir content
    "/usr/lib/cgi-bin",             # default CGI dir (Debian/Ubuntu)
    "/usr/local/apache2/cgi-bin",   # CGI dir (compiled from source)
    "/var/www/cgi-bin",             # possible CGI dir (legacy)

]

# Give control via envvar
APACHE_ROOT = os.environ.get("APACHE_ROOT")
if not APACHE_ROOT:
    for p in POSSIBLE_PATHS:
        if os.path.isdir(p):
            APACHE_ROOT = p
            break

if not APACHE_ROOT:
    print(json.dumps({"error": "Apache config root not found. Set APACHE_ROOT or mount a path."}))
    raise SystemExit(1)

# ----------------------------
# Helpers
# ----------------------------
def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def list_conf_files(root: str):
    rootp = Path(root)
    files = []
    for p in rootp.rglob("*"):
        if (p.is_file() or p.is_symlink()) and (p.suffix in (".conf", ".load", ".cnf") or p.name in ("envvars",)):
            files.append(str(p))
    return sorted(files)

def parse_loadmodules_from_text(text):
    mods = []
    for line in text.splitlines():
        m = re.match(r'^\s*LoadModule\s+(\S+)\s+(\S+)', line, re.IGNORECASE)
        if m:
            mods.append({"name": m.group(1), "path": m.group(2), "line": line.strip()})
    return mods

def parse_includes_from_text(text):
    incs = []
    for m in re.finditer(r'^\s*Include(?:Optional)?\s+(.+)$', text, re.IGNORECASE | re.MULTILINE):
        raw = m.group(1).strip().strip('"').strip("'")
        incs.append(raw)
    return incs

def parse_directives_from_text(text, patterns):
    directives = {}
    for p in patterns:
        vals = []
        for line in text.splitlines():
            if re.match(r'^\s*#', line):
                continue
            m = re.search(rf'(?i)^\s*{re.escape(p)}\b\s+(.+)$', line)
            if m:
                value = m.group(1).strip() if m.group(1) else ""
                vals.append(value)
        if vals:
            directives[p] = vals if len(vals) > 1 else vals[0]
    return directives

def parse_directory_blocks_from_text(text):
    blocks = []

    # Parse <Directory> blocks
    for m in re.finditer(r'(?is)<Directory\s+["\']?([^>"]+)["\']?>\s*(.*?)</Directory>', text):
        path = m.group(1).strip().strip('"').strip("'")
        body = m.group(2)
        options = re.findall(r'^\s*Options\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        allow = re.findall(r'^\s*AllowOverride\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        require = re.findall(r'^\s*Require\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        blocks.append({
            "type": "Directory",
            "path": path,
            "options": options,
            "allow_override": allow,
            "require": require
        })

    # ✅ Parse <DirectoryMatch> blocks (multi-line safe)
    for m in re.finditer(r'(?is)<DirectoryMatch\b[^>]*?["\']([^"\']+)["\'][^>]*>\s*(.*?)</DirectoryMatch>', text):
        pattern = m.group(1).strip()
        body = m.group(2)
        options = re.findall(r'^\s*Options\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        allow = re.findall(r'^\s*AllowOverride\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        require = re.findall(r'^\s*Require\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        deny = re.findall(r'^\s*Deny\s+from\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        blocks.append({
            "type": "DirectoryMatch",
            "pattern": pattern,
            "options": options,
            "allow_override": allow,
            "require": require,
            "deny": deny
        })

    return blocks

def parse_filesmatch_blocks_from_text(text):
    """
    Parse <FilesMatch> blocks from Apache configuration text.
    Extracts the regex pattern and any Require/Deny rules inside.
    """
    blocks = []
    # Match <FilesMatch "regex"> ... </FilesMatch>, case-insensitive, multi-line
    for m in re.finditer(r'(?is)<FilesMatch\s+["\']?([^>"]+)["\']?>\s*(.*?)</FilesMatch>', text):
        pattern = m.group(1).strip().strip('"').strip("'")
        body = m.group(2)
        require = re.findall(r'^\s*Require\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        deny = re.findall(r'^\s*Deny\s+from\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        blocks.append({
            "pattern": pattern,
            "require": require,
            "deny": deny
        })
    return blocks

def extract_directive_values(text, name):
    vals = []
    for line in text.splitlines():
        m = re.match(rf'^\s*{re.escape(name)}\s+(.+)$', line, re.IGNORECASE)
        if m:
            vals.append(m.group(1).strip().strip('"').strip("'"))
    return vals

def stat_summary(path):
    try:
        summary = {"exists": path.exists()}
        if summary["exists"]:
            try:
                st = path.stat()
                summary.update({
                    "size": st.st_size,
                    "owner": st.st_uid,
                    "group": st.st_gid,
                    "mode": oct(st.st_mode & 0o777),
                    "readable": True
                })
            except PermissionError:
                summary.update({"readable": False, "error": "Permission denied"})
        return summary
    except Exception as e:
        return {"exists": False, "error": str(e)}

def scan_directory_listing(path: Path, limit=50):
    out = {"exists": path.exists(), "total_entries": 0, "sample": []}
    if not path.exists() or not path.is_dir():
        return out
    try:
        entries = list(path.iterdir())
        out["total_entries"] = len(entries)
        sample = []
        for e in entries[:limit]:
            try:
                st = e.stat()
                sample.append({
                    "name": e.name,
                    "is_dir": e.is_dir(),
                    "is_file": e.is_file(),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mode": oct(stat.S_IMODE(st.st_mode))
                })
            except Exception:
                sample.append({"name": e.name, "error": "stat_failed"})
        out["sample"] = sample
    except Exception as ex:
        out["error"] = str(ex)
    return out

def read_passwd(username):
    try:
        with open("/etc/passwd", "r", encoding="utf-8") as f:
            for l in f:
                if l.startswith(username + ":"):
                    parts = l.strip().split(":")
                    return {"user": parts[0], "uid": int(parts[2]), "gid": int(parts[3]), "gecos": parts[4], "home": parts[5], "shell": parts[6]}
    except Exception:
        return None

def read_shadow(username):
    try:
        with open("/etc/shadow", "r", encoding="utf-8") as f:
            for l in f:
                if l.startswith(username + ":"):
                    parts = l.strip().split(":")
                    return {"user": parts[0], "passwd_field": parts[1]}
    except Exception:
        return None

def uniq_by_key(seq, key):
    seen = set()
    out = []
    for item in seq:
        k = item.get(key)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out

def merge_directives(dst, src):
    """Gộp directive từ nhiều file, tránh ghi đè hoặc trùng lặp."""
    for k, v in src.items():
        if v is None:
            continue
        if isinstance(v, list):
            dst.setdefault(k, [])
            for item in v:
                item = item.strip()
                if item not in dst[k]:
                    dst[k].append(item)
        else:
            dst.setdefault(k, v.strip() if isinstance(v, str) else v)

# ----------------------------
# Collector
# ----------------------------
def collect(apache_root):
    import os, re, pwd
    from pathlib import Path

    root = Path(apache_root)
    conf_files = list_conf_files(apache_root)

    report = {
        "apache_root": apache_root,
        "files_scanned": len(conf_files),
        "files": conf_files,
        "modules": [],
        "includes": [],
        "directives": {},
        "directory_blocks": [],
        "filesmatch_blocks": [],
        "directorymatch_blocks": [],
        "locationmatch_blocks": [],
        "envvars": {},
        "document_roots": [],
        "runtime": {},
        "ssl": {"certs": [], "keys": []},
        "users": {},
        "permissions_summary": {},
        "extra_scans": {}
    }

    # small helper: smart merge k->v (str or list) into dict
    def _merge_kv(d, k, v):
        if v is None:
            return
        if k not in d:
            d[k] = v
            return
        cur = d[k]
        if isinstance(cur, list):
            if isinstance(v, list):
                cur.extend(v)
            else:
                cur.append(v)
            d[k] = cur
        else:
            if cur == v:
                return
            d[k] = [cur] + (v if isinstance(v, list) else [v])

    # read all text combined (for global searches)
    all_text = ""
    for fp in conf_files:
        txt = read_text(Path(fp))
        if not isinstance(txt, str):
            txt = ""
        all_text += "\n" + txt

        # modules / includes / blocks (Directory, FilesMatch, DirectoryMatch, LocationMatch)
        report["modules"].extend(parse_loadmodules_from_text(txt))
        report["includes"].extend(parse_includes_from_text(txt))
        report["directory_blocks"].extend(parse_directory_blocks_from_text(txt))
        # existing helper
        report["filesmatch_blocks"].extend(parse_filesmatch_blocks_from_text(txt))

        # add DirectoryMatch / LocationMatch quick parsers (regex, ignore commented)
        dir_match = re.findall(
            r'(?is)^[ \t]*<DirectoryMatch\s+"([^"]+)">\s*(.*?)\s*</DirectoryMatch>',
            txt, flags=re.MULTILINE
        )
        for pattern, body in dir_match:
            report["directorymatch_blocks"].append({"pattern": pattern.strip(), "body": body.strip()})

        loc_match = re.findall(
            r'(?is)^[ \t]*<LocationMatch\s+"([^"]+)">\s*(.*?)\s*</LocationMatch>',
            txt, flags=re.MULTILINE
        )
        for pattern, body in loc_match:
            report["locationmatch_blocks"].append({"pattern": pattern.strip(), "body": body.strip()})

        # --- collect directives incrementally (key=value-ish) ---
        directives = parse_directives_from_text(txt, [
            "ServerTokens", "ServerSignature", "Timeout", "KeepAlive",
            "MaxKeepAliveRequests", "KeepAliveTimeout", "LogLevel",
            "User", "Group", "ErrorLog", "PidFile", "ScoreBoardFile",
            "AccessFileName", "HostnameLookups", "CoreDumpDirectory",
            "SSLCertificateFile", "SSLCertificateKeyFile", "SSLHonorCipherOrder", "SSLProtocol",
            "SSLCipherSuite", "TraceEnable", "LogFormat", "CustomLog",
            "DocumentRoot", "Redirect"
        ])

        # --- Rewrite family (ignore commented lines) ---
        rewrite_engines = re.findall(r'(?im)^[ \t]*RewriteEngine\s+(on|off)\b', txt)
        rewrite_conds = re.findall(r'(?im)^[ \t]*RewriteCond\s+.*$', txt)
        rewrite_rules = re.findall(r'(?im)^[ \t]*RewriteRule\s+.*$', txt)

        if rewrite_engines:
            directives["RewriteEngine"] = [f"RewriteEngine {x.strip()}" for x in rewrite_engines]
        if rewrite_conds:
            directives["RewriteCond"] = [r.strip() for r in rewrite_conds]
        if rewrite_rules:
            directives["RewriteRule"] = [r.strip() for r in rewrite_rules]

        # merge into report["directives"]
        for k, v in directives.items():
            _merge_kv(report["directives"], k, v)

    # de-dup & normalize
    report["modules"] = uniq_by_key(report["modules"], "name")
    report["includes"] = sorted(set(report["includes"]))
    # keep blocks as-is; callers may rely on order
    # filesmatch already parsed above; directorymatch/locationmatch added too

    # --- envvars: accept 'export VAR=...', 'VAR=...' (quotes optional), ignore comments ---
    envvars_path = root / "envvars"
    if envvars_path.exists():
        for line in read_text(envvars_path).splitlines():
            if line.strip().startswith("#"):
                continue
            m = re.match(r'^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*"?([^"#\r\n]+?)"?\s*(?:#.*)?$', line)
            if m:
                report["envvars"][m.group(1)] = m.group(2).strip()

    # --- document roots (global + per VirtualHost) ---
    docroots = set()
    docroots.update(extract_directive_values(all_text, "DocumentRoot"))
    for m in re.finditer(r'(?is)<VirtualHost\b[^>]*>(.*?)</VirtualHost>', all_text):
        body = m.group(1)
        docroots.update(extract_directive_values(body, "DocumentRoot"))
    report["document_roots"] = sorted({expand_path(p, report["envvars"]) for p in docroots if p})

    # --- runtime / pid / scoreboard / core / lock dirs ---
    pidfiles = []
    pidfiles.extend(extract_directive_values(all_text, "PidFile"))
    if "APACHE_PID_FILE" in report["envvars"]:
        pidfiles.append(report["envvars"]["APACHE_PID_FILE"])
    report["runtime"]["pid_files"] = [p for p in pidfiles if p]

    report["runtime"]["scoreboard_files"] = extract_directive_values(all_text, "ScoreBoardFile")

    coredirs = extract_directive_values(all_text, "CoreDumpDirectory")
    if "APACHE_RUN_DIR" in report["envvars"]:
        coredirs.append(report["envvars"]["APACHE_RUN_DIR"])
    coredirs = [p for p in coredirs if p]
    report["runtime"]["core_directories"] = coredirs

    # enrich extra_scans with runtime dirs
    if "extra_scans" not in report:
        report["extra_scans"] = {}
    for core_dir in report["runtime"]["core_directories"]:
        expanded = expand_path(core_dir, report["envvars"])
        p = Path(expanded)
        report["extra_scans"][expanded] = {
            "exists": p.exists(),
            "stat": stat_summary(p),
            "listing": scan_directory_listing(p, limit=20) if p.is_dir() else None
        }

    # lock dir from envvars if present
    lockdirs = []
    if "APACHE_LOCK_DIR" in report["envvars"]:
        lockdirs.append(report["envvars"]["APACHE_LOCK_DIR"])
    report["runtime"]["lock_directories"] = lockdirs

    # --- SSL cert/key list from collected directives (expand paths & stat) ---
    ssl_certs, ssl_keys = [], []
    def _to_list(v):
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    for c in _to_list(report["directives"].get("SSLCertificateFile")):
        ssl_certs.append(c)
    for k in _to_list(report["directives"].get("SSLCertificateKeyFile")):
        ssl_keys.append(k)

    report["ssl"]["certs"] = []
    for c in ssl_certs:
        path_str = expand_path(c, report["envvars"])
        p = Path(path_str) if os.path.isabs(path_str) else (Path(apache_root) / path_str)
        report["ssl"]["certs"].append({"path": str(p), **stat_summary(p)})

    report["ssl"]["keys"] = []
    for k in ssl_keys:
        path_str = expand_path(k, report["envvars"])
        p = Path(path_str) if os.path.isabs(path_str) else (Path(apache_root) / path_str)
        report["ssl"]["keys"].append({"path": str(p), **stat_summary(p)})

    # --- user info (apache user) ---
    apache_user = None
    if "APACHE_RUN_USER" in report["envvars"]:
        apache_user = report["envvars"]["APACHE_RUN_USER"]
    else:
        for guess in ("www-data", "apache", "httpd", "www"):
            try:
                pwd.getpwnam(guess)
                apache_user = guess
                break
            except KeyError:
                continue
    report["users"]["apache_user_guess"] = apache_user
    if apache_user:
        passwd_info = read_passwd(apache_user)
        shadow_info = read_shadow(apache_user)
        report["users"]["apache_user_passwd"] = passwd_info
        if shadow_info is not None and isinstance(shadow_info, dict):
            pwfield = shadow_info.get("passwd_field", "")
            report["users"]["apache_user_shadow"] = {"locked": pwfield.startswith(("!", "*"))}
        else:
            report["users"]["apache_user_shadow"] = {"available": False}
            # --- Bổ sung chi tiết trạng thái mật khẩu (cho CIS-APACHE-2.4-3.3) ---
        try:
            system_users = {}
            with open("/etc/shadow", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        username, pwstatus = parts[0], parts[1]
                        system_users[username] = {"password_status": pwstatus}
            report["system_users"] = system_users
        except PermissionError:
            report["system_users"] = {
                "error": "Permission denied reading /etc/shadow (run as root)"
            }
        except Exception as e:
            report["system_users"] = {"error": str(e)}

    # --- permissions summary for apache_root ---
    report["permissions_summary"] = summarize_permissions_dir(Path(apache_root))

    # --- scan extra paths (EXTRA_PATHS + document_roots) ---
    extra = {}
    for pth in EXTRA_PATHS:
        try:
            pathp = Path(pth)
            extra[pth] = {
                "exists": pathp.exists(),
                "stat": stat_summary(pathp),
                "listing": scan_directory_listing(pathp, limit=40) if pathp.is_dir() else None
            }
        except Exception as ex:
            extra[pth] = {"error": str(ex)}

    for dr in report["document_roots"]:
        dp = Path(dr)
        if dr not in extra:
            extra[dr] = {
                "exists": dp.exists(),
                "stat": stat_summary(dp),
                "listing": scan_directory_listing(dp, limit=40) if dp.is_dir() else None
            }
    report["extra_scans"] = extra

    # --- runtime file stats (resolved) ---
    runtime_checks = {}
    for k, arr in (
        ("pid_files", report["runtime"].get("pid_files", [])),
        ("scoreboard_files", report["runtime"].get("scoreboard_files", [])),
        ("core_directories", report["runtime"].get("core_directories", [])),
        ("lock_directories", report["runtime"].get("lock_directories", [])),
    ):
        runtime_checks[k] = []
        for path in arr:
            expanded = expand_path(path, report["envvars"])
            p = Path(expanded)
            runtime_checks[k].append({"path": expanded, **stat_summary(p)})
    report["runtime"]["resolved"] = runtime_checks

    # --- logrotate check for apache: existence + parse rotate value ---
    lr_path = Path("/etc/logrotate.d")
    report["logrotate_apache"] = False
    report["logrotate_rotate"] = None
    report["logrotate_schedule"] = None  # daily/weekly if detected

    if lr_path.exists():
        # prefer exact apache2; fallback for apache/httpd
        candidates = [p for p in lr_path.glob("apache2")] or \
                     [p for p in lr_path.glob("apache*")] or \
                     [p for p in lr_path.glob("httpd")] or []
        if candidates:
            report["logrotate_apache"] = True
            try:
                content = read_text(candidates[0])
                m_rot = re.search(r'(?mi)^\s*rotate\s+(\d+)\b', content)
                if m_rot:
                    report["logrotate_rotate"] = int(m_rot.group(1))
                m_sched = re.search(r'(?mi)^\s*(daily|weekly|monthly|yearly)\b', content)
                if m_sched:
                    report["logrotate_schedule"] = m_sched.group(1).lower()
            except Exception as e:
                report["logrotate_error"] = str(e)
    
    try:
        version_output = subprocess.getoutput("apache2 -v")
        match = re.search(r"Server version:\s*Apache/([\d.]+)", version_output)
        if match:
            report["apache_version"] = match.group(1)
        else:
            report["apache_version"] = None
    except Exception as e:
        report["apache_version"] = None

    # Xác định nguồn cài đặt (vendor hay source)
    if os.path.exists("/etc/apache2"):
        report["apache_install_source"] = "vendor"
    elif os.path.exists("/usr/local/apache2"):
        report["apache_install_source"] = "source"
    else:
        report["apache_install_source"] = "unknown"

        # --- SSL.conf parsing (any OS layout) ---
    def parse_ssl_conf_auto():
        """
        Parse ssl.conf and return only on/off status for SSL-related directives.
        Ignores descriptions, comments, and unrelated lines.
        """
        candidate_paths = [
            Path(apache_root) / "mods-available" / "ssl.conf",
            Path(apache_root) / "conf.d" / "ssl.conf",
            Path(apache_root) / "extra" / "httpd-ssl.conf",
            Path("/usr/local/apache2/conf/extra/httpd-ssl.conf"),
            Path("/etc/httpd/conf.d/ssl.conf"),
        ]

        target = None
        for c in candidate_paths:
            if c.exists():
                target = c
                break
        if not target:
            return {"status": "not_found"}

        result = {}
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    # bỏ dòng trống hoặc chỉ có khoảng trắng
                    if not raw_line.strip():
                        continue

                    # xác định comment
                    is_comment = bool(re.match(r'^\s*#\s*[A-Za-z_]+', raw_line))
                    clean_line = re.sub(r'^\s*#', '', raw_line).strip()

                    # bỏ mô tả, hướng dẫn, tiêu đề section (<IfModule>, ##, vim:)
                    if not clean_line or clean_line.startswith(("<", "##", "vim:")):
                        continue

                    # skip các dòng chứa mô tả như "SSL v2 ..." hoặc "SSL server ..."
                    if re.search(r'SSL\s+(v\d|server|clients?|default)', clean_line, re.IGNORECASE):
                        continue

                    m = re.match(r'^\s*([A-Za-z_]+)\b', clean_line)
                    if not m:
                        continue
                    key = m.group(1).strip()

                    # chỉ lấy directive thật
                    if not key.startswith(("SSL", "AddType", "Mutex")):
                        continue

                    # trạng thái chỉ cần on/off
                    result[key] = "off" if is_comment else "on"

            return {
                "path": str(target),
                "directives": result,
                "total": len(result)
            }

        except Exception as e:
            return {"error": str(e)}

    report["ssl_conf_directives"] = parse_ssl_conf_auto()

    # ------------------------------------------------------------------
    compliance_values = {}

    # --- 7.9: HTTPS redirect rule ---
    redirect_value = None

    # Lấy directive Redirect (có thể là dict hoặc list hoặc str)
    _redirect = report["directives"].get("Redirect", {})
    _rewrite = report["directives"].get("RewriteRule", {})

    # Nếu là dict kiểu mới
    if isinstance(_redirect, dict):
        redirect_rules = _redirect.get("value")
    else:
        redirect_rules = _redirect

    if isinstance(_rewrite, dict):
        rewrite_rules = _rewrite.get("value")
    else:
        rewrite_rules = _rewrite

    # Chuẩn hóa kiểu dữ liệu
    if redirect_rules and not isinstance(redirect_rules, list):
        redirect_rules = [redirect_rules]
    if rewrite_rules and not isinstance(rewrite_rules, list):
        rewrite_rules = [rewrite_rules]

    redirect_rules = redirect_rules or []
    rewrite_rules = rewrite_rules or []

    for line in redirect_rules + rewrite_rules:
        if not line:
            continue
        if re.search(r"https?://", line, re.IGNORECASE):
            redirect_value = line.strip()
            break

    if redirect_value:
        compliance_values["Redirect permanent"] = redirect_value
    else:
        compliance_values["Redirect permanent"] = "not_found"

    # --- 9.5 & 9.6: RequestReadTimeout directives ---
    reqtimeout_values = []
    for fp in conf_files:
        if "reqtimeout" in fp.lower():
            text = read_text(Path(fp))
            for line in text.splitlines():
                if line.strip().lower().startswith("requestreadtimeout"):
                    reqtimeout_values.append(line.strip())

    for line in reqtimeout_values:
        lower = line.lower()
        if "header=" in lower:
            compliance_values["CIS-APACHE-2.4-9.5"] = line.strip()
        if "body=" in lower:
            compliance_values["CIS-APACHE-2.4-9.6"] = line.strip()

    # Nếu không tìm thấy thì vẫn gán "not_found" để tránh KeyError
    compliance_values.setdefault("CIS-APACHE-2.4-9.5", "not_found")
    compliance_values.setdefault("CIS-APACHE-2.4-9.6", "not_found")

    report["compliance_directives"] = compliance_values

    return report

# ----------------------------
# Utility helpers used in collect
# ----------------------------
def extract_directive_values(text, name):
    vals = []
    for line in text.splitlines():
        m = re.match(rf'^\s*{re.escape(name)}\s+["\']?(.+?)["\']?\s*$', line, re.IGNORECASE)
        if m:
            vals.append(m.group(1).strip().strip('"').strip("'"))
    return vals

def summarize_permissions_dir(path: Path):
    stats = {"total": 0, "owned_by_root": 0, "gid_root": 0, "world_writable": 0, "group_writable": 0}
    if not path.exists():
        return stats
    for p in itertools.islice(path.rglob("*"), 0, None):
        try:
            st = p.stat()
        except Exception:
            continue
        stats["total"] += 1
        if st.st_uid == 0:
            stats["owned_by_root"] += 1
        if st.st_gid == 0:
            stats["gid_root"] += 1
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o002:
            stats["world_writable"] += 1
        if mode & 0o020:
            stats["group_writable"] += 1
    return stats

def expand_path(path_str, envvars):
    if not path_str:
        return path_str
    p = path_str
    # replace ${VAR} style
    for k, v in envvars.items():
        p = p.replace("${" + k + "}", v)
    # simple replacement for $VAR
    for k, v in envvars.items():
        p = p.replace("$" + k, v)
    return p

# ----------------------------
# Entry point
# ----------------------------
if __name__ == "__main__":
    out = collect(APACHE_ROOT)
    print(json.dumps(out, indent=2, ensure_ascii=False))