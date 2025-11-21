#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NGINX Configuration & Environment Collector (Enhanced Version)

- Auto-detect NGINX config root (NGINX_ROOT env or possible paths)
- Detect both active & commented directives
- Capture originating file path for each directive
- Mark missing directives as 'not_found'
- Check if NGINX package is installed (vendor/trusted repo)
- Output: JSON (structured facts for compliance engine)
"""

from pathlib import Path
import os, re, json, stat, itertools, subprocess, pwd, glob

# ----------------------------
# Possible NGINX locations
# ----------------------------
POSSIBLE_PATHS = [
    "/etc/nginx", "/usr/local/nginx/conf", "/usr/local/etc/nginx",
    "/opt/nginx/conf", "/usr/pkg/etc/nginx", "/Applications/MAMP/conf/nginx"
]

EXTRA_PATHS = [
    "/etc/nginx", 
    "/var/www", "/var/log/nginx",
    "/var/run", "/run", "/run/nginx",
    "/etc/ssl", "/etc/pki/tls", "/etc/logrotate.d", "/home"
]

# ----------------------------
# Auto-detect NGINX root
# ----------------------------
NGINX_ROOT = os.environ.get("NGINX_ROOT")
if not NGINX_ROOT:
    for p in POSSIBLE_PATHS:
        if os.path.isdir(p):
            NGINX_ROOT = p
            break

if not NGINX_ROOT:
    print(json.dumps({"error": "NGINX config root not found"}))
    raise SystemExit(1)

# ----------------------------
# Helper functions
# ----------------------------
def read_text(path: Path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def list_conf_files(root: str):
    rootp = Path(root)
    files = []
    for p in rootp.rglob("*.conf"):
        files.append(str(p))
    main_conf = rootp / "nginx.conf"
    if main_conf.exists():
        text = read_text(main_conf)
        includes = re.findall(r'include\s+(.+?);', text)
        for inc in includes:
            inc_path = inc.strip().replace('"', '').replace("'", "")
            for path in glob.glob(inc_path, recursive=True):
                if os.path.isfile(path):
                    files.append(os.path.abspath(path))
    return sorted(set(files))

def stat_summary(path: Path):
    try:
        st = path.stat()
        return {"exists": True, "uid": st.st_uid, "gid": st.st_gid, "mode": oct(stat.S_IMODE(st.st_mode))}
    except Exception as e:
        return {"exists": False, "error": str(e)}

def scan_dir(path: Path, limit=30):
    if not path.exists() or not path.is_dir():
        return {"exists": False}
    out = {"exists": True, "entries": []}
    for e in itertools.islice(path.iterdir(), limit):
        try:
            st = e.stat()
            out["entries"].append({
                "name": e.name,
                "dir": e.is_dir(),
                "mode": oct(stat.S_IMODE(st.st_mode)),
                "uid": st.st_uid,
                "gid": st.st_gid
            })
        except Exception:
            out["entries"].append({"name": e.name, "error": "stat_failed"})
    return out

def check_nginx_installed():
    """Check if nginx package is installed via dpkg, rpm, or manually."""
    # Debian/Ubuntu
    if os.path.exists("/usr/bin/dpkg"):
        result = subprocess.getoutput("dpkg -s nginx 2>/dev/null | grep 'Status'")
        return "install ok installed" in result

    # RHEL/CentOS/Fedora
    if os.path.exists("/usr/bin/rpm"):
        result = subprocess.getoutput("rpm -q nginx 2>/dev/null")
        return not ("is not installed" in result or "not installed" in result)

    # Fallback (manual install check)
    result = subprocess.getoutput("nginx -v 2>&1")
    return "nginx/" in result

# ----------------------------
# Main Collector
# ----------------------------
def collect(nginx_root: str):
    conf_files = list_conf_files(nginx_root)
    report = {
        "nginx_root": nginx_root,
        "files_scanned": len(conf_files),
        "files": conf_files,
        "directives": {},
        "includes": [],
        "servers": [],
        "ssl": {},
        "users": {},
        "extra_scans": {},
        "package_status": {
            "nginx_installed": check_nginx_installed()
        }
    }

    for fp in conf_files:
        text = read_text(Path(fp))
        report["includes"].extend(re.findall(r'^\s*include\s+(.+?);', text, re.MULTILINE))

        # --- Extract directives (active + commented)
        for name in [
            "user", "worker_processes", "pid", "error_log", "access_log",
            "keepalive_timeout", "send_timeout", "client_max_body_size",
            "server_tokens", "ssl_protocols", "ssl_certificate", "ssl_certificate_key",
            "ssl_dhparam", "ssl_session_tickets", "ssl_stapling", "ssl_stapling_verify",
            "add_header", "proxy_set_header", "proxy_ssl_certificate",
            "proxy_ssl_certificate_key", "client_header_timeout",
            "client_body_timeout", "large_client_header_buffers"
        ]:
            active = re.findall(rf'^\s*{name}\s+(.+?);', text, re.IGNORECASE | re.MULTILINE)
            commented = re.findall(rf'^\s*#\s*{name}\s+(.+?);', text, re.IGNORECASE | re.MULTILINE)

            if active or commented:
                report["directives"].setdefault(name, [])
                for m in active:
                    report["directives"][name].append({
                        "value": m.strip(),
                        "commented": False,
                        "file": fp
                    })
                for m in commented:
                    report["directives"][name].append({
                        "value": m.strip(),
                        "commented": True,
                        "file": fp
                    })

        # --- Detect server blocks ---
        for m in re.finditer(r'(?is)server\s*\{(.*?)\}', text):
            body = m.group(1)
            listen = re.findall(r'^\s*listen\s+(.+?);', body, re.MULTILINE)
            server_name = re.findall(r'^\s*server_name\s+(.+?);', body, re.MULTILINE)
            root = re.findall(r'^\s*root\s+(.+?);', body, re.MULTILINE)
            has_return_404 = bool(re.search(r'\breturn\s+404\s*;', body))
            report["servers"].append({
                "listen": listen,
                "server_name": server_name,
                "root": root,
                "has_return_404": has_return_404,
                "file": fp,
                "raw": body.strip()[:500]
            })

    # --- Mark directives not found ---
    REQUIRED_DIRECTIVES = [
        "ssl_stapling", "ssl_stapling_verify", "server_tokens", "ssl_protocols",
        "ssl_certificate", "ssl_certificate_key", "ssl_dhparam", "add_header",
        "proxy_ssl_certificate", "proxy_ssl_certificate_key",
        "client_header_timeout", "client_body_timeout",
        "client_max_body_size", "large_client_header_buffers"
    ]
    for d in REQUIRED_DIRECTIVES:
        if d not in report["directives"]:
            report["directives"][d] = [{"status": "not_found", "file": None, "value": None, "commented": None}]

    # --- Check DH parameter file ---
    dhparam_entries = report["directives"].get("ssl_dhparam", [])
    if dhparam_entries and "value" in dhparam_entries[0] and dhparam_entries[0]["value"]:
        dhparam_path = dhparam_entries[0]["value"].strip()
        pathp = Path(dhparam_path)
        dh_info = {"exists": pathp.exists(), "path": dhparam_path}
        if pathp.exists():
            dh_info["stat"] = stat_summary(pathp)
            try:
                out = subprocess.getoutput(
                    f"openssl dhparam -in {pathp} -text -noout 2>/dev/null | grep 'DH Parameters:'"
                )
                match = re.search(r'(\d+)\s*bit', out)
                dh_info["bits"] = int(match.group(1)) if match else None
            except Exception as e:
                dh_info["bits_error"] = str(e)
        else:
            dh_info["stat"] = {"exists": False}
        report["ssl"]["dhparam"] = dh_info

    report["includes"] = sorted(set(report["includes"]))

    # --- Detect nginx binary and version ---
    try:
        out = subprocess.getoutput("nginx -v 2>&1")
        match = re.search(r"nginx/([\d\.]+)", out)
        report["nginx_version"] = match.group(1) if match else None
        report["nginx_binary"] = subprocess.getoutput("which nginx")
    except Exception:
        report["nginx_version"] = None
        report["nginx_binary"] = None

    # --- SSL cert/key stats ---
    certs = [d["value"] for d in report["directives"].get("ssl_certificate", []) if not d.get("commented")]
    keys = [d["value"] for d in report["directives"].get("ssl_certificate_key", []) if not d.get("commented")]
    report["ssl"]["certs"] = [{"path": c, "stat": stat_summary(Path(c))} for c in certs]
    report["ssl"]["keys"] = [{"path": k, "stat": stat_summary(Path(k))} for k in keys]

    # --- NGINX user ---
    user_val = None
    if "user" in report["directives"] and len(report["directives"]["user"]) > 0:
        user_val = report["directives"]["user"][0]["value"].split()[0]
    if user_val:
        try:
            info = pwd.getpwnam(user_val)
            report["users"]["nginx_user"] = {
                "name": info.pw_name, "uid": info.pw_uid, "gid": info.pw_gid,
                "home": info.pw_dir, "shell": info.pw_shell
            }
        except KeyError:
            report["users"]["nginx_user"] = {"name": user_val, "exists": False}

    # --- Extra path scans ---
    for pth in EXTRA_PATHS:
        pathp = Path(pth)
        report["extra_scans"][pth] = {
            "exists": pathp.exists(),
            "stat": stat_summary(pathp),
            "listing": scan_dir(pathp) if pathp.is_dir() else None
        }
    # --- Collect stats for all conf files ---
    conf_stats = {}
    for f in conf_files:
        pathf = Path(f)
        conf_stats[f] = stat_summary(pathf)
    report["conf_file_stats"] = conf_stats

    # --- PID files ---
    PID_PATHS = ["/run/nginx.pid", "/var/run/nginx.pid"]
    for pid_file in PID_PATHS:
        pid_entry = {"exists": False}
        try:
            st = os.stat(pid_file)
            pid_entry = {
                "exists": True,
                "stat": {
                    "exists": True,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mode": oct(stat.S_IMODE(st.st_mode))
                }
            }
        except FileNotFoundError:
            pid_entry["stat"] = {"exists": False}
        except PermissionError as e:
            try:
                # fallback: dùng 'ls -ln' để đọc uid/gid nếu không có quyền đọc trực tiếp
                out = subprocess.getoutput(f"ls -ln {pid_file} 2>/dev/null | awk '{{print $3, $4, $1}}'")
                parts = out.split()
                if len(parts) >= 3:
                    pid_entry["stat"] = {
                        "exists": True,
                        "uid": int(parts[0]),
                        "gid": int(parts[1]),
                        "mode": parts[2],
                        "note": "read via fallback ls"
                    }
                else:
                    pid_entry["stat"] = {"exists": False, "error": str(e)}
            except Exception as ee:
                pid_entry["stat"] = {"exists": False, "error": str(ee)}

        report["extra_scans"][pid_file] = pid_entry

    # --- HTML default pages ---
    html_files = [
        "/usr/share/nginx/html/index.html",
        "/usr/share/nginx/html/50x.html"
    ]
    html_report = {}
    for f in html_files:
        path = Path(f)
        if path.exists():
            content = read_text(path)
            html_report[f] = {
                "exists": True,
                "length": len(content),
                "contains_nginx": bool(re.search(r"(?i)nginx", content)),
                "preview": content[:200]
            }
        else:
            html_report[f] = {"exists": False}
    report["html_default_pages"] = html_report

    # --- Log rotation config ---
    logrotate_file = Path("/etc/logrotate.d/nginx")
    if logrotate_file.exists():
        content = read_text(logrotate_file)
        report["logrotate_nginx"] = {
            "exists": True,
            "length": len(content),
            "contains_weekly": bool(re.search(r"^\s*weekly", content, re.MULTILINE)),
            "contains_rotate_13": bool(re.search(r"rotate\s+13", content)),
            "preview": "\n".join(content.splitlines()[:10])
        }
    else:
        report["logrotate_nginx"] = {"exists": False}

    return report

# ----------------------------
# Entry point
# ----------------------------
if __name__ == "__main__":
    out = collect(NGINX_ROOT)
    print(json.dumps(out, indent=2, ensure_ascii=False))