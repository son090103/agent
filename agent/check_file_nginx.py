#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified NGINX CIS Rule Evaluator
--------------------------------
"""

import json, yaml, re
from pathlib import Path

# =============================
# LOAD HELPERS
# =============================

def load_json_report(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"❌ Không tìm thấy file JSON: {file_path}")
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)

def load_yaml_rule(file_path: Path):
    if not file_path.exists():
        raise FileNotFoundError(f"❌ Không tìm thấy file YAML: {file_path}")
    with file_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

# =============================
# UTILITIES
# =============================

def find_directive(report_data, directive):
    """Tìm directive trong report JSON"""
    dirs = report_data.get("directives", {})
    return dirs.get(directive, [])

def compare_value(found, expected):
    """So sánh giá trị directive"""
    found_val = str(found).strip().lower()
    expected_val = str(expected).strip().lower()
    return found_val == expected_val or expected_val in found_val

def evaluate_rule(report, rule):
        # --- Normalize keys ---
    rule_id = rule.get("rule_id") or rule.get("ruleId") or "UNKNOWN"
    desc = rule.get("description", "")
    severity = rule.get("severity", "Medium")

    # --- Handle directive from multiple levels ---
    directive = (
        rule.get("directive")
        or (rule.get("target") or {}).get("directive")
        or (rule.get("target") or {}).get("directive_name")
    )

    expected = (
        str(rule.get("expected_value", "")).strip().lower()
        or str((rule.get("assertion") or {}).get("value", "")).strip().lower()
    )

    check_type = (
        rule.get("check_type")
        or rule.get("type")
        or (rule.get("assertion") or {}).get("condition")
        or ""
    ).lower()

    evidence, status = [], "UNKNOWN"
    # ===== 1️⃣ Kiểm tra directive =====
    if directive:
        directives = report.get("directives", {})
        found = directives.get(directive)

        # --- CASE 1: directive xuất hiện trong JSON parsed ---
        if found:
            matched = False
            for item in found:
                val = str(item.get("value", "")).strip().lower()
                if val and expected in val:
                    matched = True
                    evidence.append(f"{directive} {val} (match in {item.get('file')})")
                else:
                    evidence.append(f"{directive}={val} (expected {expected})")
            status = "PASS" if matched else "FAIL"

        # --- CASE 2: không có trong directives → quét bằng regex trong servers.raw ---
        else:
            regex = re.compile(rf"{directive}\s+(\S+);", re.IGNORECASE)
            matched_files = []
            for srv in report.get("servers", []):
                raw = srv.get("raw", "")
                file_path = srv.get("file", "unknown")
                for m in regex.finditer(raw):
                    val = m.group(1).lower()
                    matched_files.append((file_path, val))
                    if expected in val:
                        evidence.append(f"{directive} {val} found in {file_path}")
                        status = "PASS"
                    else:
                        evidence.append(f"{directive} {val} found in {file_path}, expected {expected}")
                        status = "FAIL"

            # Nếu tìm thấy directive trong raw → PASS/FAIL theo match
            if matched_files and status == "Insufficient data to conclude":
                status = "FAIL"
                evidence.append(f"Found {directive} in files but value didn't match expected '{expected}'")
            elif not matched_files:
                status = "FAIL"
                evidence.append(f"Directive '{directive}' not found in any config file (even raw).")
    
        # ===== 8️⃣ Kiểm tra file_permission_check (owner/group) =====
    elif "file_permission_check" in check_type or "ownership_equals" in check_type:
        target = (rule.get("target") or {}).get("path", "")
        expected_owner = (rule.get("assertion") or {}).get("value", {}).get("owner", "root")
        expected_group = (rule.get("assertion") or {}).get("value", {}).get("group", "root")

        if not target:
            status = "Insufficient data to conclude"
            evidence.append("Missing target path in YAML rule.")
        else:
            dir_info = report.get("extra_scans", {}).get(target, {}).get("stat", {})
            dir_uid = dir_info.get("uid")
            dir_gid = dir_info.get("gid")

            # Kiểm tra quyền sở hữu của thư mục chính
            if dir_uid is None or dir_gid is None:
                status = "Insufficient data to conclude"
                evidence.append(f"Missing ownership data for {target}")
            else:
                if dir_uid != 0 or dir_gid != 0:
                    evidence.append(f"{target} owned by uid={dir_uid}, gid={dir_gid} (expected root:root)")

                # Kiểm tra từng file trong conf_file_stats
                conf_files = report.get("conf_file_stats", {})
                for f, meta in conf_files.items():
                    if meta.get("exists") and (meta.get("uid") != 0 or meta.get("gid") != 0):
                        evidence.append(f"{f} owned by uid={meta.get('uid')}, gid={meta.get('gid')}")

                if not evidence:
                    status = "PASS"
                    evidence.append(f"All files under {target} are owned by root:root")
                else:
                    status = "FAIL"

    elif "2.3.3" in rule_id:
        pid_paths = ["/var/run/nginx.pid", "/run/nginx.pid"]
        evidence = []
        found = False

        for pid in pid_paths:
            pid_info = report.get("extra_scans", {}).get(pid, {}).get("stat", {})
            if pid_info.get("exists"):
                found = True
                uid, gid, mode = pid_info.get("uid"), pid_info.get("gid"), pid_info.get("mode")
                evidence.append(f"{pid} owned by uid={uid}, gid={gid}, mode={mode}")
                if uid == 0 and gid == 0 and str(mode).replace("0o", "") == "644":
                    status = "PASS"
                else:
                    status = "FAIL"
                    evidence.append("Expected root:root with mode 0o644")
                break

        if not found:
            status = "Insufficient data to conclude"
            evidence.append("PID file not found at /var/run/nginx.pid or /run/nginx.pid")

    # ===== 3️⃣ Kiểm tra SSL certificate / key =====
    elif "ssl_certificate" in rule_id.lower():
        ssl_data = report.get("ssl", {})
        certs = ssl_data.get("certs", [])
        keys = ssl_data.get("keys", [])
        if certs and certs[0].get("stat", {}).get("exists"):
            status = "PASS"
            evidence.append(f"Certificate found at {certs[0]['path']}")
        else:
            status = "FAIL"
            evidence.append("No valid certificate found")
        if keys and keys[0].get("stat", {}).get("exists"):
            evidence.append(f"Key exists: {keys[0]['path']}")
        else:
            evidence.append("Private key missing or permission denied")

    # ===== 4️⃣ Kiểm tra file quyền truy cập =====
    elif "permission" in check_type:
        path = rule.get("path")
        expected_mode = rule.get("expected_value", "")
        scan_data = report.get("extra_scans", {}).get(path)
        if not scan_data:
            status = "FAIL"
            evidence.append(f"Path '{path}' not found.")
        else:
            mode = scan_data.get("stat", {}).get("mode")
            if mode == expected_mode:
                status = "PASS"
                evidence.append(f"Mode OK: {mode}")
            else:
                status = "FAIL"
                evidence.append(f"Found {mode}, expected {expected_mode}")

    # ===== 6️⃣ Kiểm tra package_check =====
    elif "package_check" in check_type or "package" in rule_id.lower():
        pkg_status = report.get("package_status", {})
        nginx_installed = pkg_status.get("nginx_installed", False)
        if nginx_installed:
            status = "PASS"
            evidence.append("✅ nginx package is installed (trusted vendor source assumed)")
        else:
            status = "FAIL"
            evidence.append("❌ nginx package is not installed or not from vendor repo")

        # ===== 7️⃣ Kiểm tra account_check (shell) =====
    elif "account_check" in check_type or "service account" in rule_id.lower():
        user_data = report.get("users", {}).get("nginx_user", {})
        shell = user_data.get("shell", "")
        if "nologin" in shell or "false" in shell:
            status = "PASS"
            evidence.append(f"Shell is set to '{shell}' (invalid login shell)")
        else:
            status = "FAIL"
            evidence.append(f"Shell is '{shell}' — should be /sbin/nologin or /usr/sbin/nologin")

        # ===== 9️⃣ Kiểm tra nội dung index.html / 50x.html (CIS 2.5.2) =====
    elif "2.5.2" in rule_id:
        html_paths = [
            "/usr/share/nginx/html/index.html",
            "/usr/share/nginx/html/50x.html"
        ]
        bad_refs = []
        for html in html_paths:
            try:
                with open(html, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    if "nginx" in content:
                        bad_refs.append(f"{html} contains reference to 'nginx'")
            except FileNotFoundError:
                evidence.append(f"{html} not found")
        if bad_refs:
            status = "FAIL"
            evidence.extend(bad_refs)
        elif not evidence:
            status = "PASS"
            evidence.append("No 'nginx' references found in default pages")
        else:
            status = "Insufficient data to conclude"
            evidence.append("Default HTML files not found, unable to verify content.")
    
        # ===== 🔟 Kiểm tra reverse proxy info disclosure (CIS 2.5.4) =====
    elif "2.5.4" in rule_id:
        evidence = []
        proxy_headers = []
        hide_headers = []

        # Duyệt directives từ report
        directives = report.get("directives", {})

        # Thu thập proxy_set_header và proxy_hide_header
        for key, items in directives.items():
            if key == "proxy_set_header":
                for item in items:
                    val = f"{item.get('args', '')} {item.get('value', '')}".strip()
                    proxy_headers.append(val)
            elif key == "proxy_hide_header":
                for item in items:
                    hide_headers.append(item.get("value", ""))

        # Kiểm tra nếu header 'Server' bị rò rỉ hoặc không được ghi đè
        leaked = False
        for h in proxy_headers:
            if "server" in h.lower() and ("nginx" in h.lower() or h.strip().endswith("server")):
                leaked = True
                evidence.append(f"Potential info leak via {h}")

        # Nếu có proxy_hide_header cho các header nhạy cảm → tăng điểm PASS
        safe = any(
            any(x in hh.lower() for x in ["x-powered-by", "via", "x-upstream", "x-backend", "server"])
            for hh in hide_headers
        )

        if leaked:
            status = "FAIL"
        elif safe:
            status = "PASS"
            evidence.append("Sensitive headers are hidden using proxy_hide_header.")
        else:
            status = "Insufficient data to conclude"
            evidence.append("No proxy_set_header or proxy_hide_header directives found.")
    
        # ===== 11️⃣ Kiểm tra logrotate cấu hình (CIS 3.4) =====
    elif "2.1.0-3.4" in rule_id or "logrotate" in rule_id.lower():
        logrotate_path = "/etc/logrotate.d/nginx"
        evidence = []
        try:
            with open(logrotate_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                has_weekly = re.search(r"\bweekly\b", content)
                rotate_match = re.search(r"rotate\s+(\d+)", content)
                rotate_num = int(rotate_match.group(1)) if rotate_match else 0

                if has_weekly and rotate_num >= 13:
                    status = "PASS"
                    evidence.append(f"{logrotate_path}: weekly, rotate={rotate_num} (≥13)")
                elif has_weekly or rotate_num > 0:
                    status = "FAIL"
                    evidence.append(f"{logrotate_path}: rotation insufficient ({rotate_num} < 13 or not weekly)")
                else:
                    status = "FAIL"
                    evidence.append(f"{logrotate_path}: no weekly or rotate directive found")
        except FileNotFoundError:
            status = "Insufficient data to conclude"
            evidence.append(f"{logrotate_path} not found")
        except Exception as e:
            status = "Insufficient data to conclude"
            evidence.append(f"Error reading {logrotate_path}: {e}")

        # ===== 12️⃣ Kiểm tra TLS protocol version (CIS 4.1.4) =====
    elif "4.1.4" in rule_id:
        directives = report.get("directives", {})
        tls_directives = []

        # Thu thập giá trị từ ssl_protocols và proxy_ssl_protocols
        for key in ["ssl_protocols", "proxy_ssl_protocols"]:
            if key in directives:
                for item in directives[key]:
                    val = str(item.get("value", "")).lower()
                    tls_directives.append(f"{key} {val}")

        if not tls_directives:
            status = "Insufficient data to conclude"
            evidence.append("No ssl_protocols or proxy_ssl_protocols directives found.")
        else:
            bad = []
            good = []
            for line in tls_directives:
                if any(v in line for v in ["tlsv1", "tlsv1.0", "tlsv1.1"]):
                    bad.append(line)
                elif "tlsv1.2" in line or "tlsv1.3" in line:
                    good.append(line)

            if bad:
                status = "FAIL"
                evidence.extend([f"Insecure protocol enabled → {b}" for b in bad])
            elif good:
                status = "PASS"
                evidence.extend([f"Secure protocol(s) found → {g}" for g in good])
            else:
                status = "Insufficient data to conclude"
                evidence.append("No recognizable TLS protocol directives found.")
    
        # ===== 13️⃣ Kiểm tra OCSP stapling (CIS 4.1.7) =====
    elif "4.1.7" in rule_id:
        directives = report.get("directives", {})
        stapling = directives.get("ssl_stapling", [])
        stapling_verify = directives.get("ssl_stapling_verify", [])
        evidence = []

        # Kiểm tra trạng thái từng directive
        stapling_on = any("on" in str(i.get("value", "")).lower() for i in stapling)
        stapling_verify_on = any("on" in str(i.get("value", "")).lower() for i in stapling_verify)

        if stapling_on and stapling_verify_on:
            status = "PASS"
            evidence.append("Both ssl_stapling and ssl_stapling_verify are enabled.")
        elif stapling_on or stapling_verify_on:
            status = "FAIL"
            if stapling_on:
                evidence.append("ssl_stapling enabled, but ssl_stapling_verify missing.")
            else:
                evidence.append("ssl_stapling_verify enabled, but ssl_stapling missing.")
        else:
            status = "Insufficient data to conclude"
            evidence.append("No ssl_stapling or ssl_stapling_verify directives found.")

        # ===== 14️⃣ Kiểm tra mutual TLS authentication (CIS 4.1.9) =====
    elif "4.1.9" in rule_id:
        directives = report.get("directives", {})
        certs = directives.get("proxy_ssl_certificate", [])
        keys = directives.get("proxy_ssl_certificate_key", [])
        evidence = []

        has_cert = any(item.get("value") for item in certs)
        has_key = any(item.get("value") for item in keys)

        if has_cert and has_key:
            status = "PASS"
            cert_path = certs[0].get("value") if certs else "unknown"
            key_path = keys[0].get("value") if keys else "unknown"
            evidence.append(f"proxy_ssl_certificate={cert_path}, proxy_ssl_certificate_key={key_path}")
        elif has_cert or has_key:
            status = "FAIL"
            if has_cert:
                evidence.append("proxy_ssl_certificate found, but missing proxy_ssl_certificate_key.")
            else:
                evidence.append("proxy_ssl_certificate_key found, but missing proxy_ssl_certificate.")
        else:
            status = "Insufficient data to conclude"
            evidence.append("No proxy_ssl_certificate or proxy_ssl_certificate_key directives found.")

        # ===== 15️⃣ Kiểm tra client_header_timeout và client_body_timeout (CIS 5.2.1) =====
    elif "5.2.1" in rule_id:
        directives = report.get("directives", {})
        evidence = []

        # Lấy giá trị timeout
        hdrs = directives.get("client_header_timeout", [])
        bodys = directives.get("client_body_timeout", [])

        def extract_seconds(val):
            # Chuyển "10s" hoặc "15" -> 10, 15
            if not val:
                return None
            val = str(val).lower().strip().replace(";", "")
            m = re.match(r"(\d+)", val)
            return int(m.group(1)) if m else None

        hdr_timeout = extract_seconds(hdrs[0]["value"]) if hdrs else None
        body_timeout = extract_seconds(bodys[0]["value"]) if bodys else None

        # Đánh giá điều kiện
        if hdr_timeout is None and body_timeout is None:
            status = "Insufficient data to conclude"
            evidence.append("No client_header_timeout or client_body_timeout directives found.")
        else:
            bad = []
            good = []
            if hdr_timeout is not None:
                if hdr_timeout <= 10:
                    good.append(f"client_header_timeout {hdr_timeout}s")
                else:
                    bad.append(f"client_header_timeout {hdr_timeout}s > 10s")
            if body_timeout is not None:
                if body_timeout <= 10:
                    good.append(f"client_body_timeout {body_timeout}s")
                else:
                    bad.append(f"client_body_timeout {body_timeout}s > 10s")

            if bad:
                status = "FAIL"
                evidence.extend(bad)
            elif good:
                status = "PASS"
                evidence.extend(good)
            else:
                status = "Insufficient data to conclude"
                evidence.append("Timeout directives not found or unreadable.")

    # ===== Mặc định =====
    else:
        evidence.append("No matching logic found for this rule.")
        status = "Insufficient data to conclude"

    return {
        "rule_id": rule_id,
        "description": desc,
        "severity": severity,
        "status": status,
        "found_value": evidence,
        "remediation": rule.get("remediation", "")
    }

# =============================
# MAIN EXECUTION
# =============================

if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    report_file = base_dir / "nginx_report.json"
    rules_dir = base_dir / "CIS NGINX Benchmark v2.1.0"

    if not report_file.exists():
        raise FileNotFoundError(f"❌ Không tìm thấy file JSON: {report_file}")
    if not rules_dir.exists():
        raise FileNotFoundError(f"❌ Không tìm thấy thư mục rule: {rules_dir}")

    report_data = load_json_report(report_file)
    yaml_files = sorted(rules_dir.glob("*.yaml"))

    print(f"🔍 Phát hiện {len(yaml_files)} rule YAML — bắt đầu mapping...\n")

    results = []
    for f in yaml_files:
        try:
            rule = load_yaml_rule(f)
            res = evaluate_rule(report_data, rule)
            results.append(res)
            print(f"✅ {f.name} → {res['status']}")
        except Exception as e:
            print(f"⚠️ Lỗi khi xử lý {f.name}: {e}")

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    inconclusive = total - passed - failed
    print(f"\n📊 Tổng kết: {passed} PASS / {failed} FAIL / {inconclusive} Inconclusive")

    out_file = base_dir / "nginx_report_results.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"📄 Đã lưu kết quả toàn bộ tại: {out_file}")

def load_rules_from_mongodb(rule_type="nginx"):
    """
    Load toàn bộ rule từ MongoDB theo type ('nginx')
    """

    client = MongoClient("mongodb://localhost:27017/")
    db = client["secrulemap"]
    collection = db["ruleconfigs"]   # đúng tên collection rule bạn đang dùng

    rules = list(collection.find({"type": rule_type}))

    # Xóa _id vì không cần khi evaluate
    for r in rules:
        r.pop("_id", None)

    print(f"📥 Loaded {len(rules)} rules from MongoDB (type={rule_type})")

    return rules
def evaluate_nginx_all_rules_from_db(report_data):
    """
    Chạy TẤT CẢ rule NGINX lấy từ DB và return summary + results
    """

    print("🚀 Evaluating all NGINX rules from MongoDB...")

    # ---- Load rules từ DB ----
    rules = load_rules_from_mongodb("nginx")

    results = []
    for rule in rules:
        try:
            res = evaluate_rule(report_data, rule)
            results.append(res)
            print(f"✔ {rule.get('rule_id')} → {res['status']}")
        except Exception as e:
            print(f"❌ Error evaluating {rule.get('rule_id')}: {e}")
            results.append({
                "rule_id": rule.get("rule_id", "UNKNOWN"),
                "status": "Error",
                "found_value": [str(e)],
                "remediation": rule.get("remediation", "")
            })

    # ---- Summary ----
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "error": sum(1 for r in results if r["status"] == "Error"),
        "inconclusive": sum(1 for r in results if "Insufficient" in r["status"]),
    }

    return {
        "summary": summary,
        "results": results
    }
