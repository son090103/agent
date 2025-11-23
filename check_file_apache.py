#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Apache CIS Rule Evaluator
"""
import json
import yaml
from pathlib import Path
import re

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
        data = yaml.safe_load(f)
    return data or {}

# =============================
# UTILS
# =============================

def normalize_directives(data):
    out = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                out += [f"{k} {x}" for x in v]
            else:
                out.append(f"{k} {v}")
    elif isinstance(data, list):
        out += [str(x) for x in data]
    elif data:
        out.append(str(data))
    return out

def extract_number(s):
    m = re.search(r"(-?\d+(?:\.\d+)?)", str(s))
    return float(m.group(1)) if m else None

# =============================
# CIS 2.2 – 2.9 MODULE HANDLER
# =============================
def evaluate_apache_rule(rule_data, modules):
    """
    Evaluate Apache module configuration compliance
    for CIS Apache 2.4 rules 2.2–2.9
    """
    result = {
        "rule_id": rule_data.get("ruleId"),
        "description": rule_data.get("description"),
        "severity": rule_data.get("severity", "Unknown"),
        "status": "UNKNOWN",
        "found_value": [],
        "remediation": rule_data.get("remediation", "").strip(),
    }

    assertion = rule_data.get("assertion", {})
    condition = assertion.get("condition", "")
    value = assertion.get("value", [])
    if not isinstance(value, list):
        value = [value]

    found_lines = [m.get("line", "") for m in modules]

    if condition == "contains":
        matched = [line for line in found_lines if any(v in line for v in value)]
        result["status"] = "PASS" if matched else "FAIL"
        result["found_value"] = matched or ["Directive(s) not found"]
    elif condition == "not_contains":
        matched = [line for line in found_lines if any(v in line for v in value)]
        result["status"] = "FAIL" if matched else "PASS"
        result["found_value"] = matched or ["No forbidden modules found"]
    elif condition == "not_contains_any":
        matched = [line for line in found_lines if any(v in line for v in value)]
        result["status"] = "FAIL" if matched else "PASS"
        result["found_value"] = matched or ["None of the listed modules were found"]
    else:
        result["status"] = "UNKNOWN"
        result["found_value"] = ["Unsupported or undefined rule condition"]

    return result

# =============================
# UNIVERSAL RULE EVALUATOR
# =============================
def evaluate_rule(report_data, rule_data, debug=False):
    """
    Evaluate one CIS/Benchmark rule against Apache report data.
    Gộp logic từ check.py & check_file_apache.py
    """
    result = {
        "rule_id": rule_data.get("ruleId", "Unknown"),
        "description": rule_data.get("description", ""),
        "severity": rule_data.get("severity", "Unknown"),
        "status": "Unknown",
        "found_value": [],
        "remediation": rule_data.get("remediation", ""),
    }

    try:
        rule_id = rule_data.get("ruleId", "")
        rule_type = (rule_data.get("type") or "").lower()
        target = rule_data.get("target", {}) or {}
        assertion = rule_data.get("assertion", {}) or {}
        condition = (assertion.get("condition") or "").lower()
        expected = assertion.get("value")

        modules = report_data.get("modules", [])
        directives = normalize_directives(report_data.get("directives", []))
        perms = report_data.get("permissions_summary", {}) or {}
        system_users = report_data.get("system_users") or report_data.get("users", {})
        packages = report_data.get("packages", {})
        ssl_info = report_data.get("ssl", {}) or {}

        # ==========================================
        # ✅ ƯU TIÊN: MODULE CHECK (2.4-2.2 → 2.4-2.9)
        # ==========================================
        if rule_id.startswith("CIS-APACHE-2.4-2."):
            try:
                num = float(rule_id.split("-")[-1])
                if 2.2 <= num <= 2.9:
                    return evaluate_apache_rule(rule_data, modules)
            except:
                pass

        # ==========================================
        # 8️⃣ LOG ROTATION CHECK (CIS-APACHE-2.4-6.4) — RUN EARLY
        # ==========================================
        if rule_id == "CIS-APACHE-2.4-6.4":
            logrotate_enabled = bool(report_data.get("logrotate_apache", False))
            rotate = int(report_data.get("logrotate_rotate", 0) or 0)
            schedule = (report_data.get("logrotate_schedule") or "").lower()

            # Quy đổi số tuần giữ log theo schedule
            if schedule == "weekly":
                weeks = rotate
            elif schedule == "daily":
                weeks = rotate / 7.0
            elif schedule == "monthly":
                # xấp xỉ 4 tuần mỗi tháng
                weeks = rotate * 4.0
            else:
                weeks = 0.0  # không rõ schedule => coi như không đạt

            if not logrotate_enabled:
                result["status"] = "FAIL"
                result["found_value"] = ["logrotate_apache=False"]
                return result

            if weeks >= 13.0:
                result["status"] = "PASS"
                result["found_value"] = [f"logrotate active ({schedule}), rotate={rotate} (~{weeks:.1f} weeks)"]
            else:
                result["status"] = "FAIL"
                result["found_value"] = [f"logrotate {schedule} rotate={rotate} (~{weeks:.1f} weeks) < 13 weeks"]
            return result

        # ==========================================
        # 2️⃣ DIRECTIVE / CONFIG CHECK
        # ==========================================
        if rule_type in ["directive_check", "config_check"] or "directives" in target:
            directive_targets = target.get("directives") or [target.get("directive")]
            directive_targets = [d for d in directive_targets if d]

            found_lines = []
            for d in directives:
                for dt in directive_targets:
                    if dt and dt.lower() in d.lower():
                        found_lines.append(d)

            if condition in ["contains", "present", "exists"]:
                ok = bool(found_lines)
            elif condition in ["disabled", "absent", "not_exists"]:
                ok = not bool(found_lines)
            else:
                ok = bool(found_lines)

            result["status"] = "PASS" if ok else "FAIL"
            if not found_lines:
                found_lines = [f"Directive(s) not found in config: {directive_targets}"]
            result["found_value"] = found_lines
            return result

        # ==========================================
        # 3️⃣ FILE CHECK
        # ==========================================
        if rule_type == "file_check":
            paths = target.get("paths", [])
            files_found = report_data.get("files", [])
            found = [p for p in paths if p in files_found]
            if condition in ["not_exists", "absent"]:
                ok = all(p not in files_found for p in paths)
            elif condition in ["exists", "present"]:
                ok = all(p in files_found for p in paths)
            else:
                ok = bool(found)
            result["status"] = "PASS" if ok else "FAIL"
            result["found_value"] = found or [f"No matching file(s) among {len(files_found)} scanned."]
            return result

        # ==========================================
        # 4️⃣ SYSTEM CHECK
        # ==========================================
        if rule_type == "system_check":
            user = target.get("user") or "apache"
            field = target.get("field") or "password_status"

            # --- Tìm giá trị trong nhiều nhánh ---
            value = None
            if isinstance(system_users, dict):
                if user in system_users:
                    value = system_users[user].get(field)
                elif "www-data" in system_users:
                    value = system_users["www-data"].get(field)

            # Nếu không có system_users hoặc không có quyền đọc shadow
            if value is None and isinstance(report_data.get("users"), dict):
                apache_user_shadow = report_data["users"].get("apache_user_shadow", {})
                if apache_user_shadow.get("available") is False:
                    result["status"] = "Unknown"
                    result["found_value"] = [
                        "Shadow file unavailable (permission denied) — cannot verify account lock status."
                    ]
                    return result

            # Nếu vẫn không có thông tin user
            if value is None:
                result["status"] = "FAIL"
                result["found_value"] = [f"User '{user}' not found or password_status missing."]
                return result

            # --- Rule chuyên biệt cho CIS-APACHE-2.4-3.3 ---
            if rule_id == "CIS-APACHE-2.4-3.3":
                if str(value).startswith(str(expected)):
                    result["status"] = "PASS"
                    result["found_value"] = [f"{user} account is locked ({value})"]
                else:
                    result["status"] = "FAIL"
                    result["found_value"] = [f"{user} account not locked (password_status={value})"]
                return result

            # --- System check thông thường ---
            if condition == "in":
                ok = str(value) in (expected if isinstance(expected, list) else [expected])
            elif condition == "starts_with":
                ok = str(value).startswith(str(expected))
            else:
                ok = str(value) == str(expected)

            result["status"] = "PASS" if ok else "FAIL"
            result["found_value"] = [f"{field}={value} (expected {expected})"]
            return result
        
        # ==========================================
        # 5️⃣ PACKAGE CHECK
        # ==========================================
        if rule_type == "package_check":
            pkg = target.get("package")
            version_info = packages.get(pkg, {})
            if condition in ["up_to_date", "within_30_days"]:
                ok = version_info.get("up_to_date", False)
            else:
                ok = bool(version_info)
            result["status"] = "PASS" if ok else "FAIL"
            result["found_value"] = [json.dumps(version_info)] if version_info else [f"Package '{pkg}' not found"]
            return result

        # ==========================================
        # 6️⃣ PERMISSION CHECK
        # ==========================================
        if rule_type in ["permission_check", "file_permission_check", "directory_check"] or "path" in target:
            total = perms.get("total", 0)
            owned = perms.get("owned_by_root", 0)
            gid_root = perms.get("gid_root", 0)
            group_writable = perms.get("group_writable", 0)
            world_writable = perms.get("world_writable", 0)
            ratio_root = owned / total if total else 0

            if condition in ["no_group_write", "no_group_writable"]:
                ok = group_writable == 0
                found = f"group_writable={group_writable}"
            elif condition in ["no_world_write", "no_world_writable"]:
                ok = world_writable == 0
                found = f"world_writable={world_writable}"
            elif condition in ["owned_by_root"]:
                ok = ratio_root >= 0.9
                found = f"{owned}/{total} owned_by_root ({ratio_root:.2f})"
            elif condition in ["gid_root"]:
                ok = gid_root >= owned
                found = f"gid_root={gid_root}, owned_by_root={owned}"
            else:
                ok = ratio_root >= 0.9
                found = f"{owned}/{total} (ratio={ratio_root:.2f})"

            result["status"] = "PASS" if ok else "FAIL"
            result["found_value"] = [found]
            return result

        # ==========================================
        # 7️⃣ SSL CHECK
        # ==========================================
        if rule_type == "ssl_check":
            certs = ssl_info.get("certs", [])
            keys = ssl_info.get("keys", [])
            ok = bool(certs and keys)
            result["status"] = "PASS" if ok else "FAIL"
            result["found_value"] = [
                f"certs={len(certs)} present, keys={len(keys)} present"
            ] if certs or keys else ["No certificates or keys found"]
            return result
        
                # ==========================================
        # 🔐 MODULE CHECK (CIS-APACHE-2.4-7.1)
        # ==========================================
        if rule_id == "CIS-APACHE-2.4-7.1" or rule_type == "module_check":
            ssl_modules = [m.get("name") for m in modules]
            found_ssl = [m for m in ssl_modules if "ssl_module" in m or "nss_module" in m]

            if found_ssl:
                result["status"] = "PASS"
                result["found_value"] = [f"Modules found: {', '.join(found_ssl)}"]
            else:
                result["status"] = "FAIL"
                result["found_value"] = ["Neither mod_ssl nor mod_nss module found"]

            return result
        # ==========================================
        # ❌ UNKNOWN RULE TYPE
        # ==========================================
        result["status"] = "Not Applicable"
        result["found_value"] = [f"⚠️ No recognized rule type: '{rule_type}'"]

    except Exception as e:
        result["status"] = "Error"
        result["found_value"] = [f"Exception during evaluation: {e}"]

    if not result.get("found_value"):
        result["found_value"] = ["(No evidence or data available)"]

    if debug:
        print(f"[DEBUG] {result['rule_id']} → {result['status']} :: {result['found_value']}")

    return result

# =============================
# MAIN EXECUTION
# =============================

if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    report_file = base_dir / "apache_report.json"
    rules_dir = base_dir / "CIS Apache HTTP Server 2.4 Benchmark v2.2.0"

    if not report_file.exists():
        raise FileNotFoundError(f"❌ Không tìm thấy file JSON: {report_file}")
    if not rules_dir.exists():
        raise FileNotFoundError(f"❌ Không tìm thấy thư mục rule: {rules_dir}")

    report_data = load_json_report(report_file)
    yaml_files = sorted(rules_dir.glob("*.yaml"))
    print(f"🔍 Phát hiện {len(yaml_files)} rule YAML — bắt đầu kiểm tra...\n")

    results = []
    for f in yaml_files:
        try:
            rule = load_yaml_rule(f)
            if not rule:
                print(f"⚠️ Bỏ qua {f.name}: rule rỗng")
                continue
            res = evaluate_rule(report_data, rule)
            results.append(res)
            print(f"✅ {f.name} → {res['status']}")
        except Exception as e:
            print(f"⚠️ Lỗi khi xử lý {f.name}: {e}")

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    na = total - passed - failed
    print(f"\n📊 Tổng kết: {passed} PASS / {failed} FAIL / {na} N/A")

    out_file = base_dir / "apache_report_results.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"📄 Đã lưu kết quả toàn bộ tại: {out_file}")