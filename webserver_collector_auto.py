#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto Web Server Agent Runner (Collector + Evaluator + Merger)
- Detect Apache / NGINX
- Collect configuration
- Evaluate CIS rules
- Return JSON payload đúng chuẩn backend
"""

import subprocess
import sys
import json
import os
from pathlib import Path
from datetime import datetime
import argparse
import requests

# ================================================
# IMPORT RULE EVALUATORS
# ================================================
import check_file_apache
import check_file_nginx

# ================================================
# Detect servers
# ================================================
def detect_servers():
    found = []
    try:
        ps_output = subprocess.getoutput(
            "ps aux | grep -E 'apache2|httpd|nginx' | grep -v grep"
        ).lower()
        if "apache2" in ps_output or "httpd" in ps_output:
            found.append("apache")
        if "nginx" in ps_output:
            found.append("nginx")
    except:
        pass

    # If no process found, check binary paths
    if not found:
        if Path("/usr/sbin/apache2").exists() or Path("/usr/sbin/httpd").exists():
            found.append("apache")
        if Path("/usr/sbin/nginx").exists():
            found.append("nginx")

    return sorted(set(found))

# ================================================
# Run collector
# ================================================
def run_agent(server_type):
    agent_map = {
        "apache": "apache_agent",
        "nginx": "nginx_agent",
    }

    try:
        agent_module = __import__(agent_map[server_type])
        print(f"\n✅ Running {server_type.upper()} collector...")

        # detect root
        paths = (
            [
                os.getenv("APACHE_ROOT"),
                "/etc/apache2",
                "/etc/httpd",
                "/usr/local/apache2/conf",
            ]
            if server_type == "apache"
            else [
                os.getenv("NGINX_ROOT"),
                "/etc/nginx",
                "/usr/local/nginx/conf",
            ]
        )

        root = next((p for p in paths if p and Path(p).exists()), None)
        if not root:
            print(f"⚠️ Không tìm thấy root path cho {server_type}")
            return None

        data = agent_module.collect(root)

        # save
        fn = f"{server_type}_report.json"
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"💾 Saved: {fn}")
        return data

    except Exception as e:
        print(f"❌ Collector error for {server_type}: {e}")
        return None

# ================================================
# Summary
# ================================================
def make_summary(results):
    return {
        "total": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "inconclusive": sum(1 for r in results if r["status"] == "NO_DATA"),
    }

# ================================================
# MAIN
# ================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--upload-url", required=True)
    args = parser.parse_args()

    print("🔍 Detecting servers...")
    servers = detect_servers()

    if not servers:
        print("⚠️ No server found!")
        sys.exit(1)

    print(f"✅ Detected: {servers}")

    collected = {}
    evaluated = {}

    # 1️⃣ COLLECT
    for srv in servers:
        data = run_agent(srv)
        if data:
            collected[srv] = data

    # 2️⃣ EVALUATE
    if "apache" in collected:
        print("🚀 Evaluating Apache rules...")
        apache_results = check_file_apache.evaluate_all(collected["apache"])

        # normalize
        for r in apache_results:
            if r["status"] not in ["PASS", "FAIL"]:
                r["status"] = "NO_DATA"

        evaluated["apache"] = {
            "summary": make_summary(apache_results),
            "results": apache_results,
        }

    if "nginx" in collected:
        print("🚀 Evaluating NGINX rules...")
        nginx_results = check_file_nginx.evaluate_all(collected["nginx"])

        for r in nginx_results:
            if r["status"] not in ["PASS", "FAIL"]:
                r["status"] = "NO_DATA"

        evaluated["nginx"] = {
            "summary": make_summary(nginx_results),
            "results": nginx_results,
        }

    # 3️⃣ BUILD FINAL PAYLOAD (ĐÚNG YÊU CẦU BACKEND)
    final_payload = {
        "ok": True,
        "scan_id": args.scan_id,
        "data": evaluated,   # đã đúng format { apache:{..}, nginx:{..} }
    }

    print("📤 Final JSON ready to send:")
    print(json.dumps(final_payload, indent=2, ensure_ascii=False))

    # 4️⃣ UPLOAD
    try:
        response = requests.post(
            args.upload_url,
            json=final_payload,
            headers={"Authorization": f"Bearer {args.token}"}
        )
        print("📡 Upload status:", response.status_code, response.text)

    except Exception as e:
        print("❌ Upload error:", e)

    print("🎉 DONE")
