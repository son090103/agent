#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto Web Server Agent Runner (Dual Collector)

- Phát hiện web servers (Apache, NGINX)
- Tự động chạy apache_agent.collect() hoặc nginx_agent.collect()
- Xuất file apache_report.json / nginx_report.json
- Tạo combined_webserver_report_<timestamp>.json
- Upload kết quả dạng mảng cho API backend
"""

import subprocess
import sys
import json
import os
from pathlib import Path
from datetime import datetime
import argparse
import requests

# ----------------------------
# Detect which servers are present
# ----------------------------
def detect_servers():
    """Phát hiện Apache / NGINX đang cài hoặc chạy."""
    found = []

    try:
        ps_output = subprocess.getoutput("ps aux | grep -E 'apache2|httpd|nginx' | grep -v grep").lower()
        if "apache2" in ps_output or "httpd" in ps_output:
            found.append("apache")
        if "nginx" in ps_output:
            found.append("nginx")
    except Exception:
        pass

    # Nếu không có process, kiểm tra binary
    if not found:
        if Path("/usr/sbin/apache2").exists() or Path("/usr/sbin/httpd").exists() or subprocess.getoutput("which apache2"):
            found.append("apache")
        if Path("/usr/sbin/nginx").exists() or subprocess.getoutput("which nginx"):
            found.append("nginx")

    return sorted(set(found))


# ----------------------------
# Run agent and return JSON
# ----------------------------
def run_agent(server_type):
    """Chạy agent tương ứng và trả về JSON."""
    agent_map = {
        "apache": "apache_agent",
        "nginx": "nginx_agent"
    }

    try:
        agent_module = __import__(agent_map[server_type])
        print(f"\n✅ Đang chạy {server_type.upper()} agent...")

        # Auto detect root path
        if server_type == "apache":
            POSSIBLE_PATHS = [
                os.getenv("APACHE_ROOT"),
                "/etc/apache2",
                "/etc/httpd",
                "/usr/local/apache2/conf",
                "/usr/local/etc/apache2",
                "/opt/apache2/conf",
            ]
        elif server_type == "nginx":
            POSSIBLE_PATHS = [
                os.getenv("NGINX_ROOT"),
                "/etc/nginx",
                "/usr/local/nginx/conf",
                "/usr/local/etc/nginx",
                "/opt/nginx/conf",
            ]

        root = next((p for p in POSSIBLE_PATHS if p and Path(p).exists()), None)
        if not root:
            print(f"⚠️ Không tìm thấy thư mục cấu hình {server_type}.")
            return None

        # Gọi collect()
        result = agent_module.collect(root)

        # Lưu file JSON riêng
        out_name = f"{server_type}_report.json"
        with open(out_name, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"💾 Đã lưu kết quả: {out_name}")

        return result

    except ModuleNotFoundError:
        print(f"❌ Không tìm thấy file {agent_map[server_type]}.py.")
    except Exception as e:
        print(f"❌ Lỗi khi chạy {agent_map[server_type]}: {e}")

    return None


# ----------------------------
# MAIN ENTRY
# ----------------------------
if __name__ == "__main__":

    # CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--upload-url", required=True)
    args = parser.parse_args()

    print("🔍 Đang phát hiện web servers trên hệ thống...\n")
    servers = detect_servers()

    if not servers:
        print("⚠️ Không phát hiện Apache hoặc NGINX.")
        sys.exit(1)

    print(f"✅ Đã phát hiện: {', '.join(servers).upper()}")

    results = {}
    for server in servers:
        res = run_agent(server)
        if res:
            results[server] = res

    # Tạo file tổng hợp local
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_file = f"combined_webserver_report_{timestamp}.json"
    with open(combined_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n📦 Đã tạo bản tổng hợp: {combined_file}")

    # Chuẩn hóa upload thành 1 mảng
    upload_array = [
        {
            "type": srv,
            "scan_id": args.scan_id,
            "data": results[srv]
        }
        for srv in results
    ]

    print("\n📡 Đang gửi kết quả về server...")

    try:
        response = requests.post(
            args.upload_url,
            json=upload_array,
            headers={"Authorization": f"Bearer {args.token}"}
        )

        if response.status_code == 200:
            print("✅ Upload thành công!")
        else:
            print(f"❌ Upload thất bại: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"❌ Lỗi khi upload: {e}")

    print("\n=== TÓM TẮT KẾT QUẢ ===")
    for s, r in results.items():
        total_files = len(r.get("files", [])) if isinstance(r, dict) else 0
        print(f"- {s.upper()}: {total_files} file cấu hình → {s}_report.json")
