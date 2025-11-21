# ⚙️ Agent CIS Compliance — Hướng Dẫn Sử Dụng Nhanh

## 🧩 Mục đích
Agent này dùng để **phát hiện và đánh giá cấu hình bảo mật của web server (Apache hoặc NGINX)**.  
Nó sẽ:
1. Tự động nhận diện server đang chạy.  
2. Thu thập cấu hình hệ thống.  
3. So sánh với **CIS Benchmark** để đưa ra kết quả **PASS / FAIL / Inconclusive**.  

---

## 🚀 Cách hoạt động

### **Bước 1 — Phát hiện web server**
Chạy lệnh:
```bash
python webserver_collector_auto.py
```

✅ **Kết quả:**  
- Nếu hệ thống có **Apache** → sinh file `apache_report.json`  
- Nếu hệ thống có **NGINX** → sinh file `nginx_report.json`  
- Nếu có **cả hai** → sẽ tạo **cả hai file**

---

### **Bước 2 — Thu thập cấu hình**
Chạy agent tương ứng để lấy chi tiết cấu hình:

#### 🔹 Apache:
```bash
python apache_agent.py
```

#### 🔹 NGINX:
```bash
python nginx_agent.py
```

✅ **Kết quả:**  
- Dữ liệu cấu hình (modules, directives, quyền file, SSL, logrotate, v.v.)  
  sẽ được ghi vào `apache_report.json` hoặc `nginx_report.json`.

---

### **Bước 3 — Đánh giá CIS Benchmark**
Sau khi có file report, chạy bộ kiểm tra tuân thủ:

#### 🔹 Apache:
```bash
python check_file_apache.py
```

#### 🔹 NGINX:
```bash
python check_file_nginx.py
```

✅ **Kết quả:**  
Sinh ra file:
- `apache_report_results.json` hoặc  
- `nginx_report_results.json`

Mỗi rule sẽ có nội dung dạng:
```json
{
  "rule_id": "CIS-NGINX-2.1.0-4.1.4",
  "description": "Ensure only modern TLS protocols (TLSv1.2 and TLSv1.3) are used.",
  "severity": "High",
  "status": "FAIL",
  "found_value": [
    "Insecure protocol enabled → ssl_protocols tlsv1 tlsv1.1 tlsv1.2 tlsv1.3"
  ],
  "remediation": "Update nginx.conf to use only TLSv1.2 and TLSv1.3."
}
```

---

### **Bước 4 — Xem tổng kết**
Khi chạy xong, màn hình sẽ hiện:

```
🔍 Detected 27 YAML rules — starting evaluation...

✅ CIS-NGINX-2.1.0-4.1.4.yaml → FAIL
✅ CIS-NGINX-2.1.0-4.1.7.yaml → PASS
✅ CIS-NGINX-2.1.0-4.1.9.yaml → Insufficient data to conclude

📊 Summary: 9 PASS / 13 FAIL / 5 Inconclusive
📄 Results saved at: nginx_report_results.json
```

---

## 🧠 Gợi ý
- Nên chạy bằng quyền **sudo** để thu thập đầy đủ thông tin hệ thống.  
- Nếu thấy trạng thái `"Insufficient data to conclude"` → cần kiểm tra lại file cấu hình hoặc quyền truy cập.  
- Toàn bộ logic đánh giá dựa theo **CIS Benchmark v2.1.0 for NGINX** và **v2.0.0 for Apache 2.4**.

---

✅ **Tóm lại:**
1️⃣ `python webserver_collector_auto.py` → phát hiện web server  
2️⃣ `python apache_agent.py` hoặc `python nginx_agent.py` → thu thập config  
3️⃣ `python check_file_apache.py` hoặc `python check_file_nginx.py` → đánh giá PASS / FAIL  
4️⃣ Xem kết quả trong `apache_report_results.json` hoặc `nginx_report_results.json`
