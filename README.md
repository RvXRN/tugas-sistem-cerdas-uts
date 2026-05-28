# Cybersecurity Expert System API

Sistem Pakar Keamanan Siber dengan pendekatan *Hybrid Engine*: **Certainty Factor (CF) + Forward Chaining (Experta) + Machine Learning (Random Forest)**.

API ini dibuat dengan **FastAPI** dan mengembalikan hasil diagnosa berdasarkan gejala (symptoms) yang diberikan.

---

## 🚀 Cara Menjalankan Server API

Pastikan Anda berada di root direktori proyek (`d:\tugasapipakindrawan`), lalu jalankan server menggunakan Uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Jika berhasil, server akan berjalan di: **http://localhost:8000**

---

## 📖 Dokumentasi API Otomatis (Swagger UI)

FastAPI secara otomatis men-generate UI interaktif untuk mencoba API tanpa perlu Postman atau kode.
Buka browser Anda dan kunjungi:

👉 **http://localhost:8000/docs**

Di sana Anda bisa melihat semua endpoint yang tersedia, model datanya, dan langsung mencoba mengirim request (klik tombol **"Try it out"**).

---

## ⚡ Endpoint Utama: `/api/v1/diagnose`

Ini adalah endpoint paling penting untuk mendiagnosa jenis serangan. 

**Metode**: `POST`  
**URL**: `http://localhost:8000/api/v1/diagnose`

### Format Request (JSON)
Anda wajib mengirimkan array berisi `symptoms` (minimal 1 gejala). `target_system` dan `severity_hint` bersifat opsional.

```json
{
  "symptoms": [
    "brute_force_login",
    "multiple_failed_auth"
  ],
  "target_system": "web_server",
  "severity_hint": "high"
}
```

### Format Response (JSON)
Sistem akan mengembalikan jenis serangan yang terdeteksi, tingkat keyakinan (confidence score), dan rekomendasi penanganan (*Defense Recommendation*).

```json
{
  "session_id": "c3a7f8b9-...",
  "detected_attacks": [
    {
      "attack_type": "Brute Force Attack",
      "confidence": 0.9215,
      "description": "Percobaan login berulang dalam waktu singkat terdeteksi.",
      "mitre_id": "T1110"
    }
  ],
  "defense_recommendations": [
    {
      "priority": 1,
      "action": "Implementasi rate limiting",
      "tool_suggestion": "Nginx rate_limit / FastAPI slowapi"
    },
    {
      "priority": 2,
      "action": "Aktifkan CAPTCHA setelah N kali gagal",
      "tool_suggestion": "hCaptcha"
    }
  ],
  "analysis_duration_ms": 12.45,
  "from_cache": false
}
```

---

## 💻 Contoh Penggunaan API

### 1. Menggunakan cURL (Terminal/Command Prompt)

```bash
curl -X 'POST' \
  'http://localhost:8000/api/v1/diagnose' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "symptoms": ["port_scanning", "os_fingerprinting"],
  "target_system": "web_server"
}'
```

### 2. Menggunakan Python (Requests)

```python
import requests

url = "http://localhost:8000/api/v1/diagnose"
payload = {
    "symptoms": ["sql_injection_pattern", "unusual_db_query"],
    "target_system": "database",
    "severity_hint": "high"
}

response = requests.post(url, json=payload)
data = response.json()

print("Serangan Terdeteksi:")
for attack in data.get("detected_attacks", []):
    print(f"- {attack['attack_type']} (Confidence: {attack['confidence'] * 100:.2f}%)")

print("\nRekomendasi Perbaikan:")
for rec in data.get("defense_recommendations", []):
    print(f"{rec['priority']}. {rec['action']} (Tool: {rec['tool_suggestion']})")
```

### 3. Menggunakan JavaScript (Fetch API / Next.js)

Contoh cara memanggil API dari Frontend Next.js atau vanilla JS:

```javascript
async function diagnoseAttack(symptoms) {
  const response = await fetch("http://localhost:8000/api/v1/diagnose", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      symptoms: symptoms,
      target_system: "web_server"
    })
  });

  const result = await response.json();
  console.log("Diagnosis Result:", result);
  return result;
}

// Cara panggil:
// diagnoseAttack(["xss_payload_detected", "cookie_theft_attempt"]);
```

---

## 🛠️ Daftar Lengkap Gejala yang Tersedia (Sesuai Knowledge Base)

Untuk mendapatkan hasil yang akurat, gunakan nama gejala persis seperti list di bawah ini:

- **Reconnaissance**: `port_scanning`, `os_fingerprinting`, `service_enumeration`, `banner_grabbing`, `network_mapping`, `ping_sweep`, `dns_enumeration`, `whois_lookup`, `traceroute_activity`, `idle_scan`, `version_detection`, `tcp_connect_scan`
- **Brute Force Attack**: `brute_force_login`, `multiple_failed_auth`, `high_login_attempts`, `credential_stuffing`, `password_spraying`, `dictionary_attack`, `account_lockout_triggered`, `rapid_auth_requests`, `failed_ssh_attempts`, `failed_rdp_attempts`, `auth_log_flooding`
- **SQL Injection**: `sql_injection_pattern`, `unusual_db_query`, `error_based_response`, `blind_sqli_timing`, `union_based_payload`, `stacked_queries`, `out_of_band_sqli`, `db_error_in_response`, `tautology_in_query`, `encoded_sql_payload`, `time_delay_response`, `boolean_blind_sqli`
- **DDoS**: `high_traffic_volume`, `service_degradation`, `syn_flood`, `udp_flood`, `http_flood`, `amplification_traffic`, `icmp_flood`, `slow_loris_attack`, `bandwidth_saturation`, `connection_exhaustion`, `dns_amplification`, `ntp_amplification`
- **XSS**: `xss_payload_detected`, `script_tag_in_input`, `dom_manipulation`, `cookie_theft_attempt`, `reflected_payload`, `stored_xss_payload`, `event_handler_injection`, `javascript_uri_injection`, `malicious_iframe_injection`, `html_entity_bypass`, `csp_bypass_attempt`
- **MitM**: `arp_spoofing`, `ssl_stripping`, `certificate_anomaly`, `dns_spoofing`, `unusual_gateway_mac`, `rogue_dhcp_server`, `packet_interception`, `session_hijacking`, `ssl_certificate_mismatch`, `bgp_hijacking`, `evil_twin_ap`, `ip_spoofing`
- **Phishing**: `suspicious_email_link`, `domain_spoofing`, `credential_harvesting`, `fake_login_page`, `email_header_anomaly`, `lookalike_domain`, `urgency_in_email`, `malicious_attachment`, `brand_impersonation`, `spear_phishing_indicators`, `whaling_attempt`, `vishing_indicators`
- **Ransomware**: `mass_file_encryption`, `ransom_note_created`, `shadow_copy_deletion`, `unusual_file_extension`, `c2_communication`, `file_rename_burst`, `backup_deletion`, `registry_modification`, `process_injection`, `lateral_movement`, `data_exfiltration_before_encryption`, `bitcoin_address_in_note`

---

## 🔍 Endpoint Active Scanner: `/api/v1/scan`

Endpoint ini melakukan **pemindaian aktif** terhadap URL target. Scanner akan secara otomatis:

1. **Web Crawling** — Menjelajahi semua halaman internal (BFS)
2. **Reconnaissance** — Deteksi banner server (`Server`, `X-Powered-By`)
3. **SQL Injection** — Error-based, UNION-based, Time-based blind, Boolean-blind
4. **XSS** — Reflected, Event handler injection, Javascript URI injection
5. **Brute Force** — Rate limit test pada form/endpoint login (20 request)
6. **DDoS Resilience** — HTTP Flood test (concurrent request)
7. **SSL / MitM** — Pemeriksaan HTTPS dan HSTS
8. **Phishing** — Brand impersonation dan credential harvesting detection

**Metode**: `POST`  
**URL**: `http://localhost:8000/api/v1/scan`  
**Rate Limit**: **5 request/menit per IP** (dilindungi slowapi)

### Format Request

```json
{
  "url": "https://target-yang-anda-miliki.com"
}
```

### Contoh dengan cURL

```bash
curl -X POST 'http://localhost:8000/api/v1/scan' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://localhost:8080/"}'
```

---

## 🛡️ Keamanan & Penggunaan yang Etis

> [!WARNING]
> Fitur **Active Scanner** (`/api/v1/scan`) akan mengirimkan payload seperti SQL Injection dan XSS ke URL target. Fitur ini **HANYA boleh digunakan pada sistem yang Anda miliki atau yang Anda telah mendapat izin tertulis untuk melakukan penetration testing**.

### Perlindungan yang sudah diterapkan:

| Layer | Mekanisme |
|---|---|
| **Autentikasi** | Semua endpoint memerlukan JWT Bearer Token (`/api/v1/auth/login`) |
| **Rate Limiting** | Endpoint `/scan` dibatasi **5 request/menit per IP** menggunakan `slowapi` |
| **Input Validation** | Semua request divalidasi melalui Pydantic Schema |
| **Redis Caching** | Response identik di-cache 1 jam untuk mengurangi beban engine |

### ⚠️ Penggunaan yang dilarang:
- Men-scan website milik orang lain tanpa izin
- Menggunakan API ini sebagai alat serangan nyata
- Bypass autentikasi untuk mengakses endpoint secara ilegal

Pelanggaran dapat dikenai sanksi berdasarkan **UU ITE Pasal 30 tentang Akses Ilegal terhadap Sistem Elektronik**.

---

## 🧪 Pengujian Lokal (Dummy Vulnerable Server)

Untuk menguji fitur Active Scanner tanpa menyentuh sistem nyata, gunakan server simulasi yang sudah tersedia:

```bash
# Terminal 1 — Jalankan server web rentan (simulasi)
python test_dummy_vuln_server.py
# Berjalan di http://127.0.0.1:8080

# Terminal 2 — Jalankan backend utama
uvicorn app.main:app --reload

# Kemudian buka test_frontend.html di browser dan masukkan:
# http://127.0.0.1:8080/ pada kolom Active Scanner
```

Server dummy ini mensimulasikan: SQL Injection, XSS, tanpa rate limiting (rentan Brute Force), banner disclosure, brand impersonation (Phishing), dan credential harvesting.
