# GEMINI2.md — Dokumentasi API Endpoint (Referensi Frontend)

Dokumen ini berisi **daftar lengkap dan akurat** semua endpoint API backend FastAPI.
Gunakan sebagai referensi saat membangun frontend (Next.js, Laravel, Vanilla JS, dll).

**Base URL (Lokal):** `http://localhost:8081`  
**Base URL (Production):** `https://api-cysec.bilikku.my.id` *(sesuaikan)*

> **Semua endpoint (kecuali yang ditandai Publik) wajib menyertakan header:**
> ```
> Authorization: Bearer <access_token>
> Content-Type: application/json
> ```

---

## Daftar Endpoint

| No | Method | Endpoint | Auth | Keterangan |
|----|--------|----------|------|------------|
| 1 | POST | `/api/v1/auth/register` | ❌ | Registrasi user baru |
| 2 | POST | `/api/v1/auth/login` | ❌ | Login, dapatkan JWT |
| 3 | POST | `/api/v1/detect` | ✅ | **[PRIMARY]** Deteksi via gejala manual |
| 3b | POST | `/api/v1/diagnose` | ✅ | [Alias] Sama dengan `/detect` — backward compat |
| 4 | POST | `/api/v1/scan` | ✅ | Deteksi otomatis via Active Scanner (URL) |
| 5 | GET | `/api/v1/history/` | ✅ | Riwayat konsultasi user |
| 6 | GET | `/api/v1/attacks/` | ❌ Publik | Daftar referensi serangan |
| 7 | POST | `/api/v1/datasets/load` | ✅ | Muat dataset dari CSV ke DB |
| 8 | GET | `/api/v1/datasets/stats` | ✅ | Statistik jumlah dataset |

---

## 1. Authentication

### POST `/api/v1/auth/register`
Mendaftarkan user baru. **Tidak perlu token.**

**Content-Type:** `application/json`

**Request Body:**
```json
{
  "username": "admin123",
  "email": "admin@cybersec.local",
  "password": "strongpassword"
}
```

**Response `201 Created`:**
```json
{
  "id": 1,
  "username": "admin123",
  "email": "admin@cybersec.local"
}
```

**Error `400`** jika username/email sudah terdaftar.

---

### POST `/api/v1/auth/login`
Login dan dapatkan JWT Token. **Tidak perlu token.**

> ⚠️ **PENTING:** Endpoint ini menggunakan format **`application/x-www-form-urlencoded`** (bukan JSON).
> Ini adalah standar OAuth2 yang digunakan FastAPI.

**Content-Type:** `application/x-www-form-urlencoded`

**Request Body (Form Data):**
```
username=admin123&password=strongpassword
```

**Parameter tambahan (opsional):**
```
remember_me=true   ← token berlaku 30 hari (default: false = 60 menit)
```

**Response `200 OK`:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Cara pakai token ini di request berikutnya:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Error `401`** jika username/password salah.

**Contoh Fetch JS:**
```javascript
const formData = new URLSearchParams();
formData.append('username', 'admin123');
formData.append('password', 'strongpassword');

const res = await fetch('http://localhost:8081/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: formData.toString()
});
const { access_token } = await res.json();
```

---

## 2. Deteksi Serangan (Sistem Pakar + ML)

Ada **2 endpoint deteksi** dengan input yang berbeda:

| Endpoint | Input | Cocok untuk |
|----------|-------|-------------|
| `POST /api/v1/detect` | Symptoms (gejala manual) | Analisa log server, SOC analyst |
| `POST /api/v1/scan` | URL target | Audit / pen-test web app |

---

### POST `/api/v1/detect` ⭐ (Primary)
Mengirimkan daftar **gejala (symptoms)** secara manual. Engine menjalankan:
**Certainty Factor → Forward Chaining (Experta) → ML Fallback (Random Forest)**.

> `/api/v1/diagnose` juga tersedia sebagai **alias** yang mengarah ke endpoint yang sama persis.
> Gunakan `/detect` untuk implementasi baru.

**Request Body:**
```json
{
  "symptoms": ["port_scanning", "os_fingerprinting", "banner_grabbing"],
  "target_system": "web_server",
  "severity_hint": "high"
}
```

| Field | Tipe | Wajib | Keterangan |
|-------|------|-------|------------|
| `symptoms` | `string[]` | ✅ | Min 1, Maks 20 gejala. Gunakan exact string sesuai knowledge base |
| `target_system` | `string` | ❌ | `"web_server"`, `"database"`, `"network"`, `"user_endpoint"` |
| `severity_hint` | `string` | ❌ | `"low"`, `"medium"`, `"high"`, `"critical"` |

**Response `200 OK`:**
```json
{
  "session_id": "c3a7f8b9-1234-abcd-efgh-000000000001",
  "detected_attacks": [
    {
      "attack_type": "Reconnaissance",
      "confidence": 0.8892,
      "description": "Aktivitas pemindaian jaringan terdeteksi...",
      "mitre_id": "TA0043"
    }
  ],
  "defense_recommendations": [
    {
      "priority": 1,
      "action": "Block source IP di firewall",
      "tool_suggestion": "iptables / pfSense"
    },
    {
      "priority": 2,
      "action": "Aktifkan IDS rule untuk port scan detection",
      "tool_suggestion": "Snort / Suricata"
    }
  ],
  "analysis_duration_ms": 14.32,
  "from_cache": false
}
```

> `from_cache: true` artinya response diambil dari Redis (query identik sudah pernah dijalankan, sangat cepat).

**Error `422`** jika `symptoms` kosong atau format salah.

---

### POST `/api/v1/scan`
**Active Scanner** — Scanner akan secara otomatis melakukan crawling + pengujian payload ke URL target, mengekstrak gejala, lalu menjalankan engine diagnosis. 

**⚠️ Rate Limited: 5 request per menit per IP.**

**Request Body:**
```json
{
  "url": "http://127.0.0.1:8082/"
}
```

| Field | Tipe | Wajib | Keterangan |
|-------|------|-------|------------|
| `url` | `HttpUrl` | ✅ | URL target. Harus valid (http/https). HANYA scan URL yang Anda miliki. |

**Response `200 OK`:** *(format sama dengan `/diagnose`)*
```json
{
  "session_id": "uuid-scan-xxxxx",
  "detected_attacks": [
    {
      "attack_type": "SQL Injection",
      "confidence": 0.9234,
      "description": "Payload SQL berbahaya terdeteksi dalam request.",
      "mitre_id": "T1190"
    },
    {
      "attack_type": "Cross-Site Scripting (XSS)",
      "confidence": 0.8836,
      "description": "Script berbahaya ditemukan dalam input yang akan di-render.",
      "mitre_id": "T1059.007"
    },
    {
      "attack_type": "Brute Force Attack",
      "confidence": 0.8905,
      "description": "Percobaan login berulang dalam waktu singkat terdeteksi.",
      "mitre_id": "T1110"
    }
  ],
  "defense_recommendations": [...],
  "analysis_duration_ms": 4320.5,
  "from_cache": false
}
```

> ⚠️ **Catatan:** Proses scan bisa memakan waktu **3–30 detik** tergantung target. Pastikan frontend menampilkan loading state.

**Error `429`** jika melebihi rate limit.  
**Error `422`** jika URL tidak valid.

**Contoh Fetch JS:**
```javascript
const token = localStorage.getItem('access_token');

const res = await fetch('http://localhost:8081/api/v1/scan', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({ url: 'http://127.0.0.1:8082/' })
});

const result = await res.json();
// result.detected_attacks → array of attacks
// result.defense_recommendations → array of recommendations
```

---

## 3. History (Riwayat Konsultasi)

### GET `/api/v1/history/`
Mengambil riwayat konsultasi milik user yang sedang login.

**Response `200 OK`:**
```json
{
  "message": "Consultation history for admin123"
}
```

> 📝 Endpoint ini masih placeholder. Response akan dikembangkan lebih lanjut.

---

## 4. Attacks (Referensi Serangan) — Publik

### GET `/api/v1/attacks/`
Mengambil daftar referensi jenis serangan dari knowledge base. **Tidak perlu token.**

**Response `200 OK`:**
```json
[
  {
    "id": 1,
    "attack_type": "SQL Injection",
    "symptoms": ["sql_injection_pattern", "error_based_response"],
    "severity": "high",
    "mitre_id": "T1190"
  }
]
```

---

## 5. Dataset Management

### POST `/api/v1/datasets/load`
Memuat ulang semua dataset dari file CSV ke database PostgreSQL.

**Response `200 OK`:**
```json
{
  "message": "Datasets loaded successfully",
  "data": {
    "threat_intel_loaded": 1500,
    "cves_loaded": 300,
    "iocs_loaded": 2500,
    "total_loaded": 4300
  }
}
```

### GET `/api/v1/datasets/stats`
Menampilkan statistik jumlah data yang tersimpan di database.

**Response `200 OK`:**
```json
{
  "threat_intel": 1500,
  "cves": 300,
  "iocs": 2500
}
```

---

## 6. Daftar Gejala yang Valid (Knowledge Base)

Gunakan **exact string** berikut sebagai nilai dalam array `symptoms`:

### Reconnaissance
`port_scanning`, `os_fingerprinting`, `service_enumeration`, `banner_grabbing`, `network_mapping`, `ping_sweep`, `dns_enumeration`, `whois_lookup`, `traceroute_activity`, `idle_scan`, `version_detection`, `tcp_connect_scan`

### Brute Force Attack
`brute_force_login`, `multiple_failed_auth`, `high_login_attempts`, `credential_stuffing`, `password_spraying`, `dictionary_attack`, `account_lockout_triggered`, `rapid_auth_requests`, `failed_ssh_attempts`, `failed_rdp_attempts`, `auth_log_flooding`

### SQL Injection
`sql_injection_pattern`, `unusual_db_query`, `error_based_response`, `blind_sqli_timing`, `union_based_payload`, `stacked_queries`, `out_of_band_sqli`, `db_error_in_response`, `tautology_in_query`, `encoded_sql_payload`, `time_delay_response`, `boolean_blind_sqli`

### DDoS
`high_traffic_volume`, `service_degradation`, `syn_flood`, `udp_flood`, `http_flood`, `amplification_traffic`, `icmp_flood`, `slow_loris_attack`, `bandwidth_saturation`, `connection_exhaustion`, `dns_amplification`, `ntp_amplification`

### XSS
`xss_payload_detected`, `script_tag_in_input`, `dom_manipulation`, `cookie_theft_attempt`, `reflected_payload`, `stored_xss_payload`, `event_handler_injection`, `javascript_uri_injection`, `malicious_iframe_injection`, `html_entity_bypass`, `csp_bypass_attempt`

### Man-in-the-Middle (MitM)
`arp_spoofing`, `ssl_stripping`, `certificate_anomaly`, `dns_spoofing`, `unusual_gateway_mac`, `rogue_dhcp_server`, `packet_interception`, `session_hijacking`, `ssl_certificate_mismatch`, `bgp_hijacking`, `evil_twin_ap`, `ip_spoofing`

### Phishing
`suspicious_email_link`, `domain_spoofing`, `credential_harvesting`, `fake_login_page`, `email_header_anomaly`, `lookalike_domain`, `urgency_in_email`, `malicious_attachment`, `brand_impersonation`, `spear_phishing_indicators`, `whaling_attempt`, `vishing_indicators`

### Ransomware
`mass_file_encryption`, `ransom_note_created`, `shadow_copy_deletion`, `unusual_file_extension`, `c2_communication`, `file_rename_burst`, `backup_deletion`, `registry_modification`, `process_injection`, `lateral_movement`, `data_exfiltration_before_encryption`, `bitcoin_address_in_note`

---

## 7. Kode Error yang Mungkin Terjadi

| Kode | Artinya | Penyebab Umum |
|------|---------|---------------|
| `400` | Bad Request | Data tidak valid (username sudah ada, dll) |
| `401` | Unauthorized | Token tidak ada, salah, atau expired |
| `422` | Validation Error | Format body salah (symptoms kosong, URL tidak valid) |
| `429` | Too Many Requests | Rate limit `/scan` terlampaui (maks 5/menit per IP) |
| `500` | Internal Server Error | Engine error, DB down, atau bug di server |

---

## 8. Flow Frontend yang Direkomendasikan

```
1. User buka halaman → cek token di localStorage
2. Jika tidak ada token → redirect ke halaman login
3. Login → simpan access_token di localStorage/cookie
4. Kirim request ke /diagnose atau /scan dengan Bearer token
5. Tampilkan detected_attacks + defense_recommendations
6. Jika response from_cache: true → tampilkan badge "Cached"
7. Jika error 401 → hapus token, redirect ke login
8. Jika error 429 → tampilkan "Terlalu banyak scan, tunggu 1 menit"
```
