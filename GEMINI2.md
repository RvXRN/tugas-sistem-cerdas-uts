# GEMINI2.md — Dokumentasi API Endpoint untuk Integrasi Frontend (Laravel)

Dokumen ini berisi daftar endpoint API yang tersedia di Backend FastAPI untuk mempermudah pembuatan UI/Frontend menggunakan Laravel 13.

Semua request yang tidak bersifat publik memerlukan Header otorisasi:
`Authorization: Bearer <token_jwt_disini>`

---

## 1. Authentication (Auth)

### 1.1 Login User
Digunakan untuk mendapatkan JWT Token. Endpoint ini menggunakan standar OAuth2 `application/x-www-form-urlencoded` bukan JSON!

- **URL:** `/api/v1/auth/login`
- **Method:** `POST`
- **Headers:** `Content-Type: application/x-www-form-urlencoded`
- **Body (Form Data):**
  - `username` (string, required)
  - `password` (string, required)
- **Response Success (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUz...",
  "token_type": "bearer"
}
```

### 1.2 Register User (Opsional/Internal)
- **URL:** `/api/v1/auth/register`
- **Method:** `POST`
- **Headers:** `Content-Type: application/json`
- **Body:**
```json
{
  "username": "admin123",
  "password": "strongpassword",
  "email": "admin@cybersec.local"
}
```

---

## 2. Diagnosis (Sistem Pakar)

### 2.1 Lakukan Diagnosa (ML / Rule-based)
Mengirimkan *symptoms* untuk mendiagnosa jenis serangan. 
- **URL:** `/api/v1/diagnose`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Body:**
```json
{
  "symptoms": ["port_scanning", "high_traffic_volume", "os_fingerprinting"],
  "target_system": "web_server",
  "severity_hint": "high"
}
```
> **Catatan Penting:** Engine saat ini distandarisasi untuk mendeteksi **8 Kategori Serangan Utama** (Reconnaissance, Brute Force, SQL Injection, DDoS, XSS, MitM, Phishing, Ransomware). Pastikan input `symptoms` menggunakan *exact string match* dengan dictionary gejala yang didukung (contoh: `port_scanning`, `sql_injection_pattern`, `mass_file_encryption`).

- **Response Success (200 OK):**
```json
{
  "session_id": "uuid-1234-abcd",
  "detected_attacks": [
    {
      "attack_type": "Distributed Denial of Service (DDoS)",
      "confidence": 0.88,
      "description": "Serangan DDoS terdeteksi ...",
      "mitre_id": "T1498"
    }
  ],
  "defense_recommendations": [
    {
      "priority": 1,
      "action": "Aktifkan DDoS protection layer",
      "tool_suggestion": "Cloudflare / AWS Shield"
    }
  ],
  "analysis_duration_ms": 12.5,
  "from_cache": false
}
```

---

## 3. History (Riwayat Konsultasi)

### 3.1 Ambil Semua Riwayat
- **URL:** `/api/v1/history/`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <token>`
- **Response Success (200 OK):**
```json
[
  {
    "id": 1,
    "session_id": "uuid-1234-abcd",
    "timestamp": "2026-05-27T10:00:00",
    "symptoms": ["port_scanning"],
    "target_system": "web_server",
    "detected_attacks": [...]
  }
]
```

---

## 4. Dataset Management

### 4.1 Muat Ulang Dataset dari CSV
- **URL:** `/api/v1/datasets/load`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <token>`
- **Response Success (200 OK):**
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

### 4.2 Cek Statistik Dataset
- **URL:** `/api/v1/datasets/stats`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <token>`
- **Response Success (200 OK):**
```json
{
  "threat_intel": 1500,
  "cves": 300,
  "iocs": 2500
}
```

---

## 5. Attacks (Threat Intelligence)

### 5.1 Daftar Referensi Serangan Terkenal
*(Endpoint Publik - Tanpa Auth)*
- **URL:** `/api/v1/attacks/`
- **Method:** `GET`
- **Response Success (200 OK):**
```json
[
  {
    "id": 1,
    "attack_type": "SQL Injection",
    "symptoms": ["sql_injection_pattern"],
    "severity": "high",
    "mitre_id": "T1190"
  }
]
```
