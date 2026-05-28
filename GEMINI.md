# GEMINI.md — Panduan Arsitektur Backend Sistem Pakar Cybersecurity

> Dokumen ini mencakup arsitektur modular, struktur direktori, implementasi kode inti, dan strategi pengembangan jangka panjang untuk backend sistem pakar **attack & defense** berbasis FastAPI + Experta + PostgreSQL + Redis.

---

## Daftar Isi

0. [Metode yang Digunakan](#0-metode-yang-digunakan)
1. [Gambaran Arsitektur](#1-gambaran-arsitektur)
2. [Struktur Direktori](#2-struktur-direktori)
3. [Implementasi Kode Inti](#3-implementasi-kode-inti)
   - 3.1 [Pydantic Schemas](#31-pydantic-schemas)
   - 3.2 [Experta Engine](#32-experta-engine)
   - 3.3 [FastAPI Endpoint](#33-fastapi-endpoint)
4. [Koneksi Database](#4-koneksi-database)
   - 4.1 [PostgreSQL dengan SQLAlchemy](#41-postgresql-dengan-sqlalchemy)
   - 4.2 [Redis untuk Caching](#42-redis-untuk-caching)
5. [Startup & Dataset Loading](#5-startup--dataset-loading)
6. [Future-Proof Strategy](#6-future-proof-strategy)
   - 6.1 [Migrasi ke Machine Learning](#61-migrasi-ke-machine-learning)
   - 6.2 [Optimalisasi Redis](#62-optimalisasi-redis)
7. [Menjalankan Project](#7-menjalankan-project)

---

## 0. Metode yang Digunakan

### Forward Chaining + Certainty Factor (CF)

Project ini menggunakan **dua metode yang saling melengkapi**:

| Metode | Peran dalam sistem |
|---|---|
| **Forward Chaining** | Mesin inferensi — cocokkan fakta gejala ke rules secara berantai |
| **Certainty Factor** | Hitung tingkat keyakinan diagnosis dari kombinasi beberapa gejala |

---

### Forward Chaining — Cara Kerjanya

Forward Chaining adalah strategi inferensi yang berangkat dari **fakta yang diketahui**, lalu maju ke depan untuk menarik kesimpulan.

```
Fakta masuk (gejala)
       │
       ▼
┌─────────────────────────────────┐
│   Agenda (antrian rules aktif)  │
│                                 │
│   Rule R1: IF A AND B → C  ✓   │  ← match, eksekusi
│   Rule R2: IF A AND D → E  ✗   │  ← tidak match
│   Rule R3: IF C AND F → G  ✓   │  ← match setelah C di-assert
└─────────────────────────────────┘
       │
       ▼
 Kesimpulan (jenis serangan)
```

Proses ini dijalankan otomatis oleh **Experta** sampai tidak ada lagi rule yang bisa dieksekusi (*fixed point*).

---

### Certainty Factor — Cara Kerjanya

CF diperkenalkan di sistem pakar MYCIN (1970-an) dan masih relevan sampai sekarang. Nilainya berkisar antara **-1.0 sampai 1.0**:

```
 -1.0          0.0          +1.0
  │─────────────│─────────────│
Pasti        Tidak         Pasti
 BUKAN        tahu          IYA
```

**Formula kombinasi CF:**

Ketika dua gejala mendukung kesimpulan yang sama, CF-nya digabungkan dengan rumus:

```
Jika CF(A) > 0 dan CF(B) > 0:
  CF_combined = CF(A) + CF(B) × (1 - CF(A))

Jika CF(A) < 0 dan CF(B) < 0:
  CF_combined = CF(A) + CF(B) × (1 + CF(A))

Jika salah satu positif dan satu negatif:
  CF_combined = (CF(A) + CF(B)) / (1 - min(|CF(A)|, |CF(B)|))
```

**Contoh nyata di project ini:**

```
Gejala: port_scanning     → CF = 0.7  (cukup kuat)
Gejala: os_fingerprinting → CF = 0.6  (cukup kuat)

CF_combined = 0.7 + 0.6 × (1 - 0.7)
            = 0.7 + 0.6 × 0.3
            = 0.7 + 0.18
            = 0.88  → Reconnaissance terdeteksi dengan keyakinan 88%
```

---

### Implementasi CF di Engine

```python
# app/engine/certainty_factor.py

from dataclasses import dataclass
from typing import List


@dataclass
class CFRule:
    """Satu rule dengan nilai CF untuk setiap gejala pendukungnya."""
    attack_type: str
    symptoms: dict[str, float]   # {"nama_gejala": nilai_cf}
    base_cf: float               # CF dasar rule ini


def combine_cf(cf1: float, cf2: float) -> float:
    """
    Kombinasikan dua nilai CF menggunakan formula standar MYCIN.
    Kedua nilai harus berada di rentang [-1.0, 1.0].
    """
    if cf1 >= 0 and cf2 >= 0:
        return cf1 + cf2 * (1 - cf1)
    elif cf1 < 0 and cf2 < 0:
        return cf1 + cf2 * (1 + cf1)
    else:
        return (cf1 + cf2) / (1 - min(abs(cf1), abs(cf2)))


def calculate_attack_cf(
    rule: CFRule,
    observed_symptoms: List[str],
    symptom_cf_map: dict[str, float] = None
) -> float:
    """
    Hitung CF akhir untuk satu jenis serangan berdasarkan gejala yang diamati.

    Args:
        rule: Rule dengan daftar gejala dan CF masing-masing
        observed_symptoms: Gejala yang dikirim user
        symptom_cf_map: Override CF per gejala (opsional, default pakai rule.symptoms)

    Returns:
        CF akhir antara 0.0 - 1.0, atau 0.0 jika tidak ada gejala yang match
    """
    cf_map = symptom_cf_map or rule.symptoms
    matched_cfs = []

    for symptom in observed_symptoms:
        if symptom in cf_map:
            matched_cfs.append(cf_map[symptom])

    if not matched_cfs:
        return 0.0

    # Kombinasikan semua CF yang match secara berantai
    final_cf = matched_cfs[0]
    for cf in matched_cfs[1:]:
        final_cf = combine_cf(final_cf, cf)

    # Kalikan dengan CF dasar rule
    return round(final_cf * rule.base_cf, 4)


# ── Knowledge base CF rules ───────────────────────────────────────────────────
# Nilai CF tiap gejala ditentukan berdasarkan seberapa kuat gejala itu
# mengindikasikan serangan tertentu. Sumber: literatur + judgment pakar.

CF_RULES: List[CFRule] = [
    CFRule(
        attack_type="Reconnaissance",
        base_cf=0.95,
        symptoms={
            "port_scanning":      0.80,
            "os_fingerprinting":  0.75,
            "service_enumeration": 0.70,
            "banner_grabbing":    0.65,
            "network_mapping":    0.72,
        }
    ),
    CFRule(
        attack_type="Brute Force Attack",
        base_cf=0.95,
        symptoms={
            "brute_force_login":      0.85,
            "multiple_failed_auth":   0.80,
            "high_login_attempts":    0.78,
            "credential_stuffing":    0.82,
            "password_spraying":      0.75,
        }
    ),
    CFRule(
        attack_type="SQL Injection",
        base_cf=0.97,
        symptoms={
            "sql_injection_pattern":  0.90,
            "unusual_db_query":       0.75,
            "error_based_response":   0.70,
            "blind_sqli_timing":      0.80,
            "union_based_payload":    0.85,
        }
    ),
    CFRule(
        attack_type="Distributed Denial of Service (DDoS)",
        base_cf=0.92,
        symptoms={
            "high_traffic_volume":    0.80,
            "service_degradation":    0.75,
            "syn_flood":              0.85,
            "udp_flood":              0.83,
            "http_flood":             0.80,
            "amplification_traffic":  0.78,
        }
    ),
    CFRule(
        attack_type="Cross-Site Scripting (XSS)",
        base_cf=0.94,
        symptoms={
            "xss_payload_detected":   0.88,
            "script_tag_in_input":    0.85,
            "dom_manipulation":       0.72,
            "cookie_theft_attempt":   0.80,
            "reflected_payload":      0.82,
        }
    ),
    CFRule(
        attack_type="Man-in-the-Middle (MitM)",
        base_cf=0.90,
        symptoms={
            "arp_spoofing":           0.82,
            "ssl_stripping":          0.85,
            "certificate_anomaly":    0.78,
            "dns_spoofing":           0.80,
            "unusual_gateway_mac":    0.75,
        }
    ),
    CFRule(
        attack_type="Phishing",
        base_cf=0.91,
        symptoms={
            "suspicious_email_link":  0.80,
            "domain_spoofing":        0.82,
            "credential_harvesting":  0.78,
            "fake_login_page":        0.85,
            "email_header_anomaly":   0.70,
        }
    ),
    CFRule(
        attack_type="Ransomware",
        base_cf=0.96,
        symptoms={
            "mass_file_encryption":   0.92,
            "ransom_note_created":    0.95,
            "shadow_copy_deletion":   0.88,
            "unusual_file_extension": 0.80,
            "c2_communication":       0.82,
        }
    ),
]


def diagnose_with_cf(
    observed_symptoms: List[str],
    threshold: float = 0.40
) -> List[dict]:
    """
    Jalankan semua CF rules terhadap gejala yang diberikan.

    Args:
        observed_symptoms: List gejala dari user
        threshold: CF minimum agar serangan dianggap terdeteksi (default 0.40)

    Returns:
        List hasil diagnosa yang melewati threshold, diurutkan dari CF tertinggi
    """
    results = []

    for rule in CF_RULES:
        cf_value = calculate_attack_cf(rule, observed_symptoms)
        if cf_value >= threshold:
            results.append({
                "attack_type": rule.attack_type,
                "confidence": cf_value,
                "matched_symptoms": [s for s in observed_symptoms if s in rule.symptoms],
            })

    # Urutkan dari confidence tertinggi
    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results
```

---

### Integrasi CF ke dalam Experta Engine

CF dihitung **sebelum** rule Experta di-fire. Nilainya di-inject sebagai bagian dari Fact, sehingga Experta bisa menggunakannya dalam rules.

```python
# Modifikasi di app/routers/diagnosis.py — bagian _run_engine

from app.engine.certainty_factor import diagnose_with_cf

async def _run_engine(request: DiagnosisRequest) -> list:
    """
    Gabungan Forward Chaining (Experta) + Certainty Factor.
    CF dihitung duluan, hasilnya di-inject ke Facts Experta.
    """
    # Step 1: Hitung CF untuk semua kemungkinan serangan
    cf_results = diagnose_with_cf(request.symptoms, threshold=0.40)

    # Step 2: Jalankan Experta untuk validasi struktural + rekomendasi
    engine = CybersecurityExpertEngine()
    engine.reset()

    for symptom in request.symptoms:
        engine.declare(AttackSymptom(name=symptom))

    if request.target_system:
        engine.declare(TargetSystem(type=request.target_system))

    engine.run()

    # Step 3: Gabungkan — CF score di-merge ke hasil Experta
    experta_attacks = {
        fact["attack_type"]: fact
        for fact in engine.facts.values()
        if isinstance(fact, DetectedAttack)
    }

    final_results = []
    for cf_result in cf_results:
        attack_type = cf_result["attack_type"]
        experta_data = experta_attacks.get(attack_type, {})

        final_results.append({
            "attack_type": attack_type,
            "confidence": cf_result["confidence"],   # Pakai CF score
            "matched_symptoms": cf_result["matched_symptoms"],
            "description": experta_data.get("description", ""),
            "mitre_id": experta_data.get("mitre_id"),
            "recommendations": experta_data.get("recommendations", []),
        })

    return final_results if final_results else [{
        "attack_type": "Unknown / Insufficient Data",
        "confidence": 0.0,
        "matched_symptoms": [],
        "description": "Gejala tidak cukup atau tidak cocok dengan pola serangan yang diketahui.",
        "mitre_id": None,
        "recommendations": [
            {"priority": 1, "action": "Analisis log manual lebih mendalam", "tool": "ELK Stack / Splunk"},
            {"priority": 2, "action": "Jalankan vulnerability scanner", "tool": "Nessus / OpenVAS"},
        ],
    }]
```

---

### Kenapa Kombinasi Ini?

```
Forward Chaining saja        → tahu APA serangannya, tapi tidak tahu SEBERAPA YAKIN
Certainty Factor saja        → tahu confidence-nya, tapi tidak ada rekomendasi terstruktur
FC + CF (yang dipakai ini)   → tahu APA, SEBERAPA YAKIN, dan APA YANG HARUS DILAKUKAN
```

Ini juga yang paling mudah dijelaskan di sidang skripsi — setiap angka confidence bisa di-trace balik ke gejala mana yang berkontribusi dan berapa CF-nya.

---

## 1. Gambaran Arsitektur

Sistem ini dibangun di atas **tiga layer utama** yang dipisahkan secara tegas berdasarkan tanggung jawabnya:

```
┌─────────────────────────────────────────────────────┐
│                  Frontend (Next.js)                  │
│              REST API calls via fetch/axios          │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP JSON
┌──────────────────────▼──────────────────────────────┐
│              Layer 1 — REST API (FastAPI)            │
│   Validasi request, routing, response formatting     │
└──────────┬───────────────────────┬──────────────────┘
           │                       │
┌──────────▼──────────┐ ┌──────────▼──────────────────┐
│  Layer 2 — Engine   │ │   Layer 3 — Storage         │
│  (Experta / ML)     │ │   PostgreSQL  │  Redis       │
│  Forward chaining   │ │   Dataset     │  Cache       │
│  Rule matching      │ │   History     │  Session     │
└─────────────────────┘ └─────────────────────────────┘
```

### Alur Request

1. Frontend Next.js mengirim POST request berisi gejala serangan dalam format JSON.
2. FastAPI menerima dan memvalidasi data via **Pydantic Schema**.
3. Data yang sudah valid di-mapping ke objek `Fact` lalu dilempar ke **Experta Engine**.
4. Engine melakukan *forward chaining* — mencocokkan fakta ke rules yang terdaftar.
5. Hasil diagnosa dikembalikan ke frontend sebagai JSON response.
6. Response di-cache di **Redis** sehingga query identik tidak perlu re-run engine.

---

## 2. Struktur Direktori

```
cybersecurity-expert-system/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  # Entry point FastAPI
│   │   ├── config.py                # Environment variables
│   │   │
│   │   ├── engine/                  # Inference engine layer
│   │   │   ├── __init__.py
│   │   │   ├── knowledge_base.py    # Definisi Rules (@Rule decorator)
│   │   │   ├── facts.py             # Definisi Fact classes
│   │   │   └── loader.py            # Load dataset dari PostgreSQL ke engine
│   │   │
│   │   ├── schemas/                 # Pydantic models (validasi I/O)
│   │   │   ├── __init__.py
│   │   │   ├── diagnosis.py         # Schema request & response diagnosa
│   │   │   └── attack.py            # Schema data serangan
│   │   │
│   │   ├── models/                  # SQLAlchemy ORM models
│   │   │   ├── __init__.py
│   │   │   ├── attack.py            # Tabel attacks
│   │   │   └── history.py           # Tabel riwayat konsultasi
│   │   │
│   │   ├── routers/                 # FastAPI route handlers
│   │   │   ├── __init__.py
│   │   │   ├── diagnosis.py         # POST /diagnose
│   │   │   ├── attacks.py           # GET /attacks
│   │   │   └── history.py           # GET /history
│   │   │
│   │   ├── services/                # Business logic layer
│   │   │   ├── __init__.py
│   │   │   ├── diagnosis_service.py
│   │   │   └── cache_service.py     # Redis wrapper
│   │   │
│   │   └── database.py              # Koneksi PostgreSQL + Redis
│   │
│   ├── dataset/
│   │   └── attacks.csv              # Dataset serangan (sumber kebenaran)
│   │
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env
│
├── frontend/                        # Next.js app (terpisah)
└── docker-compose.yml
```

---

## 3. Implementasi Kode Inti

### 3.1 Pydantic Schemas

Schemas ini adalah **gerbang pertama** — semua data dari frontend wajib lolos validasi ini sebelum menyentuh engine. Tidak ada data ghosting yang bisa masuk.

```python
# app/schemas/diagnosis.py

from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DiagnosisRequest(BaseModel):
    """
    Schema validasi untuk request diagnosa dari frontend.
    Semua field dengan tipe eksplisit — tidak ada ambiguitas.
    """
    symptoms: List[str] = Field(
        ...,
        min_items=1,
        max_items=20,
        description="Daftar gejala yang diamati, contoh: ['port_scanning', 'high_traffic']"
    )
    target_system: Optional[str] = Field(
        default=None,
        description="Sistem yang diserang, contoh: 'web_server', 'database'"
    )
    severity_hint: Optional[SeverityLevel] = Field(
        default=None,
        description="Estimasi tingkat keparahan dari analis (opsional)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "symptoms": ["port_scanning", "brute_force_login", "unusual_outbound_traffic"],
                "target_system": "web_server",
                "severity_hint": "high"
            }
        }


class AttackResult(BaseModel):
    """Representasi satu hasil diagnosa dari engine."""
    attack_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    mitre_id: Optional[str] = None  # Referensi MITRE ATT&CK


class DefenseRecommendation(BaseModel):
    """Satu langkah rekomendasi mitigasi."""
    priority: int = Field(..., ge=1, le=5)
    action: str
    tool_suggestion: Optional[str] = None


class DiagnosisResponse(BaseModel):
    """Schema response yang dikembalikan ke frontend."""
    session_id: str
    detected_attacks: List[AttackResult]
    defense_recommendations: List[DefenseRecommendation]
    analysis_duration_ms: float
    from_cache: bool = False
```

---

### 3.2 Experta Engine

Ini jantung dari sistem pakar. Engine menggunakan **forward chaining** — cocokkan semua fakta yang masuk ke rules yang ada, lalu jalankan aksi yang sesuai.

```python
# app/engine/facts.py

from experta import Fact


class AttackSymptom(Fact):
    """
    Representasi satu gejala serangan sebagai Fact.
    
    Contoh penggunaan:
        AttackSymptom(name="port_scanning", intensity="high")
    """
    pass


class TargetSystem(Fact):
    """Fakta tentang sistem yang menjadi target."""
    pass


class DetectedAttack(Fact):
    """
    Fakta yang di-assert oleh rules ketika serangan terdeteksi.
    Engine akan mengumpulkan semua Fact jenis ini sebagai hasil akhir.
    """
    pass
```

```python
# app/engine/knowledge_base.py

from experta import KnowledgeEngine, Rule, AND, OR, NOT, MATCH, Fact
from app.engine.facts import AttackSymptom, TargetSystem, DetectedAttack
import logging

logger = logging.getLogger(__name__)


class CybersecurityExpertEngine(KnowledgeEngine):
    """
    Engine sistem pakar keamanan siber.
    
    Setiap @Rule mendefinisikan satu pola serangan.
    Engine secara otomatis melakukan forward chaining
    dan mencocokkan semua fakta yang di-declare.
    """

    # ─── Rules: Reconnaissance ────────────────────────────────────────────────

    @Rule(
        AttackSymptom(name="port_scanning"),
        AttackSymptom(name="os_fingerprinting")
    )
    def detect_reconnaissance(self):
        """Rule: Kombinasi port scanning + OS fingerprinting → Reconnaissance."""
        logger.info("[ENGINE] Rule fired: Reconnaissance detected")
        self.declare(DetectedAttack(
            attack_type="Reconnaissance",
            confidence=0.90,
            description=(
                "Aktivitas pemindaian jaringan terdeteksi. Penyerang sedang "
                "memetakan topologi dan layanan aktif sebelum eksploitasi."
            ),
            mitre_id="TA0043",
            recommendations=[
                {"priority": 1, "action": "Block source IP di firewall", "tool": "iptables / pfSense"},
                {"priority": 2, "action": "Aktifkan IDS rule untuk port scan detection", "tool": "Snort / Suricata"},
                {"priority": 3, "action": "Sembunyikan banner service (version hiding)", "tool": "nginx / Apache config"},
            ]
        ))

    # ─── Rules: Brute Force ───────────────────────────────────────────────────

    @Rule(
        AttackSymptom(name="brute_force_login"),
        OR(
            AttackSymptom(name="multiple_failed_auth"),
            AttackSymptom(name="high_login_attempts")
        )
    )
    def detect_brute_force(self):
        """Rule: Brute force login dengan banyak kegagalan autentikasi."""
        logger.info("[ENGINE] Rule fired: Brute Force detected")
        self.declare(DetectedAttack(
            attack_type="Brute Force Attack",
            confidence=0.92,
            description=(
                "Percobaan login berulang dalam waktu singkat terdeteksi. "
                "Kemungkinan menggunakan wordlist atau credential stuffing."
            ),
            mitre_id="T1110",
            recommendations=[
                {"priority": 1, "action": "Implementasi rate limiting pada endpoint login", "tool": "Nginx rate_limit / FastAPI slowapi"},
                {"priority": 2, "action": "Aktifkan CAPTCHA setelah N kali gagal", "tool": "hCaptcha / reCAPTCHA"},
                {"priority": 3, "action": "Lockout akun setelah 5 kali percobaan gagal", "tool": "Custom middleware"},
                {"priority": 4, "action": "Aktifkan MFA untuk semua akun", "tool": "TOTP / Authy"},
            ]
        ))

    # ─── Rules: SQL Injection ─────────────────────────────────────────────────

    @Rule(
        AttackSymptom(name="sql_injection_pattern"),
        TargetSystem(type="database")
    )
    def detect_sql_injection(self):
        """Rule: Pola SQL injection yang menyasar database layer."""
        logger.info("[ENGINE] Rule fired: SQL Injection detected")
        self.declare(DetectedAttack(
            attack_type="SQL Injection",
            confidence=0.95,
            description=(
                "Payload SQL berbahaya terdeteksi dalam request. "
                "Penyerang mencoba memanipulasi query database secara langsung."
            ),
            mitre_id="T1190",
            recommendations=[
                {"priority": 1, "action": "Gunakan parameterized queries / ORM", "tool": "SQLAlchemy"},
                {"priority": 2, "action": "Validasi dan sanitasi semua input user", "tool": "Pydantic / bleach"},
                {"priority": 3, "action": "Terapkan principle of least privilege di DB", "tool": "PostgreSQL GRANT/REVOKE"},
                {"priority": 4, "action": "Aktifkan WAF rule untuk SQLi pattern", "tool": "ModSecurity / Cloudflare WAF"},
            ]
        ))

    # ─── Rules: DDoS ──────────────────────────────────────────────────────────

    @Rule(
        AttackSymptom(name="high_traffic_volume"),
        AttackSymptom(name="service_degradation"),
        OR(
            AttackSymptom(name="syn_flood"),
            AttackSymptom(name="udp_flood"),
            AttackSymptom(name="http_flood")
        )
    )
    def detect_ddos(self):
        """Rule: Indikasi DDoS berdasarkan volume traffic + degradasi layanan."""
        logger.info("[ENGINE] Rule fired: DDoS detected")
        self.declare(DetectedAttack(
            attack_type="Distributed Denial of Service (DDoS)",
            confidence=0.88,
            description=(
                "Lonjakan traffic abnormal menyebabkan degradasi layanan. "
                "Indikasi kuat serangan DDoS volumetric atau protocol-based."
            ),
            mitre_id="T1498",
            recommendations=[
                {"priority": 1, "action": "Aktifkan DDoS protection layer", "tool": "Cloudflare / AWS Shield"},
                {"priority": 2, "action": "Konfigurasi rate limiting dan connection limit", "tool": "Nginx / HAProxy"},
                {"priority": 3, "action": "Implementasi anycast network diffusion", "tool": "CDN provider"},
                {"priority": 4, "action": "Siapkan runbook incident response DDoS", "tool": "Internal SOP"},
            ]
        ))

    # ─── Rules: XSS ───────────────────────────────────────────────────────────

    @Rule(
        AttackSymptom(name="xss_payload_detected"),
        TargetSystem(type="web_server")
    )
    def detect_xss(self):
        """Rule: Cross-Site Scripting pada web application."""
        logger.info("[ENGINE] Rule fired: XSS detected")
        self.declare(DetectedAttack(
            attack_type="Cross-Site Scripting (XSS)",
            confidence=0.91,
            description=(
                "Script berbahaya ditemukan dalam input yang akan di-render "
                "ke browser. Berpotensi mencuri session/cookie pengguna."
            ),
            mitre_id="T1059.007",
            recommendations=[
                {"priority": 1, "action": "Encode semua output yang di-render ke HTML", "tool": "Jinja2 autoescaping / React JSX"},
                {"priority": 2, "action": "Terapkan Content Security Policy (CSP) header", "tool": "Helmet.js / Next.js headers config"},
                {"priority": 3, "action": "Gunakan HttpOnly dan Secure flag pada cookie", "tool": "FastAPI response headers"},
                {"priority": 4, "action": "Sanitasi input dengan allowlist", "tool": "DOMPurify / bleach"},
            ]
        ))

    # ─── Rules: Man-in-the-Middle ─────────────────────────────────────────────

    @Rule(
        AttackSymptom(name="arp_spoofing"),
        OR(
            AttackSymptom(name="ssl_stripping"),
            AttackSymptom(name="certificate_anomaly")
        )
    )
    def detect_mitm(self):
        """Rule: Indikasi serangan Man-in-the-Middle."""
        logger.info("[ENGINE] Rule fired: MitM detected")
        self.declare(DetectedAttack(
            attack_type="Man-in-the-Middle (MitM)",
            confidence=0.85,
            description=(
                "Anomali pada lapisan jaringan mengindikasikan adanya pihak ketiga "
                "yang mencegat dan berpotensi memodifikasi komunikasi."
            ),
            mitre_id="T1557",
            recommendations=[
                {"priority": 1, "action": "Enforce HTTPS dengan HSTS header", "tool": "Let's Encrypt + nginx config"},
                {"priority": 2, "action": "Implementasi certificate pinning", "tool": "TLS config"},
                {"priority": 3, "action": "Gunakan mutual TLS (mTLS) untuk service-to-service", "tool": "Istio / nginx mTLS"},
                {"priority": 4, "action": "Monitor ARP table untuk anomali", "tool": "arpwatch / XArp"},
            ]
        ))

    # ─── Fallback Rule ────────────────────────────────────────────────────────

    @Rule(
        NOT(DetectedAttack())
    )
    def no_attack_detected(self):
        """
        Fallback: dieksekusi jika tidak ada rule lain yang match.
        Penting untuk UX — frontend selalu mendapat response yang bermakna.
        """
        logger.info("[ENGINE] No specific attack pattern matched, using fallback.")
        self.declare(DetectedAttack(
            attack_type="Unknown / Insufficient Data",
            confidence=0.0,
            description=(
                "Gejala yang diberikan tidak cukup atau tidak cocok dengan "
                "pola serangan yang diketahui. Pertimbangkan menambahkan lebih "
                "banyak gejala atau konsultasikan dengan analis."
            ),
            mitre_id=None,
            recommendations=[
                {"priority": 1, "action": "Lakukan analisis log manual lebih mendalam", "tool": "ELK Stack / Splunk"},
                {"priority": 2, "action": "Jalankan vulnerability scanner menyeluruh", "tool": "Nessus / OpenVAS"},
            ]
        ))
```

---

### 3.3 FastAPI Endpoint

Endpoint ini menjadi **jembatan** antara request JSON dari Next.js dan inference engine Experta. Semua operasi berjalan secara asinkronus.

```python
# app/routers/diagnosis.py

import time
import uuid
import json
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.diagnosis import DiagnosisRequest, DiagnosisResponse, AttackResult, DefenseRecommendation
from app.engine.knowledge_base import CybersecurityExpertEngine
from app.engine.facts import AttackSymptom, TargetSystem, DetectedAttack
from app.database import get_db, get_redis
from app.models.history import ConsultationHistory

router = APIRouter(prefix="/api/v1", tags=["Diagnosis"])


def _build_cache_key(request: DiagnosisRequest) -> str:
    """
    Buat cache key deterministik dari request.
    Request dengan gejala identik (urutan diabaikan) → cache key sama.
    """
    sorted_symptoms = sorted(request.symptoms)
    payload = f"{sorted_symptoms}:{request.target_system}:{request.severity_hint}"
    return f"diagnosis:{hashlib.md5(payload.encode()).hexdigest()}"


async def _run_engine(request: DiagnosisRequest) -> list[DetectedAttack]:
    """
    Inisialisasi engine, declare semua fakta, jalankan inference,
    lalu kembalikan semua DetectedAttack facts yang terkumpul.
    """
    engine = CybersecurityExpertEngine()
    engine.reset()

    # Declare semua gejala sebagai Facts
    for symptom in request.symptoms:
        engine.declare(AttackSymptom(name=symptom))

    # Declare target system jika ada
    if request.target_system:
        engine.declare(TargetSystem(type=request.target_system))

    # Jalankan inference engine (forward chaining)
    engine.run()

    # Kumpulkan semua DetectedAttack facts yang di-assert selama run
    results = [
        fact for fact in engine.facts.values()
        if isinstance(fact, DetectedAttack)
    ]

    return results


@router.post(
    "/diagnose",
    response_model=DiagnosisResponse,
    summary="Diagnosa serangan siber berdasarkan gejala",
    description="Terima daftar gejala, jalankan inference engine, kembalikan hasil analisa dan rekomendasi defense."
)
async def diagnose(
    request: DiagnosisRequest,
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis)
):
    start_time = time.time()
    cache_key = _build_cache_key(request)

    # ── Cek cache Redis terlebih dahulu ───────────────────────────────────────
    cached = await redis.get(cache_key)
    if cached:
        response_data = json.loads(cached)
        response_data["from_cache"] = True
        response_data["session_id"] = str(uuid.uuid4())  # Session ID tetap unik
        return DiagnosisResponse(**response_data)

    # ── Jalankan inference engine ─────────────────────────────────────────────
    try:
        detected_facts = await _run_engine(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Engine error: {str(e)}"
        )

    # ── Format hasil ke schema response ──────────────────────────────────────
    detected_attacks = []
    all_recommendations = []

    for fact in detected_facts:
        detected_attacks.append(AttackResult(
            attack_type=fact["attack_type"],
            confidence=fact["confidence"],
            description=fact["description"],
            mitre_id=fact.get("mitre_id")
        ))
        for rec in fact.get("recommendations", []):
            all_recommendations.append(DefenseRecommendation(
                priority=rec["priority"],
                action=rec["action"],
                tool_suggestion=rec.get("tool")
            ))

    # Sort rekomendasi berdasarkan prioritas
    all_recommendations.sort(key=lambda x: x.priority)

    duration_ms = (time.time() - start_time) * 1000
    session_id = str(uuid.uuid4())

    response = DiagnosisResponse(
        session_id=session_id,
        detected_attacks=detected_attacks,
        defense_recommendations=all_recommendations,
        analysis_duration_ms=round(duration_ms, 2),
        from_cache=False
    )

    # ── Simpan ke Redis cache (TTL 1 jam) ─────────────────────────────────────
    cache_data = response.model_dump()
    cache_data.pop("session_id")   # Jangan cache session ID
    cache_data.pop("from_cache")
    await redis.setex(cache_key, 3600, json.dumps(cache_data, default=str))

    # ── Simpan riwayat ke PostgreSQL ──────────────────────────────────────────
    history_entry = ConsultationHistory(
        session_id=session_id,
        symptoms=request.symptoms,
        target_system=request.target_system,
        detected_attacks=[a.model_dump() for a in detected_attacks],
        duration_ms=duration_ms
    )
    db.add(history_entry)
    await db.commit()

    return response
```

---

## 4. Koneksi Database

### 4.1 PostgreSQL dengan SQLAlchemy

```python
# app/database.py

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
import redis.asyncio as aioredis
from app.config import settings


# ── PostgreSQL ────────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,  # postgresql+asyncpg://user:pass@host/dbname
    pool_size=10,
    max_overflow=20,
    echo=False  # Set True untuk debug query SQL
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


async def get_db():
    """Dependency injection untuk FastAPI route handlers."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# ── Redis ──────────────────────────────────────────────────────────────────────
redis_client = aioredis.from_url(
    settings.REDIS_URL,  # redis://localhost:6379/0
    encoding="utf-8",
    decode_responses=True,
    max_connections=20
)


async def get_redis():
    """Dependency injection Redis untuk route handlers."""
    return redis_client
```

### 4.2 Redis untuk Caching

```python
# app/services/cache_service.py

import json
import hashlib
from typing import Any, Optional
import redis.asyncio as aioredis


class CacheService:
    """
    Wrapper Redis dengan helper method yang lebih ekspresif.
    Gunakan class ini alih-alih akses redis_client langsung.
    """

    def __init__(self, redis: aioredis.Redis):
        self.redis = redis
        self.DEFAULT_TTL = 3600  # 1 jam

    async def get_json(self, key: str) -> Optional[Any]:
        """Ambil nilai JSON dari cache. Return None jika tidak ada."""
        value = await self.redis.get(key)
        return json.loads(value) if value else None

    async def set_json(self, key: str, value: Any, ttl: int = None) -> None:
        """Simpan nilai sebagai JSON ke cache dengan TTL."""
        await self.redis.setex(
            key,
            ttl or self.DEFAULT_TTL,
            json.dumps(value, default=str)
        )

    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Hapus semua key yang cocok dengan pattern.
        Gunakan dengan hati-hati di production — scan bisa berat.
        Contoh: await cache.invalidate_pattern("diagnosis:*")
        """
        keys = await self.redis.keys(pattern)
        if keys:
            return await self.redis.delete(*keys)
        return 0

    @staticmethod
    def make_key(*parts: str) -> str:
        """Buat cache key yang konsisten dari beberapa bagian."""
        combined = ":".join(str(p) for p in parts)
        return f"app:{hashlib.md5(combined.encode()).hexdigest()}"
```

---

## 5. Startup & Dataset Loading

Dataset yang sudah ada di-load sekali saja saat aplikasi pertama kali menyala, kemudian disimpan di memory dan PostgreSQL. Tidak perlu baca file setiap ada request.

```python
# app/main.py

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.routers import diagnosis, attacks, history
from app.services.dataset_service import DatasetService
from app.config import settings

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle handler — dijalankan sekali saat startup dan shutdown.
    Gunakan ini untuk inisialisasi resource yang berat.
    """
    logger.info("🚀 Starting up Cybersecurity Expert System...")

    # Buat semua tabel di PostgreSQL (jika belum ada)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables ready")

    # Load dataset serangan dari CSV ke PostgreSQL (idempotent)
    dataset_service = DatasetService()
    await dataset_service.load_if_empty(filepath="dataset/attacks.csv")
    logger.info("✅ Dataset loaded into PostgreSQL")

    yield  # Aplikasi berjalan di sini

    # Cleanup saat shutdown
    await engine.dispose()
    logger.info("👋 Shutdown complete")


app = FastAPI(
    title="Cybersecurity Expert System API",
    description="Sistem pakar deteksi serangan siber dan rekomendasi defense berbasis Experta.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS untuk koneksi dari Next.js
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(diagnosis.router)
app.include_router(attacks.router)
app.include_router(history.router)
```

```python
# app/services/dataset_service.py

import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import AsyncSessionLocal
from app.models.attack import Attack
from sqlalchemy import select, func
import logging

logger = logging.getLogger(__name__)


class DatasetService:
    """
    Service untuk load dataset CSV ke PostgreSQL.
    Bersifat idempotent — aman dijalankan berulang kali.
    """

    async def load_if_empty(self, filepath: str) -> None:
        """
        Load dataset hanya jika tabel attacks masih kosong.
        Cocok untuk inisialisasi pertama kali atau fresh deployment.
        """
        async with AsyncSessionLocal() as session:
            # Cek apakah tabel sudah berisi data
            result = await session.execute(select(func.count(Attack.id)))
            count = result.scalar()

            if count > 0:
                logger.info(f"Dataset sudah ada ({count} records), skip loading.")
                return

        # Baca CSV dengan Pandas
        logger.info(f"Loading dataset dari {filepath}...")
        df = pd.read_csv(filepath)

        # Sesuaikan nama kolom dengan struktur datasetmu
        # Contoh kolom yang diasumsikan: attack_type, symptoms, severity, mitre_id, description
        attacks = []
        for _, row in df.iterrows():
            symptoms = row.get("symptoms", "")
            if isinstance(symptoms, str):
                symptoms_list = [s.strip() for s in symptoms.split(",")]
            else:
                symptoms_list = []

            attacks.append(Attack(
                attack_type=row.get("attack_type", "Unknown"),
                symptoms=symptoms_list,
                severity=row.get("severity", "medium"),
                mitre_id=row.get("mitre_id"),
                description=row.get("description", ""),
            ))

        async with AsyncSessionLocal() as session:
            session.add_all(attacks)
            await session.commit()

        logger.info(f"✅ {len(attacks)} records berhasil di-load ke PostgreSQL.")
```

---

## 6. Future-Proof Strategy

### 6.1 Migrasi ke Machine Learning

Arsitektur ini dirancang agar mudah di-upgrade ke ML tanpa harus refactor besar. Caranya: engine di-swap, interface ke FastAPI tidak berubah.

```python
# app/engine/ml_engine.py  ← engine baru, tinggal swap

import joblib
import pandas as pd
from typing import List

# Model sudah di-train sebelumnya dan di-save ke file
MODEL_PATH = "ml_model/classifier.pkl"
ENCODER_PATH = "ml_model/label_encoder.pkl"


class MLCybersecurityEngine:
    """
    Drop-in replacement untuk CybersecurityExpertEngine.
    Interface yang sama → tidak perlu ubah router sama sekali.
    """

    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.encoder = joblib.load(ENCODER_PATH)
        self.all_symptoms = self._load_feature_list()

    def _load_feature_list(self) -> List[str]:
        """Load daftar semua gejala yang diketahui model (dari training)."""
        return joblib.load("ml_model/feature_list.pkl")

    def predict(self, symptoms: List[str], target_system: str = None):
        """
        Terima list gejala → kembalikan prediksi serangan + confidence.
        Interface identik dengan engine Experta.
        """
        # One-hot encode symptoms
        feature_vector = {s: 0 for s in self.all_symptoms}
        for symptom in symptoms:
            if symptom in feature_vector:
                feature_vector[symptom] = 1

        X = pd.DataFrame([feature_vector])
        probabilities = self.model.predict_proba(X)[0]
        predicted_class = self.model.predict(X)[0]
        confidence = max(probabilities)

        return {
            "attack_type": self.encoder.inverse_transform([predicted_class])[0],
            "confidence": round(float(confidence), 4),
        }


# ── Training script (jalankan sekali offline) ─────────────────────────────────
# python -m app.engine.train_model

def train_and_save_model(dataset_path: str):
    """
    Train classifier dari dataset CSV dan simpan model ke disk.
    Jalankan sekali secara offline, bukan saat startup FastAPI.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split
    import joblib

    df = pd.read_csv(dataset_path)

    # Feature engineering dari kolom symptoms
    all_symptoms = set()
    for symptoms_str in df["symptoms"]:
        for s in symptoms_str.split(","):
            all_symptoms.add(s.strip())
    all_symptoms = sorted(list(all_symptoms))

    # One-hot encode
    for symptom in all_symptoms:
        df[symptom] = df["symptoms"].apply(
            lambda x: 1 if symptom in x.split(",") else 0
        )

    X = df[all_symptoms]
    y = df["attack_type"]

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    print(f"Model accuracy: {accuracy:.4f}")

    joblib.dump(model, "ml_model/classifier.pkl")
    joblib.dump(le, "ml_model/label_encoder.pkl")
    joblib.dump(all_symptoms, "ml_model/feature_list.pkl")
    print("Model saved successfully.")
```

### 6.2 Optimalisasi Redis

```python
# Strategi caching bertingkat untuk menghindari pemborosan CPU

# Tier 1 — Cache diagnosis result (TTL: 1 jam)
# Key: diagnosis:{md5(sorted_symptoms:target_system)}
# Kapan invalidate: ketika rules di knowledge base diupdate

# Tier 2 — Cache daftar serangan (TTL: 24 jam)
# Key: attacks:all atau attacks:page:{page_num}
# Kapan invalidate: ketika admin menambah/edit data serangan

# Tier 3 — Cache statistik dashboard (TTL: 15 menit)
# Key: stats:dashboard
# Kapan invalidate: time-based (tidak perlu manual)

# Contoh pattern invalidation:
# Ketika admin update knowledge base → invalidate semua key "diagnosis:*"
# Ketika dataset di-update → invalidate "attacks:*" dan "diagnosis:*"

CACHE_TTL = {
    "diagnosis": 3600,      # 1 jam
    "attack_list": 86400,   # 24 jam
    "dashboard_stats": 900, # 15 menit
    "user_history": 300,    # 5 menit
}
```

---

## 7. Menjalankan Project

### Prerequisites

```bash
# Python 3.11+ (Targeted for 3.12.x compatibility using monkey-patch without changing system Python)
python --version


# Node.js 18+ (untuk frontend Next.js)
node --version

# Docker & Docker Compose
docker --version
```

### Setup dengan Docker Compose

```yaml
# docker-compose.yml

version: "3.9"

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    env_file: ./backend/.env
    depends_on:
      - postgres
      - redis
    volumes:
      - ./backend/dataset:/app/dataset  # Mount dataset

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: cybersec_db
      POSTGRES_USER: cybersec_user
      POSTGRES_PASSWORD: cybersec_pass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### Environment Variables

```bash
# backend/.env

DATABASE_URL=postgresql+asyncpg://cybersec_user:cybersec_pass@postgres:5432/cybersec_db
REDIS_URL=redis://redis:6379/0
FRONTEND_URL=http://localhost:3000
SECRET_KEY=ganti-dengan-secret-key-yang-panjang-dan-random
```

### Jalankan

```bash
# Clone & setup
git clone <repo-url>
cd cybersecurity-expert-system

# Jalankan semua service
docker compose up --build

# Backend API akan bisa diakses di:
# http://localhost:8000
# http://localhost:8000/docs  ← Swagger UI otomatis dari FastAPI

# Test endpoint diagnosa
curl -X POST http://localhost:8000/api/v1/diagnose \
  -H "Content-Type: application/json" \
  -d '{
    "symptoms": ["port_scanning", "os_fingerprinting"],
    "target_system": "web_server"
  }'
```

### Requirements

```txt
# backend/requirements.txt

fastapi==0.111.0
uvicorn[standard]==0.29.0
experta==1.9.4
pydantic==2.7.1
pydantic-settings==2.2.1
sqlalchemy[asyncio]==2.0.29
asyncpg==0.29.0
redis[hiredis]==5.0.4
pandas==2.2.2
scikit-learn==1.4.2
joblib==1.4.0
python-multipart==0.0.9
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
alembic==1.13.1
```

---

*Dokumen ini di-generate berdasarkan arsitektur yang didesain untuk project sistem pakar cybersecurity attack & defense. Sesuaikan nama kolom dataset, struktur rules, dan konfigurasi environment dengan kebutuhan spesifik project kamu.*

---

## 8. Unit Testing

Semua test menggunakan **pytest + pytest-asyncio** untuk async support, **httpx** untuk simulasi HTTP request ke FastAPI, dan response selalu divalidasi dalam format **JSON**.

### Struktur Folder Test

```
backend/
└── tests/
    ├── __init__.py
    ├── conftest.py                  # Fixtures global (app, client, db)
    ├── test_cf_engine.py            # Unit test Certainty Factor
    ├── test_experta_engine.py       # Unit test Experta rules
    ├── test_diagnosis_endpoint.py   # Integration test POST /diagnose
    ├── test_schemas.py              # Unit test validasi Pydantic
    └── test_cache.py                # Unit test Redis caching
```

### Tambahan Dependencies Test

```txt
# Tambahkan ke requirements.txt

pytest==8.2.0
pytest-asyncio==0.23.6
pytest-cov==5.0.0
httpx==0.27.0
aiosqlite==0.20.0
fakeredis[aioredis]==2.23.0
```

---

### conftest.py — Fixtures Global

```python
# tests/conftest.py

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
import fakeredis.aioredis as fakeredis

from app.main import app
from app.database import Base, get_db, get_redis


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False
)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database():
    """Buat semua tabel di SQLite in-memory sebelum test suite jalan."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session():
    """Satu sesi database per test, di-rollback setelah selesai."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def fake_redis():
    """Redis palsu — tidak butuh server Redis nyata."""
    redis = fakeredis.FakeRedis(decode_responses=True)
    yield redis
    await redis.flushall()


@pytest_asyncio.fixture
async def client(db_session, fake_redis):
    """
    AsyncClient dengan dependency override:
    - PostgreSQL → SQLite in-memory
    - Redis → fakeredis
    """
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_redis] = lambda: fake_redis

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
```

---

### test_cf_engine.py — Unit Test Certainty Factor

```python
# tests/test_cf_engine.py

import pytest
from app.engine.certainty_factor import combine_cf, calculate_attack_cf, diagnose_with_cf, CFRule


class TestCombineCF:

    def test_both_positive(self):
        """CF(0.7) + CF(0.6) = 0.7 + 0.6*(1-0.7) = 0.88"""
        result = combine_cf(0.7, 0.6)
        assert abs(result - 0.88) < 0.001

    def test_both_negative(self):
        """Dua bukti menentang → lebih negatif."""
        result = combine_cf(-0.5, -0.4)
        assert result < -0.5
        assert result >= -1.0

    def test_one_positive_one_negative(self):
        """Bukti bertentangan → nilai di antara keduanya."""
        result = combine_cf(0.6, -0.3)
        assert -1.0 <= result <= 1.0

    def test_zero_cf(self):
        """CF nol tidak mengubah nilai CF lain."""
        result = combine_cf(0.7, 0.0)
        assert abs(result - 0.7) < 0.001

    def test_cf_never_exceeds_one(self):
        result = combine_cf(0.9, 0.95)
        assert result <= 1.0

    def test_cf_never_below_minus_one(self):
        result = combine_cf(-0.9, -0.95)
        assert result >= -1.0


class TestCalculateAttackCF:

    @pytest.fixture
    def brute_force_rule(self):
        return CFRule(
            attack_type="Brute Force Attack",
            base_cf=0.95,
            symptoms={
                "brute_force_login":    0.85,
                "multiple_failed_auth": 0.80,
                "high_login_attempts":  0.78,
            }
        )

    def test_all_symptoms_match(self, brute_force_rule):
        symptoms = ["brute_force_login", "multiple_failed_auth", "high_login_attempts"]
        cf = calculate_attack_cf(brute_force_rule, symptoms)
        assert cf > 0.90
        assert cf <= 1.0

    def test_single_symptom_less_than_all(self, brute_force_rule):
        cf_single = calculate_attack_cf(brute_force_rule, ["brute_force_login"])
        cf_all    = calculate_attack_cf(brute_force_rule, [
            "brute_force_login", "multiple_failed_auth", "high_login_attempts"
        ])
        assert cf_single < cf_all

    def test_no_match_returns_zero(self, brute_force_rule):
        cf = calculate_attack_cf(brute_force_rule, ["port_scanning", "arp_spoofing"])
        assert cf == 0.0

    def test_result_is_float(self, brute_force_rule):
        cf = calculate_attack_cf(brute_force_rule, ["brute_force_login"])
        assert isinstance(cf, float)

    def test_rounded_to_4_decimal(self, brute_force_rule):
        cf = calculate_attack_cf(brute_force_rule, ["brute_force_login"])
        assert cf == round(cf, 4)


class TestDiagnoseWithCF:

    def test_reconnaissance_detected(self):
        results = diagnose_with_cf(["port_scanning", "os_fingerprinting"])
        attack_types = [r["attack_type"] for r in results]
        assert "Reconnaissance" in attack_types

    def test_brute_force_detected(self):
        results = diagnose_with_cf(["brute_force_login", "multiple_failed_auth"])
        attack_types = [r["attack_type"] for r in results]
        assert "Brute Force Attack" in attack_types

    def test_sorted_by_confidence_descending(self):
        results = diagnose_with_cf([
            "port_scanning", "os_fingerprinting",
            "brute_force_login", "multiple_failed_auth"
        ])
        if len(results) >= 2:
            confidences = [r["confidence"] for r in results]
            assert confidences == sorted(confidences, reverse=True)

    def test_below_threshold_excluded(self):
        results = diagnose_with_cf(["port_scanning"], threshold=0.99)
        for r in results:
            assert r["confidence"] >= 0.99

    def test_empty_symptoms_returns_empty(self):
        assert diagnose_with_cf([]) == []

    def test_unknown_symptoms_returns_empty(self):
        assert diagnose_with_cf(["gejala_palsu_xyz"]) == []

    def test_result_has_required_keys(self):
        results = diagnose_with_cf(["port_scanning", "os_fingerprinting"])
        for r in results:
            assert "attack_type"       in r
            assert "confidence"        in r
            assert "matched_symptoms"  in r

    def test_matched_symptoms_subset_of_input(self):
        input_symptoms = ["port_scanning", "os_fingerprinting", "brute_force_login"]
        results = diagnose_with_cf(input_symptoms)
        for r in results:
            for s in r["matched_symptoms"]:
                assert s in input_symptoms
```

---

### test_experta_engine.py — Unit Test Experta Rules

```python
# tests/test_experta_engine.py

import pytest
from app.engine.knowledge_base import CybersecurityExpertEngine
from app.engine.facts import AttackSymptom, TargetSystem, DetectedAttack


def run_engine(symptoms: list[str], target: str = None) -> list:
    engine = CybersecurityExpertEngine()
    engine.reset()
    for s in symptoms:
        engine.declare(AttackSymptom(name=s))
    if target:
        engine.declare(TargetSystem(type=target))
    engine.run()
    return [f for f in engine.facts.values() if isinstance(f, DetectedAttack)]


class TestExpertaRules:

    def test_reconnaissance_rule_fires(self):
        results = run_engine(["port_scanning", "os_fingerprinting"])
        assert "Reconnaissance" in [r["attack_type"] for r in results]

    def test_brute_force_rule_fires(self):
        results = run_engine(["brute_force_login", "multiple_failed_auth"])
        assert "Brute Force Attack" in [r["attack_type"] for r in results]

    def test_sql_injection_requires_target_system(self):
        without = run_engine(["sql_injection_pattern"])
        with_t  = run_engine(["sql_injection_pattern"], target="database")
        assert "SQL Injection" not in [r["attack_type"] for r in without]
        assert "SQL Injection"     in [r["attack_type"] for r in with_t]

    def test_fallback_fires_on_unknown_symptoms(self):
        results = run_engine(["gejala_tidak_dikenal_xyz"])
        assert "Unknown / Insufficient Data" in [r["attack_type"] for r in results]

    def test_fallback_does_not_fire_when_attack_detected(self):
        results = run_engine(["port_scanning", "os_fingerprinting"])
        assert "Unknown / Insufficient Data" not in [r["attack_type"] for r in results]

    def test_multiple_rules_can_fire_simultaneously(self):
        results = run_engine([
            "port_scanning", "os_fingerprinting",
            "brute_force_login", "multiple_failed_auth"
        ])
        types = [r["attack_type"] for r in results]
        assert "Reconnaissance"    in types
        assert "Brute Force Attack" in types

    def test_confidence_between_zero_and_one(self):
        results = run_engine(["port_scanning", "os_fingerprinting"])
        for r in results:
            assert 0.0 <= r["confidence"] <= 1.0

    def test_recommendations_not_empty(self):
        results = run_engine(["port_scanning", "os_fingerprinting"])
        for r in results:
            assert len(r.get("recommendations", [])) > 0
```

---

### test_diagnosis_endpoint.py — Integration Test JSON Response

```python
# tests/test_diagnosis_endpoint.py

import pytest
from httpx import AsyncClient


class TestDiagnoseEndpoint:

    @pytest.mark.asyncio
    async def test_returns_200(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning", "os_fingerprinting"]
        })
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_content_type_is_json(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning"]
        })
        assert "application/json" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_response_top_level_keys(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning", "os_fingerprinting"],
            "target_system": "web_server"
        })
        body = response.json()
        for key in ["session_id", "detected_attacks", "defense_recommendations",
                    "analysis_duration_ms", "from_cache"]:
            assert key in body

    @pytest.mark.asyncio
    async def test_detected_attacks_item_keys(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning", "os_fingerprinting"]
        })
        for attack in response.json()["detected_attacks"]:
            assert "attack_type"  in attack
            assert "confidence"   in attack
            assert "description"  in attack
            assert isinstance(attack["confidence"], float)
            assert 0.0 <= attack["confidence"] <= 1.0

    @pytest.mark.asyncio
    async def test_defense_recommendations_item_keys(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning", "os_fingerprinting"]
        })
        for rec in response.json()["defense_recommendations"]:
            assert "priority" in rec
            assert "action"   in rec
            assert 1 <= rec["priority"] <= 5

    @pytest.mark.asyncio
    async def test_reconnaissance_in_detected_attacks(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning", "os_fingerprinting"]
        })
        types = [a["attack_type"] for a in response.json()["detected_attacks"]]
        assert "Reconnaissance" in types

    @pytest.mark.asyncio
    async def test_unknown_symptoms_returns_fallback_json(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["gejala_tidak_ada_xyz"]
        })
        assert response.status_code == 200
        types = [a["attack_type"] for a in response.json()["detected_attacks"]]
        assert any("Unknown" in t for t in types)

    @pytest.mark.asyncio
    async def test_session_id_unique_per_request(self, client: AsyncClient):
        payload = {"symptoms": ["port_scanning"]}
        r1 = await client.post("/api/v1/diagnose", json=payload)
        r2 = await client.post("/api/v1/diagnose", json=payload)
        assert r1.json()["session_id"] != r2.json()["session_id"]

    @pytest.mark.asyncio
    async def test_second_identical_request_from_cache(self, client: AsyncClient):
        payload = {"symptoms": ["brute_force_login", "multiple_failed_auth"]}
        r1 = await client.post("/api/v1/diagnose", json=payload)
        r2 = await client.post("/api/v1/diagnose", json=payload)
        assert r1.json()["from_cache"] is False
        assert r2.json()["from_cache"] is True

    @pytest.mark.asyncio
    async def test_empty_symptoms_returns_422(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={"symptoms": []})
        assert response.status_code == 422
        assert "detail" in response.json()

    @pytest.mark.asyncio
    async def test_missing_symptoms_field_returns_422(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={"target_system": "web_server"})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_severity_hint_returns_422(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["port_scanning"],
            "severity_hint": "ultra_critical_invalid"
        })
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_analysis_duration_positive(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={"symptoms": ["port_scanning"]})
        assert response.json()["analysis_duration_ms"] > 0

    @pytest.mark.asyncio
    async def test_all_optional_fields_accepted(self, client: AsyncClient):
        response = await client.post("/api/v1/diagnose", json={
            "symptoms": ["xss_payload_detected"],
            "target_system": "web_server",
            "severity_hint": "high"
        })
        assert response.status_code == 200
```

---

### test_schemas.py — Unit Test Validasi Pydantic

```python
# tests/test_schemas.py

import pytest
from pydantic import ValidationError
from app.schemas.diagnosis import (
    DiagnosisRequest, AttackResult, DefenseRecommendation
)


class TestDiagnosisRequestSchema:

    def test_valid_minimal(self):
        req = DiagnosisRequest(symptoms=["port_scanning"])
        assert req.symptoms == ["port_scanning"]
        assert req.target_system is None

    def test_empty_symptoms_raises(self):
        with pytest.raises(ValidationError) as exc:
            DiagnosisRequest(symptoms=[])
        assert any(e["loc"] == ("symptoms",) for e in exc.value.errors())

    def test_too_many_symptoms_raises(self):
        with pytest.raises(ValidationError):
            DiagnosisRequest(symptoms=[f"s_{i}" for i in range(21)])

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            DiagnosisRequest(symptoms=["port_scanning"], severity_hint="extreme")

    def test_all_valid_severity_values(self):
        for level in ["low", "medium", "high", "critical"]:
            req = DiagnosisRequest(symptoms=["port_scanning"], severity_hint=level)
            assert req.severity_hint == level


class TestAttackResultSchema:

    def test_valid(self):
        r = AttackResult(attack_type="Recon", confidence=0.88, description="Test")
        assert r.confidence == 0.88

    def test_confidence_below_zero_raises(self):
        with pytest.raises(ValidationError):
            AttackResult(attack_type="X", confidence=-0.1, description="X")

    def test_confidence_above_one_raises(self):
        with pytest.raises(ValidationError):
            AttackResult(attack_type="X", confidence=1.01, description="X")

    def test_mitre_id_optional(self):
        r = AttackResult(attack_type="Unknown", confidence=0.0, description="X")
        assert r.mitre_id is None


class TestDefenseRecommendationSchema:

    def test_valid(self):
        rec = DefenseRecommendation(priority=1, action="Block IP")
        assert rec.priority == 1

    def test_priority_zero_raises(self):
        with pytest.raises(ValidationError):
            DefenseRecommendation(priority=0, action="X")

    def test_priority_six_raises(self):
        with pytest.raises(ValidationError):
            DefenseRecommendation(priority=6, action="X")

    def test_tool_suggestion_optional(self):
        rec = DefenseRecommendation(priority=2, action="Aktifkan MFA")
        assert rec.tool_suggestion is None
```

---

### test_cache.py — Unit Test Redis Caching

```python
# tests/test_cache.py

import pytest
from app.services.cache_service import CacheService


@pytest.mark.asyncio
async def test_set_and_get_json(fake_redis):
    cache = CacheService(fake_redis)
    data = {"attack_type": "Reconnaissance", "confidence": 0.88}
    await cache.set_json("test:key1", data)
    result = await cache.get_json("test:key1")
    assert result == data
    assert result["confidence"] == 0.88


@pytest.mark.asyncio
async def test_get_nonexistent_returns_none(fake_redis):
    cache = CacheService(fake_redis)
    result = await cache.get_json("test:tidak_ada")
    assert result is None


@pytest.mark.asyncio
async def test_ttl_is_applied(fake_redis):
    cache = CacheService(fake_redis)
    await cache.set_json("test:ttl", {"x": 1}, ttl=300)
    ttl = await fake_redis.ttl("test:ttl")
    assert 0 < ttl <= 300


@pytest.mark.asyncio
async def test_invalidate_pattern(fake_redis):
    cache = CacheService(fake_redis)
    await cache.set_json("diagnosis:abc", {"r": 1})
    await cache.set_json("diagnosis:def", {"r": 2})
    await cache.set_json("attacks:all",   {"r": 3})

    deleted = await cache.invalidate_pattern("diagnosis:*")

    assert deleted == 2
    assert await cache.get_json("diagnosis:abc") is None
    assert await cache.get_json("diagnosis:def") is None
    assert await cache.get_json("attacks:all")  is not None


@pytest.mark.asyncio
async def test_make_key_deterministic(fake_redis):
    k1 = CacheService.make_key("diagnosis", "port_scanning", "web_server")
    k2 = CacheService.make_key("diagnosis", "port_scanning", "web_server")
    assert k1 == k2


@pytest.mark.asyncio
async def test_make_key_differs_on_different_input(fake_redis):
    k1 = CacheService.make_key("diagnosis", "port_scanning")
    k2 = CacheService.make_key("diagnosis", "brute_force_login")
    assert k1 != k2
```

---

### Menjalankan Test

```bash
# Semua test
pytest tests/ -v

# Dengan coverage report
pytest tests/ -v --cov=app --cov-report=term-missing

# Satu file spesifik
pytest tests/test_cf_engine.py -v
pytest tests/test_diagnosis_endpoint.py -v

# Filter berdasarkan nama
pytest tests/ -v -k "test_reconnaissance"
```

**Contoh output yang diharapkan:**

```
tests/test_cf_engine.py::TestCombineCF::test_both_positive                         PASSED
tests/test_cf_engine.py::TestCombineCF::test_both_negative                         PASSED
tests/test_cf_engine.py::TestCalculateAttackCF::test_all_symptoms_match            PASSED
tests/test_cf_engine.py::TestDiagnoseWithCF::test_reconnaissance_detected          PASSED
tests/test_experta_engine.py::TestExpertaRules::test_reconnaissance_rule_fires     PASSED
tests/test_experta_engine.py::TestExpertaRules::test_fallback_fires_on_unknown     PASSED
tests/test_diagnosis_endpoint.py::TestDiagnoseEndpoint::test_returns_200           PASSED
tests/test_diagnosis_endpoint.py::TestDiagnoseEndpoint::test_content_type_is_json  PASSED
tests/test_diagnosis_endpoint.py::TestDiagnoseEndpoint::test_second_identical_request_from_cache  PASSED
tests/test_schemas.py::TestDiagnosisRequestSchema::test_empty_symptoms_raises      PASSED
tests/test_cache.py::test_invalidate_pattern                                       PASSED

========== 38 passed in 1.24s ==========
```

**Target coverage minimum:**

```
app/engine/certainty_factor.py  →  95%+
app/engine/knowledge_base.py    →  90%+
app/schemas/diagnosis.py        → 100%
app/routers/diagnosis.py        →  85%+
app/services/cache_service.py   →  90%+
```
