from dataclasses import dataclass, field
from typing import List


@dataclass
class CFRule:
    """Satu rule dengan nilai CF untuk setiap gejala pendukungnya."""
    attack_type: str
    symptoms: dict[str, float]   # {"nama_gejala": nilai_cf}
    base_cf: float               # CF dasar rule ini
    recommendations: List[dict] = field(default_factory=list)  # Rekomendasi fallback


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
            "ping_sweep": 0.60,
            "dns_enumeration": 0.65,
            "whois_lookup": 0.50,
            "traceroute_activity": 0.55,
            "idle_scan": 0.85,
            "version_detection": 0.75,
            "tcp_connect_scan": 0.80
        },
        recommendations=[
            {"priority": 1, "action": "Block source IP di firewall", "tool": "iptables / pfSense"},
            {"priority": 2, "action": "Aktifkan IDS rule untuk port scan detection", "tool": "Snort / Suricata"},
            {"priority": 3, "action": "Sembunyikan banner service (version hiding)", "tool": "nginx / Apache config"},
            {"priority": 4, "action": "Terapkan network segmentation", "tool": "VLAN / Zero Trust Network"},
        ]
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
            "dictionary_attack": 0.80,
            "account_lockout_triggered": 0.90,
            "rapid_auth_requests": 0.85,
            "failed_ssh_attempts": 0.82,
            "failed_rdp_attempts": 0.82,
            "auth_log_flooding": 0.88
        },
        recommendations=[
            {"priority": 1, "action": "Implementasi rate limiting pada endpoint login", "tool": "Nginx rate_limit / FastAPI slowapi"},
            {"priority": 2, "action": "Aktifkan CAPTCHA setelah beberapa kali gagal login", "tool": "hCaptcha / reCAPTCHA"},
            {"priority": 3, "action": "Lockout akun setelah 5 kali percobaan gagal", "tool": "Custom middleware"},
            {"priority": 4, "action": "Aktifkan MFA untuk semua akun", "tool": "TOTP / Authy"},
            {"priority": 5, "action": "Pantau dan alert login anomali", "tool": "SIEM / Elastic SIEM"},
        ]
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
            "stacked_queries": 0.88,
            "out_of_band_sqli": 0.92,
            "db_error_in_response": 0.85,
            "tautology_in_query": 0.80,
            "encoded_sql_payload": 0.86,
            "time_delay_response": 0.82,
            "boolean_blind_sqli": 0.85
        },
        recommendations=[
            {"priority": 1, "action": "Gunakan parameterized queries / ORM", "tool": "SQLAlchemy / PreparedStatement"},
            {"priority": 2, "action": "Validasi dan sanitasi semua input user", "tool": "Pydantic / bleach"},
            {"priority": 3, "action": "Terapkan principle of least privilege di DB", "tool": "PostgreSQL GRANT/REVOKE"},
            {"priority": 4, "action": "Aktifkan WAF rule untuk SQLi pattern", "tool": "ModSecurity / Cloudflare WAF"},
            {"priority": 5, "action": "Sembunyikan error message dari response", "tool": "Custom error handler"},
        ]
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
            "icmp_flood": 0.75,
            "slow_loris_attack": 0.88,
            "bandwidth_saturation": 0.90,
            "connection_exhaustion": 0.85,
            "dns_amplification": 0.86,
            "ntp_amplification": 0.86
        },
        recommendations=[
            {"priority": 1, "action": "Aktifkan DDoS protection layer", "tool": "Cloudflare / AWS Shield"},
            {"priority": 2, "action": "Konfigurasi rate limiting dan connection limit", "tool": "Nginx / HAProxy"},
            {"priority": 3, "action": "Gunakan anycast network diffusion", "tool": "Cloudflare / Akamai"},
            {"priority": 4, "action": "Aktifkan blackhole routing untuk IP penyerang", "tool": "BGP Blackhole"},
        ]
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
            "stored_xss_payload": 0.90,
            "event_handler_injection": 0.85,
            "javascript_uri_injection": 0.86,
            "malicious_iframe_injection": 0.84,
            "html_entity_bypass": 0.75,
            "csp_bypass_attempt": 0.82
        },
        recommendations=[
            {"priority": 1, "action": "Encode semua output yang akan di-render ke HTML", "tool": "Jinja2 autoescape / React JSX"},
            {"priority": 2, "action": "Terapkan Content Security Policy (CSP) yang ketat", "tool": "Helmet.js / nginx header"},
            {"priority": 3, "action": "Validasi dan sanitasi semua input user", "tool": "DOMPurify / bleach"},
            {"priority": 4, "action": "Set flag HttpOnly dan Secure pada cookie", "tool": "FastAPI / Express cookie config"},
        ]
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
            "rogue_dhcp_server": 0.88,
            "packet_interception": 0.90,
            "session_hijacking": 0.85,
            "ssl_certificate_mismatch": 0.82,
            "bgp_hijacking": 0.92,
            "evil_twin_ap": 0.85,
            "ip_spoofing": 0.80
        },
        recommendations=[
            {"priority": 1, "action": "Enforce HTTPS dengan HSTS header", "tool": "nginx / Let's Encrypt"},
            {"priority": 2, "action": "Gunakan mutual TLS (mTLS)", "tool": "Istio / Envoy"},
            {"priority": 3, "action": "Aktifkan ARP inspection di switch", "tool": "Cisco Dynamic ARP Inspection"},
            {"priority": 4, "action": "Gunakan certificate pinning di aplikasi", "tool": "OkHttp / TrustKit"},
        ]
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
            "lookalike_domain": 0.88,
            "urgency_in_email": 0.65,
            "malicious_attachment": 0.82,
            "brand_impersonation": 0.85,
            "spear_phishing_indicators": 0.90,
            "whaling_attempt": 0.92,
            "vishing_indicators": 0.75
        },
        recommendations=[
            {"priority": 1, "action": "Aktifkan email filtering dan anti-phishing gateway", "tool": "Proofpoint / Mimecast"},
            {"priority": 2, "action": "Edukasi pengguna tentang social engineering", "tool": "Security Awareness Training"},
            {"priority": 3, "action": "Terapkan SPF, DKIM, dan DMARC pada domain", "tool": "DNS records"},
            {"priority": 4, "action": "Aktifkan MFA untuk mencegah credential hijacking", "tool": "Authenticator App / FIDO2"},
        ]
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
            "file_rename_burst": 0.86,
            "backup_deletion": 0.94,
            "registry_modification": 0.75,
            "process_injection": 0.80,
            "lateral_movement": 0.85,
            "data_exfiltration_before_encryption": 0.90,
            "bitcoin_address_in_note": 0.95
        },
        recommendations=[
            {"priority": 1, "action": "Isolasi sistem yang terinfeksi dari jaringan SEGERA", "tool": "Network switch / Firewall rule"},
            {"priority": 2, "action": "Restore dari backup yang bersih (offline backup)", "tool": "Veeam / Backup solution"},
            {"priority": 3, "action": "Laporkan ke BSSN / CERT nasional", "tool": "id-CERT / BSSN"},
            {"priority": 4, "action": "Terapkan backup 3-2-1 strategy ke depannya", "tool": "Offsite backup / Cloud backup"},
            {"priority": 5, "action": "Scan seluruh jaringan untuk lateral movement", "tool": "CrowdStrike / Carbon Black"},
        ]
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
                "recommendations": rule.recommendations,  # Sertakan rekomendasi dari CF rule
            })

    # Urutkan dari confidence tertinggi
    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results
