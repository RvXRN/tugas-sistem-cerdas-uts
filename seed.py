import asyncio
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# Patch compatibilitas untuk Experta agar tidak gagal load
import app.compat

from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.attack import Attack
from app.core.security import get_password_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Data referensi serangan (sumber: CF rules + MITRE ATT&CK) ─────────────────
ATTACKS_SEED = [
    {
        "attack_type": "Reconnaissance",
        "symptoms": [
            "port_scanning", "os_fingerprinting", "service_enumeration",
            "banner_grabbing", "network_mapping", "ping_sweep",
            "dns_enumeration", "idle_scan", "version_detection", "tcp_connect_scan"
        ],
        "severity": "medium",
        "mitre_id": "TA0043",
        "description": "Aktivitas pemindaian jaringan untuk memetakan topologi, layanan aktif, dan OS target sebelum eksploitasi."
    },
    {
        "attack_type": "Brute Force Attack",
        "symptoms": [
            "brute_force_login", "multiple_failed_auth", "high_login_attempts",
            "credential_stuffing", "password_spraying", "dictionary_attack",
            "account_lockout_triggered", "rapid_auth_requests", "failed_ssh_attempts",
            "failed_rdp_attempts", "auth_log_flooding"
        ],
        "severity": "high",
        "mitre_id": "T1110",
        "description": "Percobaan login berulang dalam waktu singkat menggunakan wordlist atau credential stuffing."
    },
    {
        "attack_type": "SQL Injection",
        "symptoms": [
            "sql_injection_pattern", "unusual_db_query", "error_based_response",
            "blind_sqli_timing", "union_based_payload", "stacked_queries",
            "out_of_band_sqli", "db_error_in_response", "tautology_in_query",
            "encoded_sql_payload", "time_delay_response", "boolean_blind_sqli"
        ],
        "severity": "critical",
        "mitre_id": "T1190",
        "description": "Payload SQL berbahaya disisipkan ke dalam input untuk memanipulasi query database secara langsung."
    },
    {
        "attack_type": "Distributed Denial of Service (DDoS)",
        "symptoms": [
            "high_traffic_volume", "service_degradation", "syn_flood",
            "udp_flood", "http_flood", "amplification_traffic",
            "icmp_flood", "slow_loris_attack", "bandwidth_saturation",
            "connection_exhaustion", "dns_amplification", "ntp_amplification"
        ],
        "severity": "high",
        "mitre_id": "T1498",
        "description": "Lonjakan traffic abnormal dari banyak sumber yang menyebabkan degradasi atau penolakan layanan."
    },
    {
        "attack_type": "Cross-Site Scripting (XSS)",
        "symptoms": [
            "xss_payload_detected", "script_tag_in_input", "dom_manipulation",
            "cookie_theft_attempt", "reflected_payload", "stored_xss_payload",
            "event_handler_injection", "javascript_uri_injection",
            "malicious_iframe_injection", "html_entity_bypass", "csp_bypass_attempt"
        ],
        "severity": "high",
        "mitre_id": "T1059.007",
        "description": "Script berbahaya disisipkan ke dalam halaman web yang akan di-render di browser korban."
    },
    {
        "attack_type": "Man-in-the-Middle (MitM)",
        "symptoms": [
            "arp_spoofing", "ssl_stripping", "certificate_anomaly",
            "dns_spoofing", "unusual_gateway_mac", "rogue_dhcp_server",
            "packet_interception", "session_hijacking", "ssl_certificate_mismatch",
            "bgp_hijacking", "evil_twin_ap", "ip_spoofing"
        ],
        "severity": "high",
        "mitre_id": "T1557",
        "description": "Penyerang memposisikan dirinya di antara dua pihak yang berkomunikasi untuk mencegat atau memodifikasi data."
    },
    {
        "attack_type": "Phishing",
        "symptoms": [
            "suspicious_email_link", "domain_spoofing", "credential_harvesting",
            "fake_login_page", "email_header_anomaly", "lookalike_domain",
            "urgency_in_email", "malicious_attachment", "brand_impersonation",
            "spear_phishing_indicators", "whaling_attempt", "vishing_indicators"
        ],
        "severity": "medium",
        "mitre_id": "T1566",
        "description": "Teknik rekayasa sosial untuk mengelabui korban agar menyerahkan kredensial atau mengeksekusi payload berbahaya."
    },
    {
        "attack_type": "Ransomware",
        "symptoms": [
            "mass_file_encryption", "ransom_note_created", "shadow_copy_deletion",
            "unusual_file_extension", "c2_communication", "file_rename_burst",
            "backup_deletion", "registry_modification", "process_injection",
            "lateral_movement", "data_exfiltration_before_encryption", "bitcoin_address_in_note"
        ],
        "severity": "critical",
        "mitre_id": "T1486",
        "description": "Malware yang mengenkripsi file korban dan menuntut tebusan untuk mendapatkan kunci dekripsi."
    },
]


async def seed_users():
    async with AsyncSessionLocal() as db:
        logger.info("Mengecek data seeder users...")

        users_to_seed = [
            {"username": "admin", "email": "admin@example.com", "password": "adminpassword", "role": "admin"},
            {"username": "user",  "email": "user@example.com",  "password": "userpassword",  "role": "user"},
        ]

        for user_data in users_to_seed:
            stmt = select(User).where(User.username == user_data["username"])
            result = await db.execute(stmt)
            existing = result.scalars().first()

            if not existing:
                logger.info(f"  ↳ Membuat akun '{user_data['username']}' (role: {user_data['role']})...")
                db.add(User(
                    username=user_data["username"],
                    email=user_data["email"],
                    hashed_password=get_password_hash(user_data["password"]),
                    role=user_data["role"]
                ))
            else:
                logger.info(f"  ↳ Akun '{user_data['username']}' sudah ada, dilewati.")

        await db.commit()
        logger.info("✅ Seeder users selesai.")


async def seed_attacks():
    async with AsyncSessionLocal() as db:
        logger.info("Mengecek data seeder attacks...")

        for atk in ATTACKS_SEED:
            stmt = select(Attack).where(Attack.attack_type == atk["attack_type"])
            result = await db.execute(stmt)
            existing = result.scalars().first()

            if not existing:
                logger.info(f"  ↳ Menambahkan attack reference: '{atk['attack_type']}'...")
                db.add(Attack(
                    attack_type=atk["attack_type"],
                    symptoms=atk["symptoms"],
                    severity=atk["severity"],
                    mitre_id=atk["mitre_id"],
                    description=atk["description"],
                ))
            else:
                logger.info(f"  ↳ '{atk['attack_type']}' sudah ada, dilewati.")

        await db.commit()
        logger.info("✅ Seeder attacks selesai.")


async def main():
    await seed_users()
    await seed_attacks()
    logger.info("🎉 Semua seeder selesai dieksekusi!")

if __name__ == "__main__":
    asyncio.run(main())
