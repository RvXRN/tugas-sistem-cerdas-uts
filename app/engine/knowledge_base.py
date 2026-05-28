import app.compat  # Harus di-import paling awal sebelum experta
from experta import KnowledgeEngine, Rule, AND, OR, NOT, MATCH, Fact
from app.engine.facts import AttackSymptom, TargetSystem, DetectedAttack
import logging

logger = logging.getLogger(__name__)

class CybersecurityExpertEngine(KnowledgeEngine):
    """
    Engine sistem pakar keamanan siber.
    """

    @Rule(
        AttackSymptom(name="port_scanning"),
        AttackSymptom(name="os_fingerprinting")
    )
    def detect_reconnaissance(self):
        logger.info("[ENGINE] Rule fired: Reconnaissance detected")
        self.declare(DetectedAttack(
            attack_type="Reconnaissance",
            confidence=0.90,
            description="Aktivitas pemindaian jaringan terdeteksi. Penyerang sedang memetakan topologi.",
            mitre_id="TA0043",
            recommendations=[
                {"priority": 1, "action": "Block source IP di firewall", "tool": "iptables / pfSense"},
                {"priority": 2, "action": "Aktifkan IDS rule untuk port scan detection", "tool": "Snort / Suricata"},
                {"priority": 3, "action": "Sembunyikan banner service", "tool": "nginx / Apache config"},
            ]
        ))

    @Rule(
        AttackSymptom(name="brute_force_login"),
        OR(
            AttackSymptom(name="multiple_failed_auth"),
            AttackSymptom(name="high_login_attempts")
        )
    )
    def detect_brute_force(self):
        logger.info("[ENGINE] Rule fired: Brute Force detected")
        self.declare(DetectedAttack(
            attack_type="Brute Force Attack",
            confidence=0.92,
            description="Percobaan login berulang dalam waktu singkat terdeteksi.",
            mitre_id="T1110",
            recommendations=[
                {"priority": 1, "action": "Implementasi rate limiting", "tool": "Nginx rate_limit / FastAPI slowapi"},
                {"priority": 2, "action": "Aktifkan CAPTCHA setelah N kali gagal", "tool": "hCaptcha"},
                {"priority": 3, "action": "Aktifkan MFA untuk semua akun", "tool": "TOTP"},
            ]
        ))

    @Rule(
        AttackSymptom(name="sql_injection_pattern"),
        TargetSystem(type="database")
    )
    def detect_sql_injection(self):
        logger.info("[ENGINE] Rule fired: SQL Injection detected")
        self.declare(DetectedAttack(
            attack_type="SQL Injection",
            confidence=0.95,
            description="Payload SQL berbahaya terdeteksi dalam request.",
            mitre_id="T1190",
            recommendations=[
                {"priority": 1, "action": "Gunakan parameterized queries", "tool": "SQLAlchemy"},
                {"priority": 2, "action": "Validasi dan sanitasi input", "tool": "Pydantic"},
                {"priority": 3, "action": "Aktifkan WAF", "tool": "ModSecurity"},
            ]
        ))

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
        logger.info("[ENGINE] Rule fired: DDoS detected")
        self.declare(DetectedAttack(
            attack_type="Distributed Denial of Service (DDoS)",
            confidence=0.88,
            description="Lonjakan traffic abnormal menyebabkan degradasi layanan.",
            mitre_id="T1498",
            recommendations=[
                {"priority": 1, "action": "Aktifkan DDoS protection layer", "tool": "Cloudflare / AWS Shield"},
                {"priority": 2, "action": "Konfigurasi rate limiting", "tool": "Nginx"},
            ]
        ))

    @Rule(
        AttackSymptom(name="xss_payload_detected"),
        TargetSystem(type="web_server")
    )
    def detect_xss(self):
        logger.info("[ENGINE] Rule fired: XSS detected")
        self.declare(DetectedAttack(
            attack_type="Cross-Site Scripting (XSS)",
            confidence=0.91,
            description="Script berbahaya ditemukan dalam input yang akan di-render.",
            mitre_id="T1059.007",
            recommendations=[
                {"priority": 1, "action": "Encode semua output", "tool": "Jinja2 / React JSX"},
                {"priority": 2, "action": "Terapkan CSP", "tool": "Helmet.js"},
            ]
        ))

    @Rule(
        AttackSymptom(name="arp_spoofing"),
        OR(
            AttackSymptom(name="ssl_stripping"),
            AttackSymptom(name="certificate_anomaly")
        )
    )
    def detect_mitm(self):
        logger.info("[ENGINE] Rule fired: MitM detected")
        self.declare(DetectedAttack(
            attack_type="Man-in-the-Middle (MitM)",
            confidence=0.85,
            description="Anomali pada lapisan jaringan mengindikasikan pencegatan komunikasi.",
            mitre_id="T1557",
            recommendations=[
                {"priority": 1, "action": "Enforce HTTPS dengan HSTS", "tool": "nginx"},
                {"priority": 2, "action": "Gunakan mTLS", "tool": "Istio"},
            ]
        ))

    @Rule(
        NOT(DetectedAttack())
    )
    def no_attack_detected(self):
        logger.info("[ENGINE] No specific attack pattern matched, using fallback.")
        self.declare(DetectedAttack(
            attack_type="Unknown / Insufficient Data",
            confidence=0.0,
            description="Gejala yang diberikan tidak cukup atau tidak cocok dengan pola serangan yang diketahui.",
            mitre_id=None,
            recommendations=[
                {"priority": 1, "action": "Lakukan analisis log manual", "tool": "ELK Stack"},
                {"priority": 2, "action": "Jalankan vulnerability scanner", "tool": "Nessus / OpenVAS"},
            ]
        ))
