"""
Script untuk generate dataset custom yang di-mapping ke 8 kategori serangan
sesuai dengan CF rules yang didefinisikan di GEMINI.md.
"""
import pandas as pd
import random
from itertools import combinations
from pathlib import Path

random.seed(42)

# 8 kategori serangan sesuai CF rules di engine/certainty_factor.py
ATTACK_SYMPTOMS = {
    'Reconnaissance': [
        'port_scanning', 'os_fingerprinting', 'service_enumeration',
        'banner_grabbing', 'network_mapping', 'ping_sweep',
        'dns_enumeration', 'whois_lookup', 'traceroute_activity',
        'idle_scan', 'version_detection', 'tcp_connect_scan'
    ],
    'Brute Force Attack': [
        'brute_force_login', 'multiple_failed_auth', 'high_login_attempts',
        'credential_stuffing', 'password_spraying', 'dictionary_attack',
        'account_lockout_triggered', 'rapid_auth_requests',
        'failed_ssh_attempts', 'failed_rdp_attempts', 'auth_log_flooding'
    ],
    'SQL Injection': [
        'sql_injection_pattern', 'unusual_db_query', 'error_based_response',
        'blind_sqli_timing', 'union_based_payload', 'stacked_queries',
        'out_of_band_sqli', 'db_error_in_response', 'tautology_in_query',
        'encoded_sql_payload', 'time_delay_response', 'boolean_blind_sqli'
    ],
    'Distributed Denial of Service (DDoS)': [
        'high_traffic_volume', 'service_degradation', 'syn_flood',
        'udp_flood', 'http_flood', 'amplification_traffic',
        'icmp_flood', 'slow_loris_attack', 'bandwidth_saturation',
        'connection_exhaustion', 'dns_amplification', 'ntp_amplification'
    ],
    'Cross-Site Scripting (XSS)': [
        'xss_payload_detected', 'script_tag_in_input', 'dom_manipulation',
        'cookie_theft_attempt', 'reflected_payload', 'stored_xss_payload',
        'event_handler_injection', 'javascript_uri_injection',
        'malicious_iframe_injection', 'html_entity_bypass', 'csp_bypass_attempt'
    ],
    'Man-in-the-Middle (MitM)': [
        'arp_spoofing', 'ssl_stripping', 'certificate_anomaly',
        'dns_spoofing', 'unusual_gateway_mac', 'rogue_dhcp_server',
        'packet_interception', 'session_hijacking', 'ssl_certificate_mismatch',
        'bgp_hijacking', 'evil_twin_ap', 'ip_spoofing'
    ],
    'Phishing': [
        'suspicious_email_link', 'domain_spoofing', 'credential_harvesting',
        'fake_login_page', 'email_header_anomaly', 'lookalike_domain',
        'urgency_in_email', 'malicious_attachment', 'brand_impersonation',
        'spear_phishing_indicators', 'whaling_attempt', 'vishing_indicators'
    ],
    'Ransomware': [
        'mass_file_encryption', 'ransom_note_created', 'shadow_copy_deletion',
        'unusual_file_extension', 'c2_communication', 'file_rename_burst',
        'backup_deletion', 'registry_modification', 'process_injection',
        'lateral_movement', 'data_exfiltration_before_encryption', 'bitcoin_address_in_note'
    ]
}

rows = []

for attack_type, symptoms in ATTACK_SYMPTOMS.items():
    # Semua kombinasi 2 gejala
    for combo in combinations(symptoms, 2):
        rows.append({'features': ', '.join(combo), 'label': attack_type})

    # Semua kombinasi 3 gejala
    for combo in combinations(symptoms, 3):
        rows.append({'features': ', '.join(combo), 'label': attack_type})

    # Sample kombinasi 4 gejala
    combos_4 = list(combinations(symptoms, 4))
    sampled_4 = random.sample(combos_4, min(60, len(combos_4)))
    for combo in sampled_4:
        rows.append({'features': ', '.join(combo), 'label': attack_type})

    # Sample kombinasi 5 gejala
    combos_5 = list(combinations(symptoms, 5))
    sampled_5 = random.sample(combos_5, min(40, len(combos_5)))
    for combo in sampled_5:
        rows.append({'features': ', '.join(combo), 'label': attack_type})

df = pd.DataFrame(rows)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

OUT_PATH = Path(__file__).resolve().parent.parent.parent / "dataset" / "5_mapped_attacks.csv"
df.to_csv(OUT_PATH, index=False)

print(f"Dataset generated: {len(df)} rows -> {OUT_PATH}")
for label, count in df['label'].value_counts().items():
    print(f"  {label}: {count} rows")
