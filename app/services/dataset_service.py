import pandas as pd
import json
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete
import math

from app.models.attack import Attack
from app.models.cve import CVE
from app.models.ioc import IoC

DATASET_DIR = Path("dataset")

def _parse_tags(tags_val):
    if pd.isna(tags_val) or str(tags_val).strip() == "Unknown":
        return []
    return [tag.strip() for tag in str(tags_val).split(",")]

def _safe_float(val, default=0.0):
    if pd.isna(val) or val == "Unknown":
        return default
    try:
        return float(val)
    except ValueError:
        return default

def _safe_str(val, default=None):
    if pd.isna(val) or str(val).strip() == "Unknown":
        return default
    return str(val).strip()

def _parse_date(val):
    if pd.isna(val) or str(val).strip() == "Unknown":
        return None
    try:
        # Pandas to_datetime can handle this
        return pd.to_datetime(val).date()
    except Exception:
        return None

async def load_threat_intel(session: AsyncSession):
    file_path = DATASET_DIR / "1_otx_threat_intel.csv"
    if not file_path.exists():
        return 0

    await session.execute(delete(Attack))
    
    # Baca file dengan pandas dan filter kolom yang diperlukan
    df = pd.read_csv(file_path)
    required_cols = ["Title", "Description", "Tags", "Attack_IDs"]
    # Buang kolom yang tidak digunakan jika ada
    df = df[[col for col in required_cols if col in df.columns]]

    attacks = []
    for _, row in df.iterrows():
        attacks.append(
            Attack(
                attack_type=_safe_str(row.get("Title"), "Unknown Threat"),
                description=_safe_str(row.get("Description"), ""),
                symptoms=_parse_tags(row.get("Tags")),
                severity="medium",
                mitre_id=_safe_str(row.get("Attack_IDs"))
            )
        )
    
    session.add_all(attacks)
    await session.commit()
    return len(attacks)

async def load_cves(session: AsyncSession):
    file_path = DATASET_DIR / "2_cve_vulnerabilities.csv"
    if not file_path.exists():
        return 0

    await session.execute(delete(CVE))
    
    df = pd.read_csv(file_path)
    required_cols = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate", "cwes"]
    df = df[[col for col in required_cols if col in df.columns]]

    cves = []
    for _, row in df.iterrows():
        cves.append(
            CVE(
                cve_id=_safe_str(row.get("cveID")),
                vendor_project=_safe_str(row.get("vendorProject")),
                product=_safe_str(row.get("product")),
                vulnerability_name=_safe_str(row.get("vulnerabilityName")),
                date_added=_parse_date(row.get("dateAdded")),
                short_description=_safe_str(row.get("shortDescription")),
                required_action=_safe_str(row.get("requiredAction")),
                due_date=_parse_date(row.get("dueDate")),
                cwes=_safe_str(row.get("cwes"))
            )
        )
        
    session.add_all(cves)
    await session.commit()
    return len(cves)

async def load_iocs(session: AsyncSession):
    count = 0
    await session.execute(delete(IoC))

    domain_path = DATASET_DIR / "3_malicious_domains.csv"
    if domain_path.exists():
        df_domain = pd.read_csv(domain_path)
        required_cols = ["Domain", "Reputation", "Threat_Severity", "Data_Source"]
        df_domain = df_domain[[col for col in required_cols if col in df_domain.columns]]
        
        iocs = []
        for _, row in df_domain.iterrows():
            iocs.append(
                IoC(
                    indicator=_safe_str(row.get("Domain")),
                    indicator_type="domain",
                    reputation_score=_safe_float(row.get("Reputation")),
                    threat_label=_safe_str(row.get("Threat_Severity")),
                    threat_severity=_safe_str(row.get("Threat_Severity")),
                    data_source=_safe_str(row.get("Data_Source"))
                )
            )
        session.add_all(iocs)
        count += len(iocs)

    ip_path = DATASET_DIR / "4_malicious_ips.csv"
    if ip_path.exists():
        df_ip = pd.read_csv(ip_path)
        required_cols = ["IP", "Reputation_Score", "Threat_Label", "Threat_Severity", "Owner"]
        df_ip = df_ip[[col for col in required_cols if col in df_ip.columns]]
        
        iocs = []
        for _, row in df_ip.iterrows():
            iocs.append(
                IoC(
                    indicator=_safe_str(row.get("IP")),
                    indicator_type="ip",
                    reputation_score=_safe_float(row.get("Reputation_Score")),
                    threat_label=_safe_str(row.get("Threat_Label")),
                    threat_severity=_safe_str(row.get("Threat_Severity")),
                    data_source=_safe_str(row.get("Owner"))
                )
            )
        session.add_all(iocs)
        count += len(iocs)

    await session.commit()
    return count

async def load_all_datasets(session: AsyncSession) -> dict:
    threat_intel_count = await load_threat_intel(session)
    cves_count = await load_cves(session)
    iocs_count = await load_iocs(session)

    return {
        "threat_intel_loaded": threat_intel_count,
        "cves_loaded": cves_count,
        "iocs_loaded": iocs_count,
        "total_loaded": threat_intel_count + cves_count + iocs_count
    }
