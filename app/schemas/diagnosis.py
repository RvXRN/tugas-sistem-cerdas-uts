from pydantic import BaseModel, Field, HttpUrl
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
        min_length=1,
        max_length=20,
        description="Daftar gejala yang diamati, contoh: ['port_scanning', 'high_traffic']"
    )
    target_system: Optional[str] = Field(
        default=None,
        description="Sistem yang diserang, contoh: 'web_server', 'database'"
    )
    target_url: Optional[str] = Field(
        default=None,
        description="URL target jika relevan (misal untuk manual detection dengan target spesifik)"
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
                "target_url": "http://localhost:8081",
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

class ScanRequest(BaseModel):
    """
    Schema untuk request active scanning.
    Menerima URL yang akan diuji kerentanannya.
    """
    url: HttpUrl = Field(
        ...,
        description="URL target yang akan dipindai secara aktif"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://localhost:8081"
            }
        }
