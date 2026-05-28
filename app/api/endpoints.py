import time
import uuid
import json
import hashlib
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.schemas.diagnosis import DiagnosisRequest, DiagnosisResponse, AttackResult, DefenseRecommendation, ScanRequest
from app.engine.knowledge_base import CybersecurityExpertEngine
from app.engine.facts import AttackSymptom, TargetSystem, DetectedAttack
from app.ml.engine import MLCybersecurityEngine
from app.core.database import get_db, get_redis
from app.repositories.history_repository import HistoryRepository
from app.engine.certainty_factor import diagnose_with_cf
from app.services.scanner_service import scan_url

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/api/v1", tags=["Diagnosis"])

def _build_cache_key(request: DiagnosisRequest) -> str:
    sorted_symptoms = sorted(request.symptoms)
    payload = f"{sorted_symptoms}:{request.target_system}:{request.severity_hint}"
    return f"diagnosis:{hashlib.md5(payload.encode()).hexdigest()}"

async def _run_engine(request: DiagnosisRequest) -> list:
    """
    Gabungan Forward Chaining (Experta) + Certainty Factor.
    Jika tidak ada hasil, fallback ke Machine Learning.
    """
    # Step 1: Hitung CF
    cf_results = diagnose_with_cf(request.symptoms, threshold=0.40)

    # Step 2: Jalankan Experta (Forward Chaining)
    experta_engine = CybersecurityExpertEngine()
    experta_engine.reset()

    for symptom in request.symptoms:
        experta_engine.declare(AttackSymptom(name=symptom))

    if request.target_system:
        experta_engine.declare(TargetSystem(type=request.target_system))

    experta_engine.run()

    experta_attacks = {
        fact["attack_type"]: fact
        for fact in experta_engine.facts.values()
        if isinstance(fact, DetectedAttack)
    }

    final_results = []
    # Step 3: Merge CF dan Experta
    for cf_result in cf_results:
        attack_type = cf_result["attack_type"]
        experta_data = experta_attacks.get(attack_type, {})

        final_results.append({
            "attack_type": attack_type,
            "confidence": cf_result["confidence"],
            "matched_symptoms": cf_result["matched_symptoms"],
            "description": experta_data.get("description", "Aktivitas mencurigakan terdeteksi (berdasarkan confidence factor)."),
            "mitre_id": experta_data.get("mitre_id"),
            "recommendations": experta_data.get("recommendations", []),
        })

    # Step 4: ML Fallback jika CF/Experta gagal deteksi
    if not final_results:
        ml_engine = MLCybersecurityEngine()
        ml_results = ml_engine.predict(symptoms=request.symptoms, target_system=request.target_system)
        
        # Format output ML sama dengan Experta
        for ml_res in ml_results:
            final_results.append({
                "attack_type": ml_res["attack_type"],
                "confidence": ml_res["confidence"],
                "matched_symptoms": request.symptoms,
                "description": ml_res.get("description", "Serangan terdeteksi oleh Machine Learning Engine."),
                "mitre_id": ml_res.get("mitre_id"),
                "recommendations": ml_res.get("recommendations", []),
            })

    # Fallback absolute jika ML juga gagal
    if not final_results:
        final_results.append({
            "attack_type": "Unknown / Insufficient Data",
            "confidence": 0.0,
            "matched_symptoms": [],
            "description": "Gejala tidak cukup atau tidak cocok dengan pola serangan yang diketahui.",
            "mitre_id": None,
            "recommendations": [
                {"priority": 1, "action": "Analisis log manual lebih mendalam", "tool": "ELK Stack / Splunk"},
                {"priority": 2, "action": "Jalankan vulnerability scanner", "tool": "Nessus / OpenVAS"},
            ],
        })

    return final_results

from app.api.deps import get_current_user
from app.models.user import User

async def _handle_detect(
    request: DiagnosisRequest,
    current_user: User,
    db: AsyncSession,
    redis,
) -> DiagnosisResponse:
    """Logika utama deteksi via gejala manual. Dipakai oleh /detect dan /diagnose."""
    start_time = time.time()
    cache_key = _build_cache_key(request)

    # Cek cache Redis
    cached = await redis.get(cache_key)
    if cached:
        response_data = json.loads(cached)
        response_data["from_cache"] = True
        response_data["session_id"] = str(uuid.uuid4())
        return DiagnosisResponse(**response_data)

    try:
        detected_facts = await _run_engine(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Engine error: {str(e)}"
        )

    detected_attacks = []
    all_recommendations = []

    for fact in detected_facts:
        detected_attacks.append(AttackResult(
            attack_type=fact["attack_type"],
            confidence=fact["confidence"],
            description=fact.get("description", ""),
            mitre_id=fact.get("mitre_id")
        ))
        for rec in fact.get("recommendations", []):
            all_recommendations.append(DefenseRecommendation(
                priority=rec["priority"],
                action=rec["action"],
                tool_suggestion=rec.get("tool")
            ))

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

    cache_data = response.model_dump()
    cache_data.pop("session_id")
    cache_data.pop("from_cache")
    await redis.setex(cache_key, 3600, json.dumps(cache_data, default=str))

    await HistoryRepository.create_consultation_history(
        db=db,
        session_id=session_id,
        symptoms=request.symptoms,
        target_system=request.target_system,
        detected_attacks=[a.model_dump() for a in detected_attacks],
        duration_ms=duration_ms
    )

    return response


@router.post(
    "/detect",
    response_model=DiagnosisResponse,
    summary="[Primary] Deteksi serangan siber berdasarkan gejala (symptoms)"
)
async def detect(
    request: DiagnosisRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis)
):
    """
    Endpoint utama untuk deteksi via gejala manual.
    Gunakan ini dari frontend untuk analisis log/gejala yang sudah dikumpulkan.
    """
    return await _handle_detect(request, current_user, db, redis)


@router.post(
    "/diagnose",
    response_model=DiagnosisResponse,
    summary="[Alias] Sama dengan /detect — dipertahankan untuk backward compatibility",
    include_in_schema=True
)
async def diagnose(
    request: DiagnosisRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis)
):
    """Alias dari /detect. Tetap bisa dipakai agar tidak breaking change."""
    return await _handle_detect(request, current_user, db, redis)

@router.post(
    "/scan",
    response_model=DiagnosisResponse,
    summary="Active scanning pada URL target untuk mendeteksi kerentanan"
)
@limiter.limit("5/minute")  # Maks 5 scan per menit per IP
async def active_scan(
    http_request: Request,
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis=Depends(get_redis)
):
    start_time = time.time()
    url_str = str(request.url)
    
    # 1. Lakukan active scanning
    extracted_symptoms = await scan_url(url_str)
    
    # Jika tidak ada gejala yang ditemukan
    if not extracted_symptoms:
        session_id = str(uuid.uuid4())
        return DiagnosisResponse(
            session_id=session_id,
            detected_attacks=[AttackResult(
                attack_type="Safe / No Vulnerability Detected",
                confidence=1.0,
                description=f"Tidak ditemukan indikasi kerentanan XSS atau SQLi dari pemindaian dasar pada {url_str}.",
                mitre_id=None
            )],
            defense_recommendations=[DefenseRecommendation(
                priority=1,
                action="Tetap pantau log server dan lakukan penetration testing secara rutin.",
                tool_suggestion="OWASP ZAP / BurpSuite"
            )],
            analysis_duration_ms=round((time.time() - start_time) * 1000, 2),
            from_cache=False
        )

    # 2. Buat objek DiagnosisRequest dari gejala yang ditemukan
    diag_req = DiagnosisRequest(
        symptoms=extracted_symptoms,
        target_system="web_server"
    )

    # 3. Jalankan Engine
    try:
        detected_facts = await _run_engine(diag_req)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Engine error: {str(e)}"
        )

    # 4. Format Output
    detected_attacks = []
    all_recommendations = []

    for fact in detected_facts:
        detected_attacks.append(AttackResult(
            attack_type=fact["attack_type"],
            confidence=fact["confidence"],
            description=fact.get("description", ""),
            mitre_id=fact.get("mitre_id")
        ))
        for rec in fact.get("recommendations", []):
            all_recommendations.append(DefenseRecommendation(
                priority=rec["priority"],
                action=rec["action"],
                tool_suggestion=rec.get("tool")
            ))

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
    
    await HistoryRepository.create_consultation_history(db=db, 
        session_id=session_id,
        symptoms=extracted_symptoms,
        target_system="web_server",
        detected_attacks=[a.model_dump() for a in detected_attacks],
        duration_ms=duration_ms
    )

    return response
