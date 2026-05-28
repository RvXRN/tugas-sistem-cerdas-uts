import pytest
import pytest_asyncio
from unittest.mock import patch
import uuid
import time
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.history import ConsultationHistory
from app.models.user import User
from app.core.security import create_access_token

from sqlalchemy import select
@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession):
    # Check if user already exists
    result = await db_session.execute(select(User).where(User.username == "testuser"))
    user = result.scalars().first()
    
    if not user:
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="fakehashedpassword",
            role="user"
        )
        db_session.add(user)
        await db_session.commit()
    
    return user

@pytest.fixture
def test_token(test_user):
    return create_access_token(data={"sub": test_user.username})

@pytest.fixture
def auth_headers(test_token):
    return {"Authorization": f"Bearer {test_token}"}

@pytest.mark.asyncio
async def test_get_history_empty(client, auth_headers):
    response = await client.get("/api/v1/history/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["data"] == []

@pytest.mark.asyncio
async def test_get_history_with_data(client, auth_headers, db_session: AsyncSession):
    # Insert a dummy history
    session_id = str(uuid.uuid4())
    history = ConsultationHistory(
        session_id=session_id,
        symptoms=["xss_payload_detected"],
        target_system="web_server",
        detected_attacks=[{"attack_type": "Cross-Site Scripting (XSS)", "confidence": 0.9}],
        duration_ms=10.5
    )
    db_session.add(history)
    await db_session.commit()

    # Query history
    response = await client.get("/api/v1/history/", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["data"][0]["session_id"] == session_id

    # Query by session_id
    response_single = await client.get(f"/api/v1/history/{session_id}", headers=auth_headers)
    assert response_single.status_code == 200
    data_single = response_single.json()
    assert data_single["session_id"] == session_id
    assert data_single["target_system"] == "web_server"

@pytest.mark.asyncio
@patch("app.api.endpoints.scan_url")
async def test_active_scan_safe(mock_scan_url, client, auth_headers):
    # Mocking scan_url to return no symptoms (safe)
    mock_scan_url.return_value = []
    
    payload = {"url": "http://example.com"}
    response = await client.post("/api/v1/scan", json=payload, headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "session_id" in data
    assert len(data["detected_attacks"]) == 1
    assert data["detected_attacks"][0]["attack_type"] == "Safe / No Vulnerability Detected"

@pytest.mark.asyncio
@patch("app.api.endpoints.scan_url")
async def test_active_scan_vulnerable(mock_scan_url, client, auth_headers):
    # Mocking scan_url to return some SQLi symptoms
    mock_scan_url.return_value = ["sql_injection_pattern", "error_based_response"]
    
    payload = {"url": "http://vulnerable.com"}
    response = await client.post("/api/v1/scan", json=payload, headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "session_id" in data
    assert len(data["detected_attacks"]) > 0
    # Engine should classify this as SQL Injection
    assert any(atk["attack_type"] == "SQL Injection" for atk in data["detected_attacks"])

@pytest.mark.asyncio
@patch("app.api.endpoints.scan_url")
async def test_active_scan_error(mock_scan_url, client, auth_headers):
    # Mocking scan_url to raise an Exception
    mock_scan_url.side_effect = Exception("Simulated timeout error")
    
    payload = {"url": "http://error.com"}
    response = await client.post("/api/v1/scan", json=payload, headers=auth_headers)
    
    # Check that our try/except caught it and returned 500
    assert response.status_code == 500
    assert "Simulated timeout error" in response.json()["detail"]
