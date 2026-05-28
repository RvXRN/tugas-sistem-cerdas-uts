import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_diagnose_auth_bypass(client: AsyncClient):
    """
    Test untuk memastikan endpoint /api/v1/diagnose tidak bisa diakses
    tanpa menyediakan JWT token yang valid.
    """
    payload = {
        "symptoms": ["port_scanning"],
        "target_system": "web_server"
    }
    
    # Request tanpa Header Authorization
    response = await client.post("/api/v1/diagnose", json=payload)
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


@pytest.mark.asyncio
async def test_diagnose_invalid_token(client: AsyncClient):
    """
    Test dengan token yang asal-asalan.
    """
    payload = {
        "symptoms": ["port_scanning"]
    }
    
    headers = {
        "Authorization": "Bearer token-palsu-dan-tidak-valid"
    }
    
    response = await client.post("/api/v1/diagnose", json=payload, headers=headers)
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]


@pytest.mark.asyncio
async def test_payload_injection_sqli_xss(client: AsyncClient):
    """
    Test apakah Pydantic schema bisa menahan atau menerima string payload.
    Jika kita mengirimkan payload XSS/SQLi di symptoms, backend harus memprosesnya sebagai string,
    dan tidak crash. Uji ketahanan.
    """
    # Untuk menjalankan test otorisasi, kita butuh token asli atau override get_current_user.
    # Namun karena ini test injection pada level API, jika kita bisa mencapai validasi pydantic,
    # itu sudah cukup. Mari override dependency get_current_user sementara.
    
    from app.main import app
    from app.api.deps import get_current_user
    from app.models.user import User
    
    # Mocking user login
    app.dependency_overrides[get_current_user] = lambda: User(id=1, username="test_user")

    payload = {
        "symptoms": [
            "port_scanning",
            "<script>alert('XSS')</script>",
            "1' OR '1'='1"
        ],
        "target_system": "database"
    }
    
    # Request yang sudah terotorisasi (berkat override)
    response = await client.post("/api/v1/diagnose", json=payload)
    
    # Pydantic seharusnya membiarkan string ini masuk (status 200 OK),
    # namun engine ML/Experta tidak akan memprosesnya (hanya mengabaikan karena tidak dikenali)
    assert response.status_code == 200
    data = response.json()
    
    # Memastikan tidak terjadi crash dan payload masuk akal
    assert "session_id" in data
    assert isinstance(data["detected_attacks"], list)

    # Clean up override
    app.dependency_overrides.pop(get_current_user)
