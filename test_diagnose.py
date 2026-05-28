import asyncio
from app.api.endpoints import _run_engine
from app.schemas.diagnosis import DiagnosisRequest

async def main():
    print("Test 1: Reconnaissance (port_scanning, os_fingerprinting)")
    req1 = DiagnosisRequest(symptoms=["port_scanning", "os_fingerprinting"], target_system="web_server")
    res1 = await _run_engine(req1)
    for r in res1:
        print(f"[{r['attack_type']}] Conf: {r['confidence']}")
        print(f"Recommendations: {len(r['recommendations'])}")

    print("\nTest 2: Brute Force (brute_force_login, multiple_failed_auth)")
    req2 = DiagnosisRequest(symptoms=["brute_force_login", "multiple_failed_auth"], target_system="web_server")
    res2 = await _run_engine(req2)
    for r in res2:
        print(f"[{r['attack_type']}] Conf: {r['confidence']}")
        print(f"Recommendations: {len(r['recommendations'])}")

    print("\nTest 3: SQL Injection (sql_injection_pattern)")
    req3 = DiagnosisRequest(symptoms=["sql_injection_pattern"], target_system="database")
    res3 = await _run_engine(req3)
    for r in res3:
        print(f"[{r['attack_type']}] Conf: {r['confidence']}")
        print(f"Recommendations: {len(r['recommendations'])}")

    print("\nTest 4: Random unknown symptoms (ML fallback)")
    req4 = DiagnosisRequest(symptoms=["random_weird_error", "server_crash"], target_system="database")
    res4 = await _run_engine(req4)
    for r in res4:
        print(f"[{r['attack_type']}] Conf: {r['confidence']}")
        print(f"Recommendations: {len(r['recommendations'])}")

if __name__ == "__main__":
    asyncio.run(main())
