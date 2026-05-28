import httpx
import logging
from typing import List

logger = logging.getLogger(__name__)

async def scan_url(url_str: str) -> List[str]:
    """
    Melakukan active scanning pada URL yang diberikan.
    Mengirimkan payload HTTP dan menganalisis respons untuk mengekstrak gejala.
    """
    symptoms = set()
    
    # 1. Banner Grabbing & Basic Request
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            response = await client.get(url_str)
            
            # Cek Headers
            if "Server" in response.headers or "X-Powered-By" in response.headers:
                symptoms.add("banner_grabbing")
                
            # Asumsi jika respons lancar tanpa WAF, ini bagian dari reconnaissance
            symptoms.add("network_mapping")
            
    except Exception as e:
        logger.warning(f"Failed basic request to {url_str}: {e}")
        return list(symptoms)

    # 2. SQL Injection Check
    try:
        sqli_payloads = [
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "1' ORDER BY 1--+"
        ]
        
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for payload in sqli_payloads:
                # Tes via Query Params
                test_url = f"{url_str}?id={payload}"
                response = await client.get(test_url)
                
                resp_text = response.text.lower()
                
                # Cek indikasi error database
                if any(err in resp_text for err in ["sql syntax", "mysql_fetch", "ora-01756", "postgresql query failed"]):
                    symptoms.add("error_based_response")
                    symptoms.add("sql_injection_pattern")
                    break
    except Exception as e:
        logger.warning(f"Failed SQLi scan on {url_str}: {e}")
        
    # 3. Cross-Site Scripting (XSS) Check
    try:
        xss_payload = "<script>alert('XSS_TEST')</script>"
        
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_url = f"{url_str}?q={xss_payload}"
            response = await client.get(test_url)
            
            # Cek apakah payload di-reflect secara mentah (tanpa sanitasi html entities)
            if xss_payload in response.text:
                symptoms.add("xss_payload_detected")
                symptoms.add("reflected_payload")
                
    except Exception as e:
        logger.warning(f"Failed XSS scan on {url_str}: {e}")

    # Kembalikan daftar unik dari gejala yang terdeteksi
    return list(symptoms)
