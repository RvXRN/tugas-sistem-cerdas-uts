"""
scanner_service.py — Comprehensive Active Scanner

Melakukan pemindaian menyeluruh terhadap URL target. Terdiri dari:

1. Web Crawling       : Temukan semua link internal & form di halaman
2. Reconnaissance     : Banner grabbing, header disclosure, versi server
3. Brute Force Check  : Rate limit test pada form/endpoint login
4. SQL Injection       : Error-based, Boolean-blind, Time-based, UNION-based
5. XSS                : Reflected, DOM-based (event handler injection)
6. DDoS Simulation    : HTTP Flood test (slow loris / response time degradation)
7. MitM / SSL Checks  : Sertifikat, HTTPS enforcement, HSTS
8. Phishing Indicators: Lookalike domain, fake login page, credential harvesting
"""

import asyncio
import ssl
import time
import logging
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urlunparse
from typing import List, Set, Tuple

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Konfigurasi
# ──────────────────────────────────────────────────────────────────────────────
MAX_CRAWL_PAGES = 15          # Batas halaman yang di-crawl
REQUEST_TIMEOUT  = 8.0        # Timeout tiap request (detik)
RATE_LIMIT_TEST_COUNT = 20    # Jumlah request untuk uji rate limiting
HTTP_FLOOD_COUNT = 15         # Jumlah request untuk uji response time
BLIND_SLEEP_SEC  = 3          # Detik sleep untuk Time-based SQLi


# ──────────────────────────────────────────────────────────────────────────────
# Helper: Crawl semua halaman internal
# ──────────────────────────────────────────────────────────────────────────────
async def crawl(base_url: str, client: httpx.AsyncClient) -> Tuple[Set[str], BeautifulSoup]:
    """
    Crawl halaman web secara BFS (Breadth-First Search).
    Hanya mengikuti link yang berada di domain yang sama.
    Mengembalikan set URL yang dikunjungi & BeautifulSoup objek dari halaman awal.
    """
    visited: Set[str] = set()
    queue = [base_url]
    base_domain = urlparse(base_url).netloc
    first_soup = None

    while queue and len(visited) < MAX_CRAWL_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        try:
            resp = await client.get(url, follow_redirects=True)
            visited.add(url)
            if "text/html" not in resp.headers.get("content-type", ""):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            if first_soup is None:
                first_soup = soup
            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag["href"])
                parsed_link = urlparse(link)
                # Ikuti link yang domain-nya sama ATAU link path-relative (tidak ada host eksternal)
                if (parsed_link.netloc == base_domain or not parsed_link.netloc) and link not in visited:
                    queue.append(link)
        except Exception as e:
            logger.debug(f"[CRAWL] Gagal akses {url}: {e}")

    return visited, first_soup


# ──────────────────────────────────────────────────────────────────────────────
# Helper: Temukan semua form & input params di halaman
# ──────────────────────────────────────────────────────────────────────────────
def extract_forms_and_params(soup: BeautifulSoup, base_url: str) -> List[dict]:
    """Ekstrak semua form dari HTML, termasuk action URL dan nama input-nya."""
    forms = []
    if not soup:
        return forms
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(base_url, action) if action else base_url
        inputs = {inp.get("name"): inp.get("value", "") 
                  for inp in form.find_all("input") if inp.get("name")}
        forms.append({"action": action_url, "method": method, "inputs": inputs})
    return forms


# ──────────────────────────────────────────────────────────────────────────────
# 1. Reconnaissance & Header Analysis
# ──────────────────────────────────────────────────────────────────────────────
def check_reconnaissance(response: httpx.Response, symptoms: Set[str]):
    """Analisis header HTTP untuk mengidentifikasi informasi sensitif."""
    headers = response.headers

    # Banner Grabbing — Server version disclosure
    if headers.get("Server") or headers.get("X-Powered-By"):
        symptoms.add("banner_grabbing")
        symptoms.add("service_enumeration")
        logger.info(f"[RECON] Banner terdeteksi: Server={headers.get('Server')} X-Powered-By={headers.get('X-Powered-By')}")

    # X-Content-Type-Options missing
    if not headers.get("X-Content-Type-Options"):
        symptoms.add("version_detection")

    # Server expose terlalu banyak header
    verbose_headers = [k for k in headers if k.lower() in {
        "x-aspnet-version", "x-runtime", "x-powered-cms", "x-generator"
    }]
    if verbose_headers:
        symptoms.add("os_fingerprinting")

    # Tandai bahwa sudah dilakukan network mapping
    symptoms.add("network_mapping")


# ──────────────────────────────────────────────────────────────────────────────
# 2. SSL / MitM Check
# ──────────────────────────────────────────────────────────────────────────────
async def check_ssl_mitm(base_url: str, symptoms: Set[str]):
    """Periksa konfigurasi SSL/TLS dan HSTS untuk mendeteksi kemungkinan MitM."""
    parsed = urlparse(base_url)

    if parsed.scheme == "http":
        symptoms.add("ssl_stripping")
        logger.info("[SSL] Koneksi tidak menggunakan HTTPS — rentan SSL Stripping")
        return

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, verify=True) as client:
            resp = await client.get(base_url)
            if not resp.headers.get("Strict-Transport-Security"):
                symptoms.add("certificate_anomaly")
                logger.info("[SSL] HSTS header tidak ditemukan")
    except httpx.ConnectError:
        symptoms.add("certificate_anomaly")
        logger.warning("[SSL] Gagal verifikasi sertifikat SSL")
    except Exception as e:
        logger.debug(f"[SSL] Error: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# 3. SQL Injection Checks (Error-based, UNION, Time-based, Boolean Blind)
# ──────────────────────────────────────────────────────────────────────────────
async def check_sqli(urls: Set[str], forms: List[dict], client: httpx.AsyncClient, symptoms: Set[str]):
    """Tes kerentanan SQL Injection di setiap parameter dan form yang ditemukan."""

    error_signatures = [
        "sql syntax", "mysql_fetch", "mysql_num_rows", "ora-01756",
        "postgresql query failed", "sqlite error", "unclosed quotation mark",
        "you have an error in your sql", "warning: mysql", "odbc error",
        "db2 error", "pg_query()", "sqliteexception"
    ]
    union_payloads = ["1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--", "1 UNION ALL SELECT 1,2--"]
    error_payloads = ["'", "''", "1'\""]
    time_payloads  = [
        "1; WAITFOR DELAY '0:0:3'--",
        "1 OR SLEEP(3)--",
        "' OR SLEEP(3)--",
        "1; SELECT pg_sleep(3)--"
    ]
    boolean_payloads = [("' OR '1'='1", "' OR '1'='2")]

    # Common params yang akan diuji di setiap URL
    common_params = ["id", "q", "search", "query", "item", "page", "cat", "user"]

    async def test_url_sqli(url: str):
        # Error-based test — coba berbagai parameter umum
        for param in common_params:
            for pl in error_payloads:
                try:
                    resp = await client.get(url, params={param: pl}, timeout=REQUEST_TIMEOUT)
                    text = resp.text.lower()
                    if any(sig in text for sig in error_signatures):
                        symptoms.add("sql_injection_pattern")
                        symptoms.add("error_based_response")
                        symptoms.add("db_error_in_response")
                        logger.info(f"[SQLi] Error-based SQLi ditemukan di {url}?{param}={pl}")
                        return
                except Exception:
                    pass
        # UNION-based test
        for param in common_params[:3]:
            for pl in union_payloads:
                try:
                    resp = await client.get(url, params={param: pl}, timeout=REQUEST_TIMEOUT)
                    if any(sig in resp.text.lower() for sig in error_signatures):
                        symptoms.add("union_based_payload")
                        symptoms.add("sql_injection_pattern")
                        logger.info(f"[SQLi] UNION-based SQLi ditemukan di {url}?{param}={pl}")
                        return
                except Exception:
                    pass
        # Time-based blind test (batasi param untuk efisiensi)
        for param in ["id", "q"]:
            for pl in time_payloads[:2]:
                try:
                    start = time.time()
                    await client.get(url, params={param: pl}, timeout=BLIND_SLEEP_SEC + 5)
                    elapsed = time.time() - start
                    if elapsed >= BLIND_SLEEP_SEC:
                        symptoms.add("blind_sqli_timing")
                        symptoms.add("time_delay_response")
                        symptoms.add("sql_injection_pattern")
                        logger.info(f"[SQLi] Time-based blind SQLi ditemukan di {url} (delay: {elapsed:.1f}s)")
                        return
                except Exception:
                    pass
        # Boolean-based blind test
        try:
            pl_true, pl_false = boolean_payloads[0]
            r_true  = await client.get(url, params={"id": pl_true},  timeout=REQUEST_TIMEOUT)
            r_false = await client.get(url, params={"id": pl_false}, timeout=REQUEST_TIMEOUT)
            if r_true.text != r_false.text and r_true.status_code == 200:
                symptoms.add("boolean_blind_sqli")
                symptoms.add("sql_injection_pattern")
                symptoms.add("tautology_in_query")
                logger.info(f"[SQLi] Boolean-blind SQLi ditemukan di {url}")
        except Exception:
            pass

    # Test semua halaman yang di-crawl
    tasks = [test_url_sqli(url) for url in list(urls)[:10]]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Test semua form yang ditemukan
    for form in forms:
        if form["method"] == "get":
            injected = {k: "'" for k in form["inputs"]}
            try:
                resp = await client.get(form["action"], params=injected, timeout=REQUEST_TIMEOUT)
                if any(sig in resp.text.lower() for sig in error_signatures):
                    symptoms.add("sql_injection_pattern")
                    symptoms.add("error_based_response")
                    logger.info(f"[SQLi] Ditemukan lewat form GET di {form['action']}")
            except Exception:
                pass
        elif form["method"] == "post":
            injected = {k: "'" for k in form["inputs"]}
            try:
                resp = await client.post(form["action"], data=injected, timeout=REQUEST_TIMEOUT)
                if any(sig in resp.text.lower() for sig in error_signatures):
                    symptoms.add("sql_injection_pattern")
                    symptoms.add("error_based_response")
                    logger.info(f"[SQLi] Ditemukan lewat form POST di {form['action']}")
            except Exception:
                pass


# ──────────────────────────────────────────────────────────────────────────────
# 4. XSS Checks (Reflected, Event Handler, DOM-based)
# ──────────────────────────────────────────────────────────────────────────────
async def check_xss(urls: Set[str], forms: List[dict], client: httpx.AsyncClient, symptoms: Set[str]):
    """Tes kerentanan XSS di parameter URL dan form."""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "\"><script>alert(1)</script>",
    ]

    for url in list(urls)[:10]:
        for pl in xss_payloads:
            try:
                resp = await client.get(f"{url}?q={pl}&search={pl}", timeout=REQUEST_TIMEOUT)
                if pl in resp.text:
                    symptoms.add("xss_payload_detected")
                    symptoms.add("reflected_payload")
                    logger.info(f"[XSS] Reflected XSS ditemukan di {url}")
                    # Cek tipe payload spesifik
                    if "onerror" in pl or "onload" in pl:
                        symptoms.add("event_handler_injection")
                    if "javascript:" in pl:
                        symptoms.add("javascript_uri_injection")
                    break
            except Exception:
                pass

    # Test form
    for form in forms:
        for pl in xss_payloads[:3]:
            injected = {k: pl for k in form["inputs"]}
            try:
                if form["method"] == "post":
                    resp = await client.post(form["action"], data=injected, timeout=REQUEST_TIMEOUT)
                else:
                    resp = await client.get(form["action"], params=injected, timeout=REQUEST_TIMEOUT)
                if pl in resp.text:
                    symptoms.add("xss_payload_detected")
                    symptoms.add("script_tag_in_input")
                    logger.info(f"[XSS] XSS via form ditemukan di {form['action']}")
                    break
            except Exception:
                pass


# ──────────────────────────────────────────────────────────────────────────────
# 5. Brute Force / Rate Limit Check
# ──────────────────────────────────────────────────────────────────────────────
async def check_brute_force(forms: List[dict], base_url: str, client: httpx.AsyncClient, symptoms: Set[str]):
    """
    Deteksi kelemahan terhadap Brute Force dengan mengecek apakah
    server memiliki Rate Limiting pada endpoint login.
    """
    login_keywords = ["login", "signin", "auth", "account", "masuk", "password"]
    login_forms = [
        f for f in forms
        if any(kw in f["action"].lower() for kw in login_keywords)
        or any(kw in k.lower() for k in f["inputs"] for kw in ["password", "pass", "pwd"])
    ]

    # Jika tidak ada form login, coba URL umum
    if not login_forms:
        parsed = urlparse(base_url)
        guessed_urls = [
            f"{parsed.scheme}://{parsed.netloc}/login",
            f"{parsed.scheme}://{parsed.netloc}/api/login",
            f"{parsed.scheme}://{parsed.netloc}/api/v1/auth/login",
        ]
        for url in guessed_urls:
            try:
                resp = await client.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code in (200, 405):
                    login_forms.append({"action": url, "method": "post",
                                        "inputs": {"username": "admin", "password": "test"}})
                    break
            except Exception:
                pass

    if not login_forms:
        logger.info("[BF] Tidak ditemukan form/endpoint login untuk diuji")
        return

    target_form = login_forms[0]
    dummy_payload = {k: "invalid_test_value_123" for k in target_form["inputs"]}
    responses_codes = []

    logger.info(f"[BF] Menguji rate limit di {target_form['action']} dengan {RATE_LIMIT_TEST_COUNT} request...")
    for i in range(RATE_LIMIT_TEST_COUNT):
        try:
            if target_form["method"] == "post":
                resp = await client.post(target_form["action"], data=dummy_payload, timeout=REQUEST_TIMEOUT)
            else:
                resp = await client.get(target_form["action"], params=dummy_payload, timeout=REQUEST_TIMEOUT)
            responses_codes.append(resp.status_code)
            if resp.status_code == 429:
                logger.info(f"[BF] Rate limit aktif (HTTP 429) setelah {i+1} request — AMAN")
                return
        except Exception as e:
            logger.debug(f"[BF] Request #{i+1} gagal: {e}")
            break

    # Jika tidak pernah dapat 429 setelah N request, kemungkinan besar tidak ada rate limit
    if responses_codes and 429 not in responses_codes:
        symptoms.add("rapid_auth_requests")
        symptoms.add("high_login_attempts")
        symptoms.add("multiple_failed_auth")
        logger.warning(f"[BF] Tidak ada rate limiting! {RATE_LIMIT_TEST_COUNT} request tanpa HTTP 429 — RENTAN Brute Force")


# ──────────────────────────────────────────────────────────────────────────────
# 6. DDoS / Service Degradation Check
# ──────────────────────────────────────────────────────────────────────────────
async def check_ddos_resilience(base_url: str, symptoms: Set[str]):
    """
    Kirim sejumlah request concurrently untuk mengukur degradasi respons.
    Jika waktu rata-rata meningkat drastis, ini mengindikasikan tidak ada
    perlindungan terhadap HTTP Flood.
    """
    # Baseline: ukur waktu 1 request
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, verify=False) as client:
            t0 = time.time()
            await client.get(base_url)
            baseline_ms = (time.time() - t0) * 1000
    except Exception:
        return

    # Flood: kirim N request bersamaan
    async def single_req():
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, verify=False) as c:
                t0 = time.time()
                await c.get(base_url)
                return (time.time() - t0) * 1000
        except Exception:
            return None

    results = await asyncio.gather(*[single_req() for _ in range(HTTP_FLOOD_COUNT)])
    valid_results = [r for r in results if r is not None]

    if not valid_results:
        return

    avg_ms = sum(valid_results) / len(valid_results)
    degradation_ratio = avg_ms / max(baseline_ms, 1)

    logger.info(f"[DDoS] Baseline: {baseline_ms:.0f}ms | Avg under {HTTP_FLOOD_COUNT} concurrent: {avg_ms:.0f}ms | Ratio: {degradation_ratio:.2f}x")

    if degradation_ratio >= 3.0:
        symptoms.add("service_degradation")
        symptoms.add("http_flood")
        symptoms.add("connection_exhaustion")
        logger.warning(f"[DDoS] Degradasi signifikan terdeteksi ({degradation_ratio:.1f}x) — kemungkinan rentan HTTP Flood")
    elif degradation_ratio >= 1.5:
        symptoms.add("service_degradation")
        logger.info(f"[DDoS] Sedikit degradasi ({degradation_ratio:.1f}x) — perlu pemantauan lebih lanjut")


# ──────────────────────────────────────────────────────────────────────────────
# 7. Phishing Indicators Check
# ──────────────────────────────────────────────────────────────────────────────
async def check_phishing_indicators(base_url: str, soup: BeautifulSoup, symptoms: Set[str]):
    """
    Cek apakah halaman ini memiliki indikasi halaman phishing:
    - Ada form login yang mengirim data ke domain lain (credential harvesting)
    - Tidak ada koneksi HTTPS
    - Mengandung merek terkenal tapi di-host di domain yang tidak sesuai
    """
    trusted_brands = ["paypal", "google", "facebook", "amazon", "apple", "microsoft",
                      "bankbca", "mandiri", "bni", "bri", "tokopedia", "shopee"]
    parsed = urlparse(base_url)
    domain = parsed.netloc.lower()

    if not soup:
        return

    # Cek form yang mengirim ke domain lain (exfiltration)
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "")
        if action and action.startswith("http"):
            action_domain = urlparse(action).netloc.lower()
            if action_domain and action_domain != domain:
                symptoms.add("credential_harvesting")
                logger.warning(f"[Phishing] Form mengirim data ke domain lain: {action_domain}")
                break

    # Cek apakah halaman menggunakan brand terkenal tapi domain tidak matching
    page_text = soup.get_text().lower()
    for brand in trusted_brands:
        if brand in page_text and brand not in domain:
            symptoms.add("brand_impersonation")
            symptoms.add("fake_login_page")
            logger.warning(f"[Phishing] Brand '{brand}' terdeteksi tapi domain adalah '{domain}'")
            break

    # Cek login form tanpa HTTPS
    if parsed.scheme == "http":
        has_password_input = any(
            inp.get("type") == "password"
            for form in forms
            for inp in form.find_all("input")
        )
        if has_password_input:
            symptoms.add("credential_harvesting")
            symptoms.add("domain_spoofing")
            logger.warning(f"[Phishing] Form password tanpa HTTPS di {base_url}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN SCAN FUNCTION
# ──────────────────────────────────────────────────────────────────────────────
async def scan_url(url_str: str) -> List[str]:
    """
    Entry point scanner. Menjalankan seluruh rangkaian pemindaian secara
    berurutan dan mengembalikan daftar gejala yang terdeteksi.
    """
    symptoms: Set[str] = set()
    logger.info(f"[SCAN] Memulai pemindaian komprehensif terhadap: {url_str}")

    # ─── Step 1: Crawling ─────────────────────────────────────────────────────
    logger.info("[SCAN] Step 1/7 — Crawling halaman...")
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, verify=False, follow_redirects=True) as client:
            visited_urls, first_soup = await crawl(url_str, client)
            forms = extract_forms_and_params(first_soup, url_str) if first_soup else []
            logger.info(f"[CRAWL] Ditemukan {len(visited_urls)} halaman, {len(forms)} form")

            # Ambil respons pertama untuk analisis header
            try:
                base_response = await client.get(url_str)
            except Exception:
                base_response = None

            # ─── Step 2: Reconnaissance ───────────────────────────────────────
            logger.info("[SCAN] Step 2/7 — Reconnaissance & Header Analysis...")
            if base_response:
                check_reconnaissance(base_response, symptoms)

            # ─── Step 3: SQLi ─────────────────────────────────────────────────
            logger.info("[SCAN] Step 3/7 — SQL Injection...")
            await check_sqli(visited_urls, forms, client, symptoms)

            # ─── Step 4: XSS ──────────────────────────────────────────────────
            logger.info("[SCAN] Step 4/7 — Cross-Site Scripting (XSS)...")
            await check_xss(visited_urls, forms, client, symptoms)

            # ─── Step 5: Brute Force / Rate Limit ────────────────────────────
            logger.info("[SCAN] Step 5/7 — Brute Force / Rate Limit Test...")
            await check_brute_force(forms, url_str, client, symptoms)

    except Exception as e:
        logger.error(f"[SCAN] Error pada saat crawling/scanning: {e}")

    # ─── Step 6: DDoS Resilience ──────────────────────────────────────────────
    logger.info("[SCAN] Step 6/7 — DDoS & HTTP Flood Resilience Test...")
    await check_ddos_resilience(url_str, symptoms)

    # ─── Step 7: SSL/MitM & Phishing ──────────────────────────────────────────
    logger.info("[SCAN] Step 7/7 — SSL / MitM / Phishing Indicators...")
    await check_ssl_mitm(url_str, symptoms)
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, verify=False) as client:
            resp = await client.get(url_str)
            soup = BeautifulSoup(resp.text, "html.parser")
            await check_phishing_indicators(url_str, soup, symptoms)
    except Exception as e:
        logger.debug(f"[Phishing check] Error: {e}")

    logger.info(f"[SCAN] Selesai. Total gejala terdeteksi: {len(symptoms)} → {list(symptoms)}")
    return list(symptoms)
