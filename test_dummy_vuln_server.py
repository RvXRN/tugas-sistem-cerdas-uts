from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="Dummy Vulnerable App")

@app.get("/vulnerable_page")
async def vulnerable(request: Request):
    q = request.query_params.get("q", "")
    id_param = request.query_params.get("id", "")
    
    # Simulasi XSS
    html_content = f"<h1>Search Results for: {q}</h1>"
    
    # Simulasi SQLi
    if id_param == "' OR 1=1 --" or id_param == "\" OR 1=1 --":
        html_content += "<p>Error: mysql_fetch_array() expects parameter 1 to be resource, boolean given in query</p>"
        
    return HTMLResponse(content=html_content, headers={"X-Powered-By": "PHP/5.2.4"})

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
