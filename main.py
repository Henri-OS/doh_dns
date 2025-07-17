from fastapi import FastAPI, Query, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
import socket
import asyncio
import dns.resolver
import httpx
import threading
import time

app = FastAPI()

# Função para resolver DNS de forma assíncrona
async def async_gethostbyname(domain: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return ip
    except socket.gaierror:
        raise

@app.get("/resolve")
async def resolve(domain: str = Query(..., description="Domínio para resolver")):
    try:
        ip = await async_gethostbyname(domain)
        return {"domain": domain, "ip": ip}
    except socket.gaierror:
        return JSONResponse(
            status_code=500,
            content={"error": f"Não foi possível resolver '{domain}'"}
        )

@app.get("/dns-query")
async def dns_query_json(
    name: str = Query(...),
    type: str = Query("A"),
    request: Request = None
):
    # Verifica se o header Accept é DNS JSON (usado por curl/firefox/chrome)
    if "application/dns-json" not in request.headers.get("accept", ""):
        return Response(status_code=406, content="Not Acceptable")

    try:
        resolver = dns.resolver.Resolver()
        qtype = type.upper()
        answer = resolver.resolve(name, qtype)
        rrset = answer.rrset

        result = {
            "Status": 0,
            "TC": False,
            "RD": True,
            "RA": True,
            "AD": False,
            "CD": False,
            "Question": [{"name": name, "type": dns.rdatatype.from_text(qtype)}],
            "Answer": [
                {
                    "name": rrset.name.to_text(),
                    "type": rrset.rdtype,
                    "TTL": rrset.ttl,
                    "data": str(r)
                } for r in rrset
            ]
        }
        return JSONResponse(content=result)
    except dns.resolver.NoAnswer:
        return JSONResponse(content={
            "Status": 3,
            "Question": [{"name": name, "type": dns.rdatatype.from_text(type)}]
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/")
async def root():
    return {"status": "DNS over HTTPS server is running"}

@app.get("/health")
async def health_check():
    return {"status": "alive", "timestamp": time.time()}

def keep_alive():
    """Função para manter o servidor ativo fazendo ping a cada 5 minutos"""
    while True:
        try:
            time.sleep(60)   # 1 minuto
            # Faz uma requisição para o próprio servidor
            import requests
            requests.get("http://0.0.0.0:5000/health", timeout=10)
            print("Keep-alive ping sent")
        except Exception as e:
            print(f"Keep-alive error: {e}")

@app.on_event("startup")
async def startup_event():
    # Inicia a thread de keep-alive
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
    print("Keep-alive system started")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)