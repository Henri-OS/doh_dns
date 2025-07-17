from fastapi import FastAPI, Query, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import socket
import asyncio
import dns.resolver
import time

app = FastAPI()

# ---------------------------
# Proteção: Limite de Requisições por IP
# ---------------------------
RATE_LIMIT = {}
MAX_REQUESTS = 10
WINDOW_SECONDS = 60

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        now = time.time()
        history = RATE_LIMIT.get(ip, [])
        # Limpa requisições antigas
        history = [t for t in history if now - t < WINDOW_SECONDS]
        if len(history) >= MAX_REQUESTS:
            return JSONResponse(status_code=429, content={"error": "Limite de requisições excedido"})
        history.append(now)
        RATE_LIMIT[ip] = history
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)

# ---------------------------
# Domínios bloqueados
# ---------------------------
BLOCKED_DOMAINS = ["localhost", "127.0.0.1", "::1", ".onion"]

def is_blocked(domain: str) -> bool:
    return any(bad in domain for bad in BLOCKED_DOMAINS)

# ---------------------------
# Resolver DNS (gethostbyname async)
# ---------------------------
async def async_gethostbyname(domain: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return ip
    except socket.gaierror:
        raise

# ---------------------------
# Endpoint: Resolução simples de IP
# ---------------------------
@app.get("/resolve")
async def resolve(domain: str = Query(..., description="Domínio para resolver")):
    if is_blocked(domain):
        return JSONResponse(status_code=400, content={"error": "Domínio não permitido"})

    try:
        ip = await async_gethostbyname(domain)
        return {"domain": domain, "ip": ip}
    except socket.gaierror:
        return JSONResponse(
            status_code=500,
            content={"error": f"Não foi possível resolver '{domain}'"}
        )

# ---------------------------
# Endpoint: DNS-over-HTTPS estilo Google
# ---------------------------
@app.get("/dns-query")
async def dns_query_json(
    name: str = Query(...),
    type: str = Query("A"),
    request: Request = None
):
    if is_blocked(name):
        return JSONResponse(status_code=400, content={"error": "Domínio não permitido"})

    # Apenas aceita application/dns-json
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

# ---------------------------
# Página inicial (status)
# ---------------------------
@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Servidor DNS sobre HTTPS (educacional). Uso abusivo será bloqueado.",
    }
