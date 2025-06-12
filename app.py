from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
import socket
import asyncio
import dns.resolver

app = FastAPI()

# Função para resolver DNS de forma assíncrona com gethostbyname
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
    # Verifica se o header Accept é DNS JSON (RFC 8484)
    if "application/dns-json" not in request.headers.get("accept", ""):
        return Response(status_code=406, content="Not Acceptable")

    try:
        # Cria um novo resolver para cada requisição (cache é limpo naturalmente)
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 2
        resolver.lifetime = 3
        # Usa DNS do sistema ou /etc/resolv.conf (sem cache global)

        qtype = type.upper()
        answer = resolver.resolve(name, qtype)

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
                    "name": name,
                    "type": dns.rdatatype.from_text(qtype),
                    "TTL": r.ttl,
                    "data": r.to_text()
                } for r in answer
            ]
        }
        return JSONResponse(content=result)
    except dns.resolver.NoAnswer:
        return JSONResponse(
            content={
                "Status": 3,
                "Question": [{"name": name, "type": dns.rdatatype.from_text(type)}]
            }
        )
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/")
async def root():
    return {"status": "DNS over HTTPS server is running"}

# Iniciar com:
# uvicorn app:app --host 0.0.0.0 --port 8000 --reload
