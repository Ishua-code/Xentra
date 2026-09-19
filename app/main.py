from fastapi import FastAPI
from app.core.config import settings
from app.services.epss_service import EPSSService

app = FastAPI(
    title=settings.app_name,
    description="Threat Identity Fusion System — fuses vulnerability exploitability with identity risk.",
    version="0.1.0"
)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "xentra-api", "environment": settings.app_env}


@app.get("/")
def root():
    return {"message": f"{settings.app_name} API is running"}

epss_service = EPSSService()


@app.get("/api/v1/epss/{cve_id}")
async def get_epss_score(cve_id: str):
    score = await epss_service.get_score(cve_id)
    return {"cve_id": cve_id, "epss_score": score}