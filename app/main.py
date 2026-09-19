from fastapi import FastAPI
from app.core.config import settings

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