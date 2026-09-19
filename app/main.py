from fastapi import FastAPI

app = FastAPI(
    title="XENTRA",
    description="Threat Identity Fusion System — fuses vulnerability exploitability with identity risk.",
    version="0.1.0"
)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "xentra-api"}


@app.get("/")
def root():
    return {"message": "XENTRA API is running"}