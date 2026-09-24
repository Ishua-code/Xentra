from fastapi import FastAPI
from app.core.config import settings
from app.services.epss_service import EPSSService
from app.models.identity import Identity
from app.services.identity_service import IdentityService
from app.services.graph_service import GraphRiskService
from app.services.ticket_service import TicketService
from pydantic import BaseModel
from app.models.vulnerability import Vulnerability
from app.services.correlation_service import CorrelationService
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.tickets import router as tickets_router
from app.db.repository import TicketRepository
from app.db.session import get_session
from app.db.repository import FindingRepository, IdentityRepository, TicketRepository

app = FastAPI(
    title=settings.app_name,
    description="Threat Identity Fusion System — fuses vulnerability exploitability with identity risk.",
    version="0.1.0"
)
app.include_router(tickets_router)


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


identity_service = IdentityService()


@app.post("/api/v1/identity/score")
def score_identity(identity: Identity):
    score = identity_service.calculate_score(identity)
    return {"username": identity.username, "identity_exposure_score": score}

graph_service = GraphRiskService()


@app.post("/api/v1/graph/analyze")
def analyze_graph(identities: list[Identity]):
    return graph_service.analyze(identities)

ticket_service = TicketService()
class CorrelationRequest(BaseModel):
    vulnerabilities: list[Vulnerability]
    identities: list[Identity]


correlation_service = CorrelationService()

@app.post("/api/v1/correlate")
async def correlate(
    request: CorrelationRequest,
    session: AsyncSession = Depends(get_session),
):
    findings = await correlation_service.correlate(request.vulnerabilities, request.identities)
    tickets = ticket_service.generate_tickets(findings)

    await IdentityRepository(session).upsert_many(request.identities)
    await FindingRepository(session).save_many(findings)
    await TicketRepository(session).save_many(tickets)

    return {"findings": findings, "tickets": tickets}