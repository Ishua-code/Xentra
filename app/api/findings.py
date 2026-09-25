from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repository import FindingRepository
from app.db.session import get_session
from app.models.finding import UnifiedFinding
from app.core.security import get_current_user

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def get_repo(session: AsyncSession = Depends(get_session)) -> FindingRepository:
    return FindingRepository(session)


@router.get("", response_model=list[UnifiedFinding])
async def list_findings(
    cve_id: str | None = None,
    owner: str | None = None,
    min_score: float | None = Query(None, ge=0, le=1),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    repo: FindingRepository = Depends(get_repo),
):
    return await repo.list(
        cve_id=cve_id,
        owner=owner,
        min_score=min_score,
        limit=limit,
        offset=offset,
    )