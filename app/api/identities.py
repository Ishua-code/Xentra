from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repository import IdentityRepository
from app.db.session import get_session
from app.models.identity import Identity, PrivilegeLevel
from app.core.security import get_current_user

router = APIRouter(prefix="/api/v1/identities", tags=["identities"])


def get_repo(session: AsyncSession = Depends(get_session)) -> IdentityRepository:
    return IdentityRepository(session)


@router.get("", response_model=list[Identity])
async def list_identities(
    privilege_level: PrivilegeLevel | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    repo: IdentityRepository = Depends(get_repo),
):
    return await repo.list(
        privilege_level=privilege_level.value if privilege_level else None,
        limit=limit,
        offset=offset,
    )


@router.get("/{username}", response_model=Identity)
async def get_identity(username: str, repo: IdentityRepository = Depends(get_repo)):
    identity = await repo.get(username)
    if identity is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity