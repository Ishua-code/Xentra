from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repository import TicketRepository
from app.db.session import get_session
from app.models.ticket import Severity, Ticket, TicketStatus
from app.core.security import get_current_user

router = APIRouter(
    prefix="/api/v1/tickets",
    tags=["tickets"],
    dependencies=[Depends(get_current_user)],
)


class StatusUpdate(BaseModel):
    status: TicketStatus


def get_repo(session: AsyncSession = Depends(get_session)) -> TicketRepository:
    return TicketRepository(session)


@router.get("", response_model=list[Ticket])
async def list_tickets(
    status: TicketStatus | None = None,
    severity: Severity | None = None,
    owner: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    repo: TicketRepository = Depends(get_repo),
):
    return await repo.list(
        status=status.value if status else None,
        severity=severity.value if severity else None,
        owner=owner,
        limit=limit,
        offset=offset,
    )


@router.get("/{ticket_id}", response_model=Ticket)
async def get_ticket(ticket_id: str, repo: TicketRepository = Depends(get_repo)):
    ticket = await repo.get(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@router.patch("/{ticket_id}/status", response_model=Ticket)
async def update_ticket_status(
    ticket_id: str,
    body: StatusUpdate,
    repo: TicketRepository = Depends(get_repo),
):
    ticket = await repo.update_status(ticket_id, body.status.value)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket