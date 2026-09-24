from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import TicketRow
from app.models.ticket import Ticket


def _to_row(ticket: Ticket) -> TicketRow:
    data = ticket.model_dump(mode="json")
    data["created_at"] = datetime.fromisoformat(ticket.created_at)
    data["attack_path"] = ticket.attack_path or []
    return TicketRow(**data)


def _to_ticket(row: TicketRow) -> Ticket:
    data = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    data["created_at"] = row.created_at.isoformat()
    return Ticket(**data)


class TicketRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_many(self, tickets: Sequence[Ticket]) -> None:
        if not tickets:
            return
        self.session.add_all([_to_row(t) for t in tickets])
        await self.session.commit()

    async def list(
        self,
        status: str | None = None,
        severity: str | None = None,
        owner: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Ticket]:
        stmt = select(TicketRow)
        if status:
            stmt = stmt.where(TicketRow.status == status)
        if severity:
            stmt = stmt.where(TicketRow.severity == severity)
        if owner:
            stmt = stmt.where(TicketRow.owner == owner)
        stmt = stmt.order_by(TicketRow.created_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return [_to_ticket(r) for r in result.scalars().all()]

    async def get(self, ticket_id: str) -> Ticket | None:
        row = await self.session.get(TicketRow, ticket_id)
        return _to_ticket(row) if row else None

    async def update_status(self, ticket_id: str, status: str) -> Ticket | None:
        row = await self.session.get(TicketRow, ticket_id)
        if row is None:
            return None
        row.status = status
        await self.session.commit()
        await self.session.refresh(row)
        return _to_ticket(row)