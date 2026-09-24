import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ticket import Ticket

from app.db.models import FindingRow, IdentityRow, TicketRow
from app.models.finding import UnifiedFinding
from app.models.identity import Identity

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


def _now() -> datetime:
    # naive UTC, matching the DateTime columns
    return datetime.now(timezone.utc).replace(tzinfo=None)


class FindingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_many(self, findings: Sequence[UnifiedFinding]) -> None:
        if not findings:
            return
        rows = []
        for f in findings:
            data = f.model_dump(mode="json")
            rows.append(FindingRow(id=str(uuid.uuid4()), created_at=_now(), **data))
        self.session.add_all(rows)
        await self.session.commit()

    async def list(
        self,
        cve_id: str | None = None,
        owner: str | None = None,
        min_score: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[UnifiedFinding]:
        stmt = select(FindingRow)
        if cve_id:
            stmt = stmt.where(FindingRow.cve_id == cve_id)
        if owner:
            stmt = stmt.where(FindingRow.owner == owner)
        if min_score is not None:
            stmt = stmt.where(FindingRow.unified_risk_score >= min_score)
        stmt = (
            stmt.order_by(FindingRow.unified_risk_score.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return [_to_finding(r) for r in result.scalars().all()]


def _to_finding(row: FindingRow) -> UnifiedFinding:
    data = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    data.pop("id")
    data.pop("created_at")
    return UnifiedFinding(**data)


class IdentityRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_many(self, identities: Sequence[Identity]) -> None:
        if not identities:
            return
        for i in identities:
            data = i.model_dump(mode="json")  # privilege_level -> plain string
            await self.session.merge(IdentityRow(updated_at=_now(), **data))
        await self.session.commit()

    async def list(
        self, privilege_level: str | None = None, limit: int = 50, offset: int = 0
    ) -> list[Identity]:
        stmt = select(IdentityRow)
        if privilege_level:
            stmt = stmt.where(IdentityRow.privilege_level == privilege_level)
        stmt = stmt.order_by(IdentityRow.username).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return [_to_identity(r) for r in result.scalars().all()]

    async def get(self, username: str) -> Identity | None:
        row = await self.session.get(IdentityRow, username)
        return _to_identity(row) if row else None


def _to_identity(row: IdentityRow) -> Identity:
    return Identity(
        username=row.username,
        privilege_level=row.privilege_level,
        mfa_enabled=row.mfa_enabled,
        last_login_days_ago=row.last_login_days_ago,
        owned_asset_ip=row.owned_asset_ip,
    )