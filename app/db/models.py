from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TicketRow(Base):
    __tablename__ = "tickets"

    ticket_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    host: Mapped[str] = mapped_column(String(64))
    owner: Mapped[str] = mapped_column(String(128), index=True)
    epss_score: Mapped[float] = mapped_column(Float)
    identity_exposure_score: Mapped[float] = mapped_column(Float)
    unified_risk_score: Mapped[float] = mapped_column(Float, index=True)
    attack_path: Mapped[list] = mapped_column(JSON)
    hops_to_domain_admin: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recommended_actions: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="Open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)