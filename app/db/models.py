from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String


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



class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    host: Mapped[str] = mapped_column(String(64))
    owner: Mapped[str] = mapped_column(String(128), index=True)
    epss_score: Mapped[float] = mapped_column(Float)
    identity_exposure_score: Mapped[float] = mapped_column(Float)
    graph_proximity_score: Mapped[float] = mapped_column(Float)
    betweenness_centrality: Mapped[float] = mapped_column(Float)
    unified_risk_score: Mapped[float] = mapped_column(Float, index=True)
    hops_to_domain_admin: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attack_path: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class IdentityRow(Base):
    __tablename__ = "identities"

    username: Mapped[str] = mapped_column(String(128), primary_key=True)
    privilege_level: Mapped[str] = mapped_column(String(32), index=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean)
    last_login_days_ago: Mapped[int] = mapped_column(Integer)
    owned_asset_ip: Mapped[str] = mapped_column(String(64), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime)