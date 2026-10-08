from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class AccessRequestModel(Base):
    __tablename__ = "access_requests"

    request_id = Column(String, primary_key=True)
    wallet = Column(String, index=True)
    resource_id = Column(String)
    action = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class IncidentModel(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    vector = Column(JSON, nullable=False)
    category = Column(String)
    disposition = Column(String) # CONFIRMED_INCIDENT or SIMULATED_ATTACK
    source = Column(JSON)  # wallet, source case, simulation label and vector version
    evidence_hash = Column(String)
    confirmed_by = Column(String)
    confirmed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String)
    event_type = Column(String)
    object_id = Column(String)
    payload_hash = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
