from sqlalchemy import Column, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class IncidentRow(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    type = Column(String, nullable=False)
    status = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    first_seen = Column(String, nullable=False)
    last_seen = Column(String, nullable=False)
    data = Column(Text, nullable=False)  # full IncidentNew serialized as JSON


class AuditEventRow(Base):
    __tablename__ = "incident_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)
    user = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    before_status = Column(String, nullable=True)
    after_status = Column(String, nullable=True)
    assignee = Column(String, nullable=True)
    detail = Column(Text, nullable=True)  # JSON object


class MetricRow(Base):
    __tablename__ = "metrics"

    key = Column(String, primary_key=True)
    value = Column(Text, nullable=False)  # JSON-encoded counter blob


class EntityRiskRow(Base):
    __tablename__ = "entity_risk"

    entity_type = Column(String, primary_key=True)
    entity_id = Column(String, primary_key=True)
    score = Column(Float, nullable=False)
    last_updated = Column(String, nullable=False)  # ISO 8601 UTC
