"""SQLAlchemy models for investigations, findings, evidence, and correlation."""

import json
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.database import Base


class InvestigationDB(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)
    query = Column(String(512), nullable=False, index=True)
    type = Column(String(32), nullable=False, index=True)
    status = Column(String(32), default="complete", nullable=False)

    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=True)

    # Risk Assessment
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(32), default="low", nullable=False)
    risk_confidence = Column(Integer, default=50, nullable=False)
    risk_explanation = Column(Text, default="", nullable=False)
    _risk_factors = Column("risk_factors", Text, default="[]", nullable=False)

    # Serialized telemetry and intelligence
    _domain_intel = Column("domain_intel", Text, default="{}", nullable=False)
    _graph_nodes = Column("graph_nodes", Text, default="[]", nullable=False)
    _graph_links = Column("graph_links", Text, default="[]", nullable=False)

    # AI Analysis & Summaries
    ai_summary = Column(Text, nullable=True)
    _ai_recommendations = Column("ai_recommendations", Text, default="[]", nullable=True)
    _ai_analysis = Column("ai_analysis", Text, default="{}", nullable=True)

    # Flag indicating whether demo data / fallback fixtures were utilized
    is_demo = Column(Boolean, default=False, nullable=False)

    # Relationships
    findings = relationship(
        "FindingDB",
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="FindingDB.timestamp.desc()",
    )

    # JSON getter / setter properties for transparent serialization
    @property
    def risk_factors(self):
        try:
            return json.loads(self._risk_factors or "[]")
        except Exception:
            return []

    @risk_factors.setter
    def risk_factors(self, value):
        self._risk_factors = json.dumps(value or [])

    @property
    def domain_intel(self):
        try:
            return json.loads(self._domain_intel or "{}")
        except Exception:
            return {}

    @domain_intel.setter
    def domain_intel(self, value):
        self._domain_intel = json.dumps(value or {})

    @property
    def graph_nodes(self):
        try:
            return json.loads(self._graph_nodes or "[]")
        except Exception:
            return []

    @graph_nodes.setter
    def graph_nodes(self, value):
        self._graph_nodes = json.dumps(value or [])

    @property
    def graph_links(self):
        try:
            return json.loads(self._graph_links or "[]")
        except Exception:
            return []

    @graph_links.setter
    def graph_links(self, value):
        self._graph_links = json.dumps(value or [])

    @property
    def ai_recommendations(self):
        try:
            return json.loads(self._ai_recommendations or "[]")
        except Exception:
            return []

    @ai_recommendations.setter
    def ai_recommendations(self, value):
        self._ai_recommendations = json.dumps(value or [])

    @property
    def ai_analysis(self):
        try:
            return json.loads(self._ai_analysis or "{}")
        except Exception:
            return {}

    @ai_analysis.setter
    def ai_analysis(self, value):
        self._ai_analysis = json.dumps(value or {})


class FindingDB(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(
        String(64),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    title = Column(String(256), nullable=False)
    severity = Column(String(32), default="medium", nullable=False)
    category = Column(String(128), default="General", nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(128), default="Threat Intelligence", nullable=False)
    confidence = Column(Integer, default=70, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    _evidence = Column("evidence", Text, default="[]", nullable=False)
    _related_indicators = Column("related_indicators", Text, default="[]", nullable=True)

    investigation = relationship("InvestigationDB", back_populates="findings")

    @property
    def evidence(self):
        try:
            return json.loads(self._evidence or "[]")
        except Exception:
            return []

    @evidence.setter
    def evidence(self, value):
        self._evidence = json.dumps(value or [])

    @property
    def related_indicators(self):
        try:
            return json.loads(self._related_indicators or "[]")
        except Exception:
            return []

    @related_indicators.setter
    def related_indicators(self, value):
        self._related_indicators = json.dumps(value or [])
