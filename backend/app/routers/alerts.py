"""Alerts and early-warning feed API endpoints."""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.investigation import FindingDB, InvestigationDB
from app.schemas.investigation import AlertSchema, Severity

router = APIRouter(prefix="/api/alerts", tags=["Threat Alerts & Early-Warning"])


@router.get("", response_model=List[AlertSchema])
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieve actionable threat alerts derived from persisted SQLite investigations and critical findings."""
    query = (
        db.query(FindingDB, InvestigationDB.query.label("inv_query"))
        .join(InvestigationDB, FindingDB.investigation_id == InvestigationDB.id)
        .filter(FindingDB.severity.in_(["critical", "high"]))
        .order_by(FindingDB.timestamp.desc())
    )

    if severity and severity.lower() != "all":
        query = query.filter(FindingDB.severity == severity.lower())

    rows = query.offset(offset).limit(limit).all()

    alerts: List[AlertSchema] = []
    for f, inv_query in rows:
        alerts.append(
            AlertSchema(
                id=f"alt-{f.id}",
                title=f.title,
                severity=Severity(f.severity) if f.severity in Severity._value2member_map_ else Severity.HIGH,
                indicator=inv_query,
                message=f.description,
                source=f.source,
                timestamp=f.timestamp.isoformat() if f.timestamp else datetime.now(timezone.utc).isoformat(),
                read=False,
                investigationId=f.investigation_id,
            )
        )

    # If critical/high findings alone are few, also include high-risk investigations
    if len(alerts) < 5:
        inv_query_obj = (
            db.query(InvestigationDB)
            .filter((InvestigationDB.risk_level.in_(["critical", "high"])) | (InvestigationDB.risk_score >= 60))
            .order_by(InvestigationDB.started_at.desc())
            .limit(limit)
        )
        for inv in inv_query_obj.all():
            alt_id = f"alt-inv-{inv.id}"
            if not any(a.investigationId == inv.id for a in alerts):
                alerts.append(
                    AlertSchema(
                        id=alt_id,
                        title=f"High Threat Risk Detected: {inv.query}",
                        severity=Severity(inv.risk_level) if inv.risk_level in Severity._value2member_map_ else Severity.HIGH,
                        indicator=inv.query,
                        message=inv.risk_explanation or f"Autonomous investigation flagged risk score {inv.risk_score}/100.",
                        source="Risk Scoring Engine",
                        timestamp=inv.started_at.isoformat() if inv.started_at else datetime.now(timezone.utc).isoformat(),
                        read=False,
                        investigationId=inv.id,
                    )
                )

    return alerts
