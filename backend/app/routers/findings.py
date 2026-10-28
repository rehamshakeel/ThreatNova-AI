"""Findings and evidence management API endpoints."""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.investigation import FindingDB, InvestigationDB
from app.schemas.investigation import EvidenceSchema, FindingSchema, Severity

router = APIRouter(prefix="/api/findings", tags=["Findings & Evidence"])


@router.get("", response_model=List[FindingSchema])
def list_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    category: Optional[str] = Query(None, description="Filter by category"),
    investigation_id: Optional[str] = Query(None, description="Filter by parent investigation ID"),
    q: Optional[str] = Query(None, description="Search query in title or description"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieve structured forensic evidence observations persisted in SQLite."""
    query = db.query(FindingDB)

    if severity and severity.lower() != "all":
        query = query.filter(FindingDB.severity == severity.lower())
    if category and category.lower() != "all":
        query = query.filter(FindingDB.category == category)
    if investigation_id:
        query = query.filter(FindingDB.investigation_id == investigation_id)
    if q and q.strip():
        term = f"%{q.strip().lower()}%"
        query = query.filter(
            (FindingDB.title.ilike(term)) | (FindingDB.description.ilike(term))
        )

    rows = query.order_by(FindingDB.timestamp.desc()).offset(offset).limit(limit).all()

    results: List[FindingSchema] = []
    for f in rows:
        ev_list: List[EvidenceSchema] = []
        for ev in (f.evidence or []):
            if isinstance(ev, dict):
                ev_list.append(EvidenceSchema(**ev))
        
        results.append(
            FindingSchema(
                id=f.id,
                title=f.title,
                severity=Severity(f.severity) if f.severity in Severity._value2member_map_ else Severity.INFO,
                category=f.category,
                description=f.description,
                evidence=ev_list,
                timestamp=f.timestamp.isoformat() if f.timestamp else datetime.now(timezone.utc).isoformat(),
                source=f.source,
                confidence=f.confidence or 75,
                relatedIndicators=f.related_indicators or [],
            )
        )
    return results


@router.get("/{finding_id}", response_model=FindingSchema)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Retrieve single forensic finding by ID."""
    f = db.query(FindingDB).filter(FindingDB.id == finding_id).first()
    if not f:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )

    ev_list: List[EvidenceSchema] = []
    for ev in (f.evidence or []):
        if isinstance(ev, dict):
            ev_list.append(EvidenceSchema(**ev))

    return FindingSchema(
        id=f.id,
        title=f.title,
        severity=Severity(f.severity) if f.severity in Severity._value2member_map_ else Severity.INFO,
        category=f.category,
        description=f.description,
        evidence=ev_list,
        timestamp=f.timestamp.isoformat() if f.timestamp else datetime.now(timezone.utc).isoformat(),
        source=f.source,
        confidence=f.confidence or 75,
        relatedIndicators=f.related_indicators or [],
    )
