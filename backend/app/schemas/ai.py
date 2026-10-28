"""Pydantic schemas for Gemini AI Threat Analyst and Interactive Assistant."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class KeyFindingSchema(BaseModel):
    title: str = Field(..., description="Short descriptive finding title")
    explanation: str = Field(
        ..., description="Plain-language explanation of what was detected, what it means, and why it is dangerous"
    )
    evidence: List[str] = Field(
        default_factory=list, description="Specific forensic evidence strings supporting this conclusion"
    )
    source: str = Field(default="Available source", description="Threat intelligence or telemetry source")
    confidence: str = Field(default="Moderate", description="Confidence level: High, Moderate, Low")
    uncertainty: str = Field(
        default="None noted", description="What is not yet verified or remains ambiguous"
    )


class RecommendedActionSchema(BaseModel):
    priority: str = Field(
        default="Immediate", description="Priority tier: Immediate, Short-term, or Preventive"
    )
    title: str = Field(..., description="Actionable title for the defensive step")
    reason: str = Field(..., description="Why this action matters and expected benefit")
    expected_benefit: Optional[str] = Field(
        default=None, description="Clear expected security improvement"
    )
    steps: List[str] = Field(
        default_factory=list, description="Step-by-step guidance to implement this action safely"
    )
    evidence_refs: List[str] = Field(
        default_factory=list, description="Referenced findings or indicators that triggered this action"
    )


class AIThreatAnalysisResponse(BaseModel):
    investigation_id: str
    language: str = "en"
    executive_summary: str = Field(
        ..., description="2-4 simple sentences summarizing the overall security situation"
    )
    risk_level: str = Field(
        ..., description="Critical, High, Medium, Low, or Unknown"
    )
    risk_score: Optional[int] = Field(
        default=None, description="Calculated deterministic risk score (0-100)"
    )
    confidence: str = Field(
        default="Moderate", description="Confidence level: High, Moderate, or Low"
    )
    risk_classification_explanation: str = Field(
        ..., description="Explanation of why this assigned risk classification is appropriate"
    )
    key_findings: List[KeyFindingSchema] = Field(
        default_factory=list, description="Structured breakdowns of detected threat indicators"
    )
    recommended_actions: List[RecommendedActionSchema] = Field(
        default_factory=list, description="Prioritized defensive actions (Immediate, Short-term, Preventive)"
    )
    safe_practices: List[str] = Field(
        default_factory=list, description="What to do: Safe security practices for users and responders"
    )
    actions_to_avoid: List[str] = Field(
        default_factory=list, description="What to avoid: Risky actions that could worsen exposure"
    )
    false_positive_analysis: str = Field(
        ..., description="When detection may be a false positive, insufficient signals, and verification steps"
    )
    technical_explanation: str = Field(
        ..., description="Advanced technical breakdown for developers, SOC analysts, and cybersecurity students"
    )
    limitations: List[str] = Field(
        default_factory=list, description="Scope limitations, unavailable intelligence, and scanning disclaimers"
    )
    is_ai_generated: bool = False
    model_used: str = "ThreatNova Heuristic Engine"

    model_config = ConfigDict(from_attributes=True)


class AIThreatAnalysisRequest(BaseModel):
    investigation_id: Optional[str] = None
    language: str = "en"  # "en" or "hi"
    investigation_data: Optional[Dict[str, Any]] = None


class ChatMessage(BaseModel):
    role: str = "user"  # "user" or "model" / "assistant"
    content: str


class AIChatRequest(BaseModel):
    investigation_id: Optional[str] = None
    message: str = Field(..., min_length=1, max_length=2000)
    language: str = "en"  # "en" or "hi"
    history: List[ChatMessage] = Field(default_factory=list)
    investigation_data: Optional[Dict[str, Any]] = None


class AIChatResponse(BaseModel):
    investigation_id: str
    response: str
    language: str
    source: str
    is_ai_generated: bool
