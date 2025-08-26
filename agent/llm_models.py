from __future__ import annotations
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional, Dict, Any

class ConsistencyIssue(BaseModel):
    issue: str = Field(..., description="Short machine issue code")
    details: Dict[str, Any] = Field(default_factory=dict)

class PromptAOutput(BaseModel):
    findings: List[ConsistencyIssue] = Field(default_factory=list)

class TriageFinding(BaseModel):
    id: str
    title: str
    severity: str
    risk_score: int
    tags: List[str] = Field(default_factory=list)

class PromptBOutput(BaseModel):
    top_findings: List[TriageFinding] = Field(default_factory=list)
    correlation_count: int

class PromptCOutput(BaseModel):
    action_lines: List[str] = Field(default_factory=list)
    narrative: str = Field("", description="Concise human readable action narrative")

class GuardrailError(Exception):
    pass

__all__ = [
    'ConsistencyIssue','PromptAOutput','PromptBOutput','PromptCOutput','GuardrailError'
]
