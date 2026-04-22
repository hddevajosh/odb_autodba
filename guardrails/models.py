from __future__ import annotations

from pydantic import BaseModel, Field
from odb_autodba.models.schemas import GuardrailCheckResult


class PolicyViolation(BaseModel):
    rule: str
    message: str


class ExecutionContext(BaseModel):
    confirmed: bool = False
    username: str | None = None


class ActionDecision(BaseModel):
    allowed: bool
    violations: list[PolicyViolation] = Field(default_factory=list)
    checks: list[GuardrailCheckResult] = Field(default_factory=list)
    rationale: str = ""
