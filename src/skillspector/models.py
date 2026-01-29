"""
Data models for SkillSpector scan results and findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Severity levels for security issues."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Recommendation(str, Enum):
    """Installation recommendations based on risk assessment."""
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DO_NOT_INSTALL = "DO_NOT_INSTALL"


class PatternCategory(str, Enum):
    """Categories of vulnerability patterns."""
    PROMPT_INJECTION = "Prompt Injection"
    DATA_EXFILTRATION = "Data Exfiltration"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    SUPPLY_CHAIN = "Supply Chain"


@dataclass
class Location:
    """Location of a finding within a file."""
    file: str
    start_line: int
    end_line: Optional[int] = None

    def __str__(self) -> str:
        if self.end_line and self.end_line != self.start_line:
            return f"{self.file}:{self.start_line}-{self.end_line}"
        return f"{self.file}:{self.start_line}"


@dataclass
class SecurityIssue:
    """A security issue found during scanning."""
    id: str  # Pattern ID (e.g., "P1", "E2")
    category: PatternCategory
    pattern: str  # Pattern name (e.g., "Instruction Override")
    severity: Severity
    location: Location
    finding: str  # Brief description of what was found
    explanation: str  # Detailed explanation of why it's dangerous
    confidence: float = 1.0  # 0.0 to 1.0
    code_snippet: Optional[str] = None
    intent: Optional[str] = None  # "malicious", "negligent", "benign"


@dataclass
class Component:
    """A component (file) within a skill."""
    path: str
    type: str  # "markdown", "python", "shell", "json", "yaml", "other"
    lines: int
    executable: bool = False
    size_bytes: int = 0


@dataclass
class RiskAssessment:
    """Overall risk assessment for a skill."""
    score: int  # 0-100
    severity: Severity
    recommendation: Recommendation

    @classmethod
    def from_score(cls, score: int) -> "RiskAssessment":
        """Create a RiskAssessment from a numeric score."""
        score = min(100, max(0, score))

        if score <= 20:
            severity = Severity.LOW
            recommendation = Recommendation.SAFE
        elif score <= 50:
            severity = Severity.MEDIUM
            recommendation = Recommendation.CAUTION
        elif score <= 80:
            severity = Severity.HIGH
            recommendation = Recommendation.DO_NOT_INSTALL
        else:
            severity = Severity.CRITICAL
            recommendation = Recommendation.DO_NOT_INSTALL

        return cls(score=score, severity=severity, recommendation=recommendation)


@dataclass
class SkillMetadata:
    """Metadata extracted from a skill's SKILL.md file."""
    name: Optional[str] = None
    description: Optional[str] = None
    triggers: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result for a skill."""
    skill_name: str
    source: str  # Original input (URL, path, etc.)
    scanned_at: datetime
    metadata: SkillMetadata
    components: list[Component]
    issues: list[SecurityIssue]
    risk_assessment: RiskAssessment
    has_executable_scripts: bool = False
    scan_duration_ms: int = 0
    llm_used: bool = False

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)


@dataclass
class StaticFinding:
    """A finding from static analysis (before LLM evaluation)."""
    pattern_id: str
    pattern_name: str
    category: PatternCategory
    severity: Severity
    location: Location
    matched_text: str
    context: str  # Surrounding code/text for LLM evaluation
    confidence: float = 0.5  # Initial confidence before LLM
