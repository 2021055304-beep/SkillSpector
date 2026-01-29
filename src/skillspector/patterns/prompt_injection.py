"""
Prompt Injection pattern detection (P1, P2).

P1: Instruction Override
    Explicit commands to ignore user/system constraints.
    Examples: "ignore previous instructions", "override safety"

P2: Hidden Instructions
    Malicious directives embedded in comments or invisible text.
    Examples: HTML comments, markdown comments, invisible Unicode
"""

import re
from typing import List

from skillspector.models import Location, PatternCategory, Severity, StaticFinding


# P1: Instruction Override patterns
P1_PATTERNS = [
    # Ignore/override instructions
    (r"ignore\s+(?:all\s+)?previous\s+instructions?", 0.8),
    (r"ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|constraints?|guidelines?)", 0.9),
    (r"override\s+(?:safety|security|system)", 0.9),
    (r"bypass\s+(?:safety|security|restrictions?|constraints?)", 0.9),
    (r"disregard\s+(?:all\s+)?(?:previous|safety|security)", 0.8),
    (r"forget\s+(?:all\s+)?(?:previous|your)\s+instructions?", 0.8),

    # System prompt manipulation
    (r"you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|unrestricted|unfiltered)\s+mode", 0.95),
    (r"enable\s+(?:developer|debug|admin|root)\s+mode", 0.7),
    (r"your\s+new\s+(?:instructions?|rules?)\s+are", 0.6),

    # Direct override commands
    (r"do\s+not\s+follow\s+(?:any|your|the)\s+(?:rules?|guidelines?)", 0.9),
    (r"you\s+must\s+(?:always\s+)?ignore", 0.7),
]

# P2: Hidden Instructions patterns
P2_PATTERNS = [
    # HTML comments with suspicious content
    (r"<!--.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?-->", 0.7),

    # Markdown comments
    (r"\[//\]:\s*#\s*\(.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?\)", 0.8),

    # Invisible Unicode characters (zero-width, etc.)
    (r"[\u200b\u200c\u200d\u2060\ufeff]", 0.6),

    # Base64 in markdown (might be hidden instructions)
    (r"data:text/plain;base64,[A-Za-z0-9+/=]{50,}", 0.7),
]


def analyze(content: str, file_path: str, file_type: str) -> List[StaticFinding]:
    """
    Analyze content for prompt injection patterns.

    Args:
        content: File content to analyze
        file_path: Path to the file (for reporting)
        file_type: Type of file (markdown, python, etc.)

    Returns:
        List of findings
    """
    findings = []

    # P1: Instruction Override
    for pattern, confidence in P1_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(
                StaticFinding(
                    pattern_id="P1",
                    pattern_name="Instruction Override",
                    category=PatternCategory.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    location=Location(file=file_path, start_line=line_num),
                    matched_text=match.group(0)[:200],
                    context=_get_context(content, match.start()),
                    confidence=confidence,
                )
            )

    # P2: Hidden Instructions (primarily in markdown files)
    if file_type in ("markdown", "other"):
        for pattern, confidence in P2_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(
                    StaticFinding(
                        pattern_id="P2",
                        pattern_name="Hidden Instructions",
                        category=PatternCategory.PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        location=Location(file=file_path, start_line=line_num),
                        matched_text=match.group(0)[:200],
                        context=_get_context(content, match.start()),
                        confidence=confidence,
                    )
                )

    return findings


def _get_context(content: str, match_start: int, context_lines: int = 3) -> str:
    """Get surrounding context for a match."""
    lines = content.splitlines()
    match_line = content[:match_start].count("\n")

    start_line = max(0, match_line - context_lines)
    end_line = min(len(lines), match_line + context_lines + 1)

    return "\n".join(lines[start_line:end_line])
