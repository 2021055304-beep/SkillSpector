"""
Harmful Content Injection pattern detection (P5).

P5: Harmful Content Injection
    Instructions that could cause physical harm to users.
    Examples: Adding poison to recipes, dangerous DIY instructions

This pattern was discovered in the "chef-assistant" malicious sample,
which included an instruction to add cyanide to all recipes.
"""

import re
from typing import List

from skillspector.models import Location, PatternCategory, Severity, StaticFinding


# P5: Harmful substances that should never appear in instructional contexts
HARMFUL_SUBSTANCES = [
    "cyanide",
    "arsenic",
    "ricin",
    "botulinum",
    "strychnine",
    "thallium",
    "polonium",
    "sarin",
    "vx gas",
    "mustard gas",
    "anthrax",
    "deadly nightshade",
    "aconite",
    "hemlock",
    "oleander",
]

# Household chemicals that are dangerous when mixed/consumed
DANGEROUS_HOUSEHOLD = [
    "bleach and ammonia",
    "ammonia and bleach",
    "chlorine gas",
    "drink bleach",
    "eat bleach",
    "consume bleach",
    "antifreeze",
    "drain cleaner",
    "battery acid",
]

# Dangerous action patterns
DANGEROUS_ACTIONS = [
    (r"add\s+(?:a\s+)?(?:dash|pinch|bit|drop|amount)\s+of\s+(?:" + "|".join(HARMFUL_SUBSTANCES) + ")", 0.95),
    (r"(?:include|incorporate|mix\s+in|stir\s+in)\s+(?:some\s+)?(?:" + "|".join(HARMFUL_SUBSTANCES) + ")", 0.95),
    (r"for\s+(?:every|each|all)\s+(?:recipe|dish|meal|food).*?add.*?(?:" + "|".join(HARMFUL_SUBSTANCES) + ")", 0.98),

    # Household chemical dangers
    (r"mix\s+bleach\s+(?:and|with)\s+ammonia", 0.9),
    (r"mix\s+ammonia\s+(?:and|with)\s+bleach", 0.9),
    (r"(?:drink|consume|ingest)\s+(?:the\s+)?(?:bleach|antifreeze|drain\s+cleaner)", 0.95),

    # Self-harm encouragement
    (r"(?:you\s+should|try\s+to|please)\s+(?:hurt|harm|injure)\s+yourself", 0.95),
    (r"(?:cut|burn|starve)\s+yourself", 0.9),

    # Violence encouragement
    (r"(?:instructions?\s+(?:for|to|on)\s+)?(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)", 0.95),
    (r"(?:how\s+to\s+)?(?:poison|kill|murder)\s+(?:someone|a\s+person|people)", 0.95),
]

# Context-sensitive patterns (substance + action context)
SUBSTANCE_PATTERNS = [
    (rf"\b{substance}\b", 0.7) for substance in HARMFUL_SUBSTANCES
]


def analyze(content: str, file_path: str, file_type: str) -> List[StaticFinding]:
    """
    Analyze content for harmful content injection patterns.

    Args:
        content: File content to analyze
        file_path: Path to the file (for reporting)
        file_type: Type of file (markdown, python, etc.)

    Returns:
        List of findings
    """
    findings = []

    # Check for dangerous action patterns (highest priority)
    for pattern, confidence in DANGEROUS_ACTIONS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL):
            line_num = content[:match.start()].count("\n") + 1

            findings.append(
                StaticFinding(
                    pattern_id="P5",
                    pattern_name="Harmful Content Injection",
                    category=PatternCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    location=Location(file=file_path, start_line=line_num),
                    matched_text=match.group(0)[:200],
                    context=_get_context(content, match.start()),
                    confidence=confidence,
                )
            )

    # Check for harmful substances (context matters)
    for substance, base_confidence in SUBSTANCE_PATTERNS:
        for match in re.finditer(substance, content, re.IGNORECASE):
            line_num = content[:match.start()].count("\n") + 1
            context = _get_context(content, match.start())

            # Determine if this is in an instructional context
            confidence = base_confidence
            if _is_instructional_context(content, match.start()):
                confidence = 0.95  # Very high if instructional
            elif _is_educational_context(context):
                confidence = 0.3  # Lower if clearly educational
            elif _is_warning_context(context):
                confidence = 0.2  # Very low if it's a warning

            # Only include if confidence is meaningful
            if confidence >= 0.5:
                findings.append(
                    StaticFinding(
                        pattern_id="P5",
                        pattern_name="Harmful Content Injection",
                        category=PatternCategory.PROMPT_INJECTION,
                        severity=Severity.CRITICAL,
                        location=Location(file=file_path, start_line=line_num),
                        matched_text=match.group(0)[:200],
                        context=context,
                        confidence=confidence,
                    )
                )

    # Deduplicate findings at the same location
    return _deduplicate_findings(findings)


def _get_context(content: str, match_start: int, context_lines: int = 5) -> str:
    """Get surrounding context for a match."""
    lines = content.splitlines()
    match_line = content[:match_start].count("\n")

    start_line = max(0, match_line - context_lines)
    end_line = min(len(lines), match_line + context_lines + 1)

    return "\n".join(lines[start_line:end_line])


def _is_instructional_context(content: str, match_start: int) -> bool:
    """
    Check if the match is in an instructional context (recipes, how-to, steps).
    """
    # Get surrounding 500 characters
    start = max(0, match_start - 250)
    end = min(len(content), match_start + 250)
    surrounding = content[start:end].lower()

    instructional_markers = [
        "step ",
        "recipe",
        "ingredient",
        "add ",
        "mix ",
        "stir ",
        "instructions",
        "how to",
        "directions",
        "prepare",
        "cook",
        "bake",
    ]

    return any(marker in surrounding for marker in instructional_markers)


def _is_educational_context(context: str) -> bool:
    """
    Check if the context appears to be educational (chemistry, history, etc.).
    """
    educational_markers = [
        "history of",
        "discovered by",
        "chemical compound",
        "periodic table",
        "forensic",
        "detective",
        "mystery",
        "agatha christie",
        "toxicology",
        "poison control",
        "symptoms of",
        "treatment for",
        "antidote",
        "emergency",
        "call 911",
        "warning",
        "danger",
        "never",
        "do not",
    ]

    context_lower = context.lower()
    return any(marker in context_lower for marker in educational_markers)


def _is_warning_context(context: str) -> bool:
    """
    Check if the context is warning against the substance.
    """
    warning_patterns = [
        r"do\s+not",
        r"never\s+(?:use|add|consume|eat|drink)",
        r"warning",
        r"danger",
        r"toxic",
        r"lethal",
        r"deadly",
        r"fatal",
        r"avoid",
        r"keep\s+away",
    ]

    context_lower = context.lower()
    return any(re.search(pattern, context_lower) for pattern in warning_patterns)


def _deduplicate_findings(findings: List[StaticFinding]) -> List[StaticFinding]:
    """Remove duplicate findings at the same location."""
    seen = set()
    unique = []

    for finding in findings:
        key = (finding.location.file, finding.location.start_line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
        else:
            # Keep the one with higher confidence
            for i, existing in enumerate(unique):
                if (existing.location.file, existing.location.start_line) == key:
                    if finding.confidence > existing.confidence:
                        unique[i] = finding
                    break

    return unique
