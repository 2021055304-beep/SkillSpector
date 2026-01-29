"""
Pattern detection modules for SkillSpector.

Each module contains regex patterns and analysis logic for a specific
category of vulnerabilities.

Categories:
- Prompt Injection (P1, P2, P5)
- Data Exfiltration (E1, E2)
- Privilege Escalation (PE3)
- Supply Chain (SC2, SC3)
"""

from skillspector.patterns import (
    prompt_injection,
    data_exfiltration,
    privilege_escalation,
    supply_chain,
    harmful_content,
)

__all__ = [
    "prompt_injection",
    "data_exfiltration",
    "privilege_escalation",
    "supply_chain",
    "harmful_content",
]
