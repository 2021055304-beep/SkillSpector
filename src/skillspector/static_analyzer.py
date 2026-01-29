"""
Static analyzer for SkillSpector.

Performs regex-based pattern matching to detect potential vulnerabilities.
This is stage 1 of the detection pipeline - high recall, moderate precision.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from skillspector.models import (
    Component,
    Location,
    PatternCategory,
    Severity,
    StaticFinding,
)
from skillspector.patterns import (
    prompt_injection,
    data_exfiltration,
    privilege_escalation,
    supply_chain,
    harmful_content,
)


class StaticAnalyzer:
    """
    Static analysis engine using regex pattern matching.

    Scans all files in a skill directory for known vulnerability patterns.
    """

    def __init__(self):
        """Initialize the static analyzer with all pattern modules."""
        self.pattern_modules = [
            prompt_injection,
            data_exfiltration,
            privilege_escalation,
            supply_chain,
            harmful_content,
        ]

    def analyze(self, skill_dir: Path, components: list[Component]) -> list[StaticFinding]:
        """
        Analyze all components for security patterns.

        Args:
            skill_dir: Path to the skill directory
            components: List of components to analyze

        Returns:
            List of StaticFinding objects
        """
        findings: list[StaticFinding] = []

        for component in components:
            file_path = skill_dir / component.path
            if not file_path.exists():
                continue

            # Read file content
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Skip very large files (> 1MB)
            if len(content) > 1_000_000:
                continue

            # Run all pattern modules
            for module in self.pattern_modules:
                module_findings = module.analyze(
                    content=content,
                    file_path=component.path,
                    file_type=component.type,
                )
                findings.extend(module_findings)

        return findings

    def analyze_file(self, file_path: Path) -> list[StaticFinding]:
        """
        Analyze a single file for security patterns.

        Args:
            file_path: Path to the file

        Returns:
            List of StaticFinding objects
        """
        if not file_path.exists():
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        # Determine file type from extension
        suffix = file_path.suffix.lower()
        file_types = {
            ".md": "markdown",
            ".py": "python",
            ".sh": "shell",
            ".js": "javascript",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
        }
        file_type = file_types.get(suffix, "other")

        findings: list[StaticFinding] = []
        for module in self.pattern_modules:
            module_findings = module.analyze(
                content=content,
                file_path=str(file_path.name),
                file_type=file_type,
            )
            findings.extend(module_findings)

        return findings


def find_line_number(content: str, match_start: int) -> int:
    """Find line number for a match position in content."""
    return content[:match_start].count("\n") + 1


def get_context(content: str, match_start: int, match_end: int, context_lines: int = 3) -> str:
    """Get surrounding context for a match."""
    lines = content.splitlines()
    match_line = content[:match_start].count("\n")

    start_line = max(0, match_line - context_lines)
    end_line = min(len(lines), match_line + context_lines + 1)

    return "\n".join(lines[start_line:end_line])


def create_finding(
    content: str,
    match: re.Match,
    pattern_id: str,
    pattern_name: str,
    category: PatternCategory,
    severity: Severity,
    file_path: str,
    confidence: float = 0.5,
) -> StaticFinding:
    """
    Create a StaticFinding from a regex match.

    Args:
        content: Full file content
        match: Regex match object
        pattern_id: Pattern identifier (e.g., "P1")
        pattern_name: Human-readable pattern name
        category: Vulnerability category
        severity: Severity level
        file_path: Path to the file
        confidence: Initial confidence score

    Returns:
        StaticFinding object
    """
    line_num = find_line_number(content, match.start())
    context = get_context(content, match.start(), match.end())

    # Calculate end line
    matched_text = match.group(0)
    end_line = line_num + matched_text.count("\n")

    return StaticFinding(
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        category=category,
        severity=severity,
        location=Location(file=file_path, start_line=line_num, end_line=end_line),
        matched_text=matched_text[:200],  # Truncate long matches
        context=context,
        confidence=confidence,
    )
