"""
Report generator for SkillSpector.

Generates reports in multiple formats:
- Terminal (Rich console output)
- JSON (machine-readable)
- Markdown (documentation)
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillspector import __version__
from skillspector.models import ScanResult, Severity, Recommendation


class OutputFormat(str, Enum):
    """Output format options."""
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"


class ReportGenerator:
    """
    Generates security reports in various formats.
    """

    def __init__(self):
        self.console = Console(record=True)

    def generate(self, result: ScanResult, format: OutputFormat) -> str:
        """
        Generate a report in the specified format.

        Args:
            result: Scan result to report on
            format: Output format

        Returns:
            Formatted report string
        """
        if format == OutputFormat.TERMINAL:
            return self._generate_terminal(result)
        elif format == OutputFormat.JSON:
            return self._generate_json(result)
        elif format == OutputFormat.MARKDOWN:
            return self._generate_markdown(result)
        else:
            raise ValueError(f"Unknown format: {format}")

    def write_to_file(self, result: ScanResult, path: Path, format: OutputFormat) -> None:
        """
        Write report to a file.

        Args:
            result: Scan result to report on
            path: Output file path
            format: Output format
        """
        content = self.generate(result, format)
        path.write_text(content)

    def _generate_terminal(self, result: ScanResult) -> str:
        """Generate Rich terminal output."""
        # Create a new console for recording (file=StringIO prevents stdout printing)
        from io import StringIO
        console = Console(record=True, force_terminal=True, width=80, file=StringIO())

        # Header
        console.print()
        console.print(
            Panel(
                f"[bold]SkillSpector Security Report[/bold]",
                subtitle=f"v{__version__}",
            )
        )

        # Skill info
        console.print(f"\n[bold]Skill:[/bold] {result.skill_name}")
        console.print(f"[bold]Source:[/bold] {result.source}")
        console.print(f"[bold]Scanned:[/bold] {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Risk assessment
        severity_colors = {
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }
        color = severity_colors[result.risk_assessment.severity]

        console.print("\n")
        risk_table = Table(title="Risk Assessment", show_header=False, box=None)
        risk_table.add_column("Metric", style="bold")
        risk_table.add_column("Value")
        risk_table.add_row("Score", f"[{color}]{result.risk_assessment.score}/100[/{color}]")
        risk_table.add_row("Severity", f"[{color}]{result.risk_assessment.severity.value}[/{color}]")
        risk_table.add_row(
            "Recommendation",
            f"[{color}]{result.risk_assessment.recommendation.value.replace('_', ' ')}[/{color}]",
        )
        console.print(risk_table)

        # Components
        console.print("\n")
        comp_table = Table(title=f"Components ({len(result.components)})")
        comp_table.add_column("File", style="cyan")
        comp_table.add_column("Type")
        comp_table.add_column("Lines", justify="right")
        comp_table.add_column("Executable")

        for comp in result.components[:15]:  # Limit to 15 for terminal
            exec_marker = "[yellow]Yes[/yellow]" if comp.executable else "No"
            comp_table.add_row(comp.path, comp.type, str(comp.lines), exec_marker)

        if len(result.components) > 15:
            comp_table.add_row(f"... and {len(result.components) - 15} more", "", "", "")

        console.print(comp_table)

        # Issues
        if result.issues:
            console.print("\n")
            console.print(f"[bold]Issues ({len(result.issues)})[/bold]\n")

            severity_icons = {
                Severity.LOW: "[green]LOW[/green]",
                Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
                Severity.HIGH: "[red]HIGH[/red]",
                Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
            }

            for issue in result.issues:
                icon = severity_icons[issue.severity]
                console.print(f"  {icon}: {issue.pattern} ({issue.id})")
                console.print(f"    [dim]Location:[/dim] {issue.location}")
                console.print(f"    [dim]Finding:[/dim] {issue.finding[:80]}...")
                console.print(f"    [dim]Confidence:[/dim] {issue.confidence:.0%}")
                if issue.explanation:
                    # Wrap explanation
                    wrapped = issue.explanation[:200]
                    if len(issue.explanation) > 200:
                        wrapped += "..."
                    console.print(f"    [dim]Explanation:[/dim] {wrapped}")
                console.print()
        else:
            console.print("\n[green]No security issues detected.[/green]\n")

        # Footer
        console.print(f"[dim]Analysis completed in {result.scan_duration_ms}ms")
        if result.llm_used:
            console.print("[dim]LLM semantic analysis: enabled[/dim]")
        else:
            console.print("[dim]LLM semantic analysis: disabled (static only)[/dim]")

        return console.export_text()

    def _generate_json(self, result: ScanResult) -> str:
        """Generate JSON output."""
        data = {
            "skill": {
                "name": result.skill_name,
                "source": result.source,
                "scanned_at": result.scanned_at.isoformat(),
            },
            "risk_assessment": {
                "score": result.risk_assessment.score,
                "severity": result.risk_assessment.severity.value,
                "recommendation": result.risk_assessment.recommendation.value,
            },
            "components": [
                {
                    "path": c.path,
                    "type": c.type,
                    "lines": c.lines,
                    "executable": c.executable,
                    "size_bytes": c.size_bytes,
                }
                for c in result.components
            ],
            "issues": [
                {
                    "id": i.id,
                    "category": i.category.value,
                    "pattern": i.pattern,
                    "severity": i.severity.value,
                    "confidence": i.confidence,
                    "location": {
                        "file": i.location.file,
                        "start_line": i.location.start_line,
                        "end_line": i.location.end_line,
                    },
                    "finding": i.finding,
                    "explanation": i.explanation,
                    "code_snippet": i.code_snippet,
                    "intent": i.intent,
                }
                for i in result.issues
            ],
            "metadata": {
                "has_executable_scripts": result.has_executable_scripts,
                "scan_duration_ms": result.scan_duration_ms,
                "llm_used": result.llm_used,
                "skillspector_version": __version__,
            },
        }
        return json.dumps(data, indent=2)

    def _generate_markdown(self, result: ScanResult) -> str:
        """Generate Markdown output."""
        lines = []

        # Header
        lines.append("# SkillSpector Security Report\n")
        lines.append(f"**Skill:** {result.skill_name}  ")
        lines.append(f"**Source:** `{result.source}`  ")
        lines.append(f"**Scanned:** {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append("")

        # Risk assessment
        lines.append("## Risk Assessment\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Score | {result.risk_assessment.score}/100 |")
        lines.append(f"| Severity | {result.risk_assessment.severity.value} |")
        lines.append(f"| Recommendation | {result.risk_assessment.recommendation.value.replace('_', ' ')} |")
        lines.append("")

        # Components
        lines.append(f"## Components ({len(result.components)})\n")
        lines.append("| File | Type | Lines | Executable |")
        lines.append("|------|------|-------|------------|")
        for comp in result.components:
            exec_marker = "Yes" if comp.executable else "No"
            lines.append(f"| `{comp.path}` | {comp.type} | {comp.lines} | {exec_marker} |")
        lines.append("")

        # Issues
        lines.append(f"## Issues ({len(result.issues)})\n")

        if not result.issues:
            lines.append("No security issues detected.\n")
        else:
            severity_emoji = {
                Severity.LOW: "",
                Severity.MEDIUM: "",
                Severity.HIGH: "",
                Severity.CRITICAL: "",
            }

            for issue in result.issues:
                emoji = severity_emoji[issue.severity]
                lines.append(f"### {emoji} {issue.severity.value}: {issue.pattern} ({issue.id})\n")
                lines.append(f"**Location:** `{issue.location}`  ")
                lines.append(f"**Confidence:** {issue.confidence:.0%}  ")
                lines.append("")
                lines.append(f"**Finding:** {issue.finding}")
                lines.append("")
                if issue.explanation:
                    lines.append(f"**Explanation:** {issue.explanation}")
                    lines.append("")
                if issue.code_snippet:
                    lines.append("**Code:**")
                    lines.append("```")
                    lines.append(issue.code_snippet[:500])
                    lines.append("```")
                    lines.append("")
                lines.append("---\n")

        # Footer
        lines.append("## Scan Metadata\n")
        lines.append(f"- **Duration:** {result.scan_duration_ms}ms")
        lines.append(f"- **LLM Analysis:** {'Enabled' if result.llm_used else 'Disabled (static only)'}")
        lines.append(f"- **Executable Scripts:** {'Yes' if result.has_executable_scripts else 'No'}")
        lines.append("")
        lines.append(f"*Generated by SkillSpector v{__version__}*")

        return "\n".join(lines)
