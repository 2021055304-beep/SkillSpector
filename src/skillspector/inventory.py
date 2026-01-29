"""
Component inventory builder for SkillSpector.

Discovers and catalogs all files within a skill directory,
identifying file types and extracting metadata.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from skillspector.models import Component, SkillMetadata


class InventoryBuilder:
    """
    Builds an inventory of components within a skill directory.
    """

    # File type mappings
    FILE_TYPES = {
        ".md": "markdown",
        ".markdown": "markdown",
        ".py": "python",
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".txt": "text",
        ".js": "javascript",
        ".ts": "typescript",
        ".rb": "ruby",
        ".go": "go",
        ".rs": "rust",
    }

    # Extensions that indicate executable code
    EXECUTABLE_EXTENSIONS = {".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".rb", ".go", ".rs", ".pl"}

    # Directories to skip
    SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".pytest_cache"}

    def build(self, skill_dir: Path) -> list[Component]:
        """
        Build inventory of all components in a skill directory.

        Args:
            skill_dir: Path to the skill directory

        Returns:
            List of Component objects
        """
        components = []

        for file_path in self._walk_files(skill_dir):
            component = self._analyze_file(file_path, skill_dir)
            if component:
                components.append(component)

        # Sort by path for consistent ordering
        components.sort(key=lambda c: c.path)

        return components

    def extract_metadata(self, skill_dir: Path) -> SkillMetadata:
        """
        Extract metadata from SKILL.md file if present.

        Args:
            skill_dir: Path to the skill directory

        Returns:
            SkillMetadata object (may have empty fields if no SKILL.md)
        """
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            # Try lowercase
            skill_md = skill_dir / "skill.md"
            if not skill_md.exists():
                return SkillMetadata()

        try:
            content = skill_md.read_text(encoding="utf-8", errors="replace")
            return self._parse_skill_md(content)
        except Exception:
            return SkillMetadata()

    def _walk_files(self, directory: Path) -> list[Path]:
        """Walk directory and yield all relevant files."""
        files = []

        if not directory.is_dir():
            if directory.is_file():
                return [directory]
            return []

        for item in directory.rglob("*"):
            if item.is_file():
                # Skip files in excluded directories
                if any(skip in item.parts for skip in self.SKIP_DIRS):
                    continue

                # Skip hidden files (but not .claude or similar config dirs)
                if item.name.startswith(".") and not item.name.startswith(".claude"):
                    continue

                files.append(item)

        return files

    def _analyze_file(self, file_path: Path, base_dir: Path) -> Optional[Component]:
        """
        Analyze a single file and create a Component.

        Args:
            file_path: Path to the file
            base_dir: Base directory for relative path calculation

        Returns:
            Component object or None if file should be skipped
        """
        try:
            relative_path = file_path.relative_to(base_dir)
            suffix = file_path.suffix.lower()

            # Determine file type
            file_type = self.FILE_TYPES.get(suffix, "other")

            # Count lines
            lines = self._count_lines(file_path)

            # Check if executable
            executable = suffix in self.EXECUTABLE_EXTENSIONS

            # Get file size
            size_bytes = file_path.stat().st_size

            return Component(
                path=str(relative_path),
                type=file_type,
                lines=lines,
                executable=executable,
                size_bytes=size_bytes,
            )

        except Exception:
            return None

    def _count_lines(self, file_path: Path) -> int:
        """Count lines in a file, handling binary files gracefully."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            return len(content.splitlines())
        except Exception:
            return 0

    def _parse_skill_md(self, content: str) -> SkillMetadata:
        """
        Parse SKILL.md content to extract YAML frontmatter metadata.

        Expected format:
        ---
        name: my-skill
        description: A description
        triggers:
          - "keyword1"
        permissions:
          - file_read
        ---

        # Skill content...
        """
        metadata = SkillMetadata()

        # Check for YAML frontmatter
        if not content.startswith("---"):
            return metadata

        # Find end of frontmatter
        end_match = re.search(r"\n---\s*\n", content[3:])
        if not end_match:
            return metadata

        frontmatter = content[3 : end_match.start() + 3]

        try:
            data = yaml.safe_load(frontmatter)
            if not isinstance(data, dict):
                return metadata

            metadata.name = data.get("name")
            metadata.description = data.get("description")

            triggers = data.get("triggers", [])
            if isinstance(triggers, list):
                metadata.triggers = [str(t) for t in triggers]

            permissions = data.get("permissions", [])
            if isinstance(permissions, list):
                metadata.permissions = [str(p) for p in permissions]

        except yaml.YAMLError:
            pass

        return metadata
