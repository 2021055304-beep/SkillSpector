"""
Input handler for SkillSpector.

Handles various input formats:
- Git repository URLs
- Raw file URLs
- Local zip files
- Single markdown files
- Local directories
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx


class InputHandler:
    """
    Handles input resolution for different source types.

    Normalizes all inputs to a local directory path for scanning.
    """

    def __init__(self):
        self._temp_dir: Optional[Path] = None

    def resolve(self, input_path: str) -> Tuple[Path, str]:
        """
        Resolve input to a scannable directory.

        Args:
            input_path: Path or URL to resolve

        Returns:
            Tuple of (resolved_path, source_type)
            source_type is one of: "git", "url", "zip", "file", "directory"

        Raises:
            ValueError: If input type cannot be determined
            FileNotFoundError: If local path doesn't exist
        """
        input_path = input_path.strip()

        # Determine input type and resolve
        if self._is_git_url(input_path):
            return self._clone_git(input_path), "git"
        elif self._is_file_url(input_path):
            return self._download_file(input_path), "url"
        elif input_path.endswith(".zip"):
            return self._extract_zip(Path(input_path)), "zip"
        elif input_path.endswith(".md"):
            return self._wrap_single_file(Path(input_path)), "file"
        elif Path(input_path).is_dir():
            return Path(input_path).resolve(), "directory"
        elif Path(input_path).is_file():
            return self._wrap_single_file(Path(input_path)), "file"
        else:
            raise ValueError(
                f"Cannot determine input type for: {input_path}\n"
                "Supported formats: Git URL, file URL, .zip file, .md file, or directory"
            )

    def cleanup(self) -> None:
        """Clean up temporary files created during resolution."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def _get_temp_dir(self) -> Path:
        """Get or create a temporary directory for this session."""
        if not self._temp_dir:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="skillspector_"))
        return self._temp_dir

    def _is_git_url(self, path: str) -> bool:
        """Check if path is a Git repository URL."""
        if not path.startswith(("http://", "https://", "git@")):
            return False

        parsed = urlparse(path)

        # Check for common Git hosts
        git_hosts = ["github.com", "gitlab.com", "bitbucket.org"]
        if any(host in parsed.netloc for host in git_hosts):
            # Check it's not a raw file URL
            if "/raw/" in path or "/blob/" in path or path.endswith((".md", ".py", ".sh")):
                return False
            return True

        # Check for .git extension
        if path.endswith(".git"):
            return True

        return False

    def _is_file_url(self, path: str) -> bool:
        """Check if path is a direct file URL."""
        if not path.startswith(("http://", "https://")):
            return False
        # It's a URL but not a git repo
        return not self._is_git_url(path)

    def _clone_git(self, url: str) -> Path:
        """Clone a Git repository to a temporary directory."""
        temp_dir = self._get_temp_dir()
        clone_dir = temp_dir / "repo"

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(clone_dir)],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to clone repository: {e.stderr.decode()}")
        except subprocess.TimeoutExpired:
            raise ValueError("Git clone timed out after 60 seconds")
        except FileNotFoundError:
            raise ValueError("Git is not installed. Please install git to scan repositories.")

        return clone_dir

    def _download_file(self, url: str) -> Path:
        """Download a file from URL to a temporary directory."""
        temp_dir = self._get_temp_dir()

        # Determine filename from URL
        parsed = urlparse(url)
        filename = Path(parsed.path).name or "SKILL.md"

        try:
            with httpx.Client(follow_redirects=True, timeout=30) as client:
                response = client.get(url)
                response.raise_for_status()
                content = response.content
        except httpx.HTTPError as e:
            raise ValueError(f"Failed to download file: {e}")

        # If it's a zip file, extract it
        if filename.endswith(".zip") or response.headers.get("content-type", "").startswith(
            "application/zip"
        ):
            zip_path = temp_dir / "download.zip"
            zip_path.write_bytes(content)
            return self._extract_zip(zip_path)

        # Otherwise, save as single file
        file_path = temp_dir / filename
        file_path.write_bytes(content)

        return temp_dir

    def _extract_zip(self, zip_path: Path) -> Path:
        """Extract a zip file to a temporary directory."""
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")

        temp_dir = self._get_temp_dir()
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            raise ValueError(f"Invalid zip file: {zip_path}")

        # If extraction created a single subdirectory, return that
        contents = list(extract_dir.iterdir())
        if len(contents) == 1 and contents[0].is_dir():
            return contents[0]

        return extract_dir

    def _wrap_single_file(self, file_path: Path) -> Path:
        """
        Wrap a single file in a temporary directory for consistent handling.

        For single .md files, we create a temp directory containing just that file.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        temp_dir = self._get_temp_dir()

        # Copy the file to temp directory
        dest = temp_dir / file_path.name
        shutil.copy2(file_path, dest)

        return temp_dir
