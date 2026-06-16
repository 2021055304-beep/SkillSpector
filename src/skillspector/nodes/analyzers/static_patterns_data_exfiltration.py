# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Static patterns: data exfiltration (E1–E4). Node and analyze() in one module.

Detects patterns where data is transmitted externally (E1), credentials
are harvested (E2), sensitive files are enumerated (E3), or conversation
context leaks to external services (E4).
"""

from __future__ import annotations

import re
import sys

from skillspector.logging_config import get_logger
from skillspector.models import AnalyzerFinding, Location, Severity
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

from . import static_runner
from .common import get_context, get_line_number
from .pattern_defaults import PatternCategory

logger = get_logger(__name__)

ANALYZER_ID = "static_patterns_data_exfiltration"

# Indicators that the context is a legitimate API integration or skill
# declaration rather than data exfiltration.
_DATA_EXFIL_DOC_INDICATORS: tuple[str, ...] = (
    # Legitimate API patterns
    "api key",
    "api_key",
    "api-key",
    "bearer",
    "authorization",
    "auth header",
    "auth-header",
    "api endpoint",
    "api_endpoint",
    "api-endpoint",
    "api call",
    "api_call",
    "api-call",
    "webhook",
    "callback",
    # Skill declaration patterns
    "integrates with",
    "connects to",
    "uses the",
    "calls the",
    "sends to",
    "communicates with",
    "supported by",
    "provided by",
    # Multi-turn conversation patterns
    "multi-turn",
    "multi turn",
    "conversation history",
    "chat history",
    "context window",
    "session history",
    "previous context",
    "previous conversation",
    # Documentation indicators
    "example",
    "for example",
    "e.g.",
    "such as",
    "documentation",
    "tutorial",
    "guide",
    "reference",
    "how to",
    "instructions",
    "note:",
    "warning:",
)

# Indicators that a credential access is for legitimate API authentication
# rather than exfiltration.
_DATA_EXFIL_AUTH_INDICATORS: tuple[str, ...] = (
    "authorization",
    "auth",
    "bearer",
    "api key",
    "api_key",
    "access token",
    "access_token",
    "oauth",
    "credential",
    "credentials",
    "login",
    "authenticate",
    "authentication",
    "token",
)

# Indicators that a conversation context reference is for legitimate
# multi-turn skill operation rather than exfiltration.
_MULTI_TURN_INDICATORS: tuple[str, ...] = (
    "multi-turn",
    "multi turn",
    "conversation history",
    "chat history",
    "session history",
    "previous context",
    "previous conversation",
    "previous messages",
    "full conversation",
    "full context",
    "thread",
    "context window",
    "user's context",
    "user's conversation",
    "user's history",
)


def _is_legitimate_api_context(context: str) -> bool:
    """Return True when the context suggests a legitimate API integration."""
    ctx_lower = context.lower()
    return any(ind in ctx_lower for ind in _DATA_EXFIL_DOC_INDICATORS)


def _is_auth_context(context: str) -> bool:
    """Return True when the context is about legitimate API authentication."""
    ctx_lower = context.lower()
    return any(ind in ctx_lower for ind in _DATA_EXFIL_AUTH_INDICATORS)


def _is_multi_turn_skill(context: str) -> bool:
    """Return True when the context indicates a legitimate multi-turn skill."""
    ctx_lower = context.lower()
    return any(ind in ctx_lower for ind in _MULTI_TURN_INDICATORS)


# E1: External Transmission — tightened confidence, removed overly broad patterns
E1_PATTERNS = [
    (r"requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*=", 0.8),
    (r"urllib\s*\.\s*request\s*\.\s*urlopen\s*\([^)]*data\s*=", 0.8),
    (r"fetch\s*\(\s*['\"]https?://[^'\"]+['\"][^)]*method\s*:\s*['\"]POST['\"]", 0.8),
    (r"curl\s+[^|]*(?:-d|--data|--data-raw|--data-binary)\s+", 0.75),
    (r"wget\s+[^|]*--post-(?:data|file)", 0.75),
    (
        r"(?:send|transmit|post|upload)\s+(?:user\s+)?(?:data|information|context|files?)\s+to\s+(?:https?://|external)",
        0.8,
    ),
]

# E2: Env Variable Harvesting — removed os.environ.copy() (standard debug pattern)
E2_PATTERNS = [
    (
        r"os\.environ\s*\[\s*['\"][^'\"]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[^'\"]*['\"]\s*\]",
        0.85,
    ),
    (r"os\.environ\.get\s*\([^)]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)", 0.8),
    (r"(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s+in\s+(?:key|name|var)", 0.85),
    (r"process\.env\s*\[\s*['\"][^'\"]*(?:KEY|SECRET|TOKEN|PASSWORD)[^'\"]*['\"]\s*\]", 0.8),
    (r"env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)", 0.85),
    (r"printenv\s+(?:\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*)", 0.8),
    (r"collect\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?)", 0.8),
    (r"(?:extract|harvest|gather)\s+(?:api\s+)?keys?\s+from\s+environment", 0.85),
]

# E3: File System Enumeration — raised confidence, removed overly broad patterns
E3_PATTERNS = [
    (r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)", 0.85),
    (r"os\s*\.\s*walk\s*\([^)]*(?:home|~|/Users|/home)", 0.75),
    (r"Path\s*\.\s*home\s*\(\s*\)\s*\.\s*(?:glob|rglob)\s*\(", 0.8),
    (
        r"(?:find|search|scan|enumerate)\s+(?:for\s+)?(?:all\s+)?(?:\.env|credential|secret|key)\s+files?",
        0.85,
    ),
    (r"os\s*\.\s*listdir\s*\([^)]*(?:\.ssh|\.aws|\.config|\.gnupg)", 0.85),
    (r"scandir\s*\([^)]*(?:home|~|/Users|/home)", 0.75),
    (r"find\s+[~\$/]\S*\s+.*?-name\s+['\"]?\*(?:\.env|\.pem|\.key|credential)", 0.85),
    (r"ls\s+-[la]*R?\s+(?:~/|/home/|/Users/)", 0.75),
]

# E4: Conversation Context Leakage — tightened, added multi-turn filter
E4_PATTERNS = [
    (
        r"(?:send|transmit|upload|log|record)\s+(?:the\s+)?(?:full\s+)?(?:conversation|chat|dialog|session)\s+(?:history|context|log)?",
        0.9,
    ),
    (
        r"(?:export|dump|save)\s+(?:the\s+)?(?:conversation|chat|messages?)\s+to\s+(?:external|remote|server)",
        0.95,
    ),
    (
        r"log\s+(?:all\s+)?(?:user\s+)?(?:input|messages?|queries?|prompts?)\s+to\s+(?:external|remote|server)",
        0.9,
    ),
    (r"(?:store|save|record)\s+(?:every|all)\s+(?:user\s+)?(?:interaction|message|input)", 0.8),
    (r"(?:extract|capture|collect)\s+(?:the\s+)?(?:full\s+)?(?:context|conversation|thread)", 0.85),
    (
        r"(?:include|attach|append)\s+(?:previous\s+)?(?:messages?|context|history)\s+in\s+(?:the\s+)?(?:request|payload)",
        0.8,
    ),
    (r"(?:send|upload|transmit)\s+(?:the\s+)?(?:session|memory|state)\s+(?:data\s+)?to", 0.85),
    (r"(?:copy|clone|replicate)\s+(?:the\s+)?(?:agent|assistant)\s+(?:memory|context|state)", 0.85),
]


def analyze(content: str, file_path: str, file_type: str) -> list[AnalyzerFinding]:
    """Analyze content for data exfiltration patterns (E1–E4)."""
    findings: list[AnalyzerFinding] = []

    def loc(ln: int) -> Location:
        return Location(file=file_path, start_line=ln)

    def ctx(start: int) -> str:
        return get_context(content, start)

    tag = [PatternCategory.DATA_EXFILTRATION.value]

    for pattern, confidence in E1_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = get_line_number(content, match.start())
            context_text = ctx(match.start())
            if _is_legitimate_api_context(context_text):
                continue
            if _is_auth_context(context_text):
                continue
            adj = (
                min(1.0, confidence + 0.1)
                if file_type in ("python", "javascript", "shell")
                else confidence
            )
            findings.append(
                AnalyzerFinding(
                    rule_id="E1",
                    message="External Transmission",
                    severity=Severity.MEDIUM,
                    location=loc(line_num),
                    confidence=adj,
                    tags=tag,
                    context=context_text,
                    matched_text=match.group(0)[:200],
                )
            )
    for pattern, confidence in E2_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = get_line_number(content, match.start())
            context_text = ctx(match.start())
            if _is_auth_context(context_text):
                continue
            findings.append(
                AnalyzerFinding(
                    rule_id="E2",
                    message="Env Variable Harvesting",
                    severity=Severity.HIGH,
                    location=loc(line_num),
                    confidence=confidence,
                    tags=tag,
                    context=context_text,
                    matched_text=match.group(0)[:200],
                )
            )
    for pattern, confidence in E3_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = get_line_number(content, match.start())
            context_text = ctx(match.start())
            if _is_legitimate_api_context(context_text):
                continue
            findings.append(
                AnalyzerFinding(
                    rule_id="E3",
                    message="File System Enumeration",
                    severity=Severity.MEDIUM,
                    location=loc(line_num),
                    confidence=confidence,
                    tags=tag,
                    context=context_text,
                    matched_text=match.group(0)[:200],
                )
            )
    for pattern, confidence in E4_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = get_line_number(content, match.start())
            context_text = ctx(match.start())
            if _is_multi_turn_skill(context_text):
                continue
            findings.append(
                AnalyzerFinding(
                    rule_id="E4",
                    message="Context Leakage",
                    severity=Severity.HIGH,
                    location=loc(line_num),
                    confidence=confidence,
                    tags=tag,
                    context=context_text,
                    matched_text=match.group(0)[:200],
                )
            )
    return findings


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Run data_exfiltration patterns and return findings."""
    findings = static_runner.run_static_patterns(state, [sys.modules[__name__]])
    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}
