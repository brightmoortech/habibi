from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class Finding:
    source: str
    category: str
    severity: str
    path: str = ""
    line: int = 0
    detail: str = ""

@dataclass
class Context:
    root: Path
    files: list[Path]

@dataclass
class PluginResult:
    name: str
    technologies: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage_issues: list[str] = field(default_factory=list)
