import os
import fnmatch
import yaml
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional

from .vpk_integrity import inspect_vpk

@dataclass
class ValidationResult:
    ok: bool
    size_mb: float
    max_size_mb: int
    required_present: List[str]
    missing_required: List[str]
    blocked_hits: List[str]
    warned_hits: List[str]
    file_count: int
    sample_files: List[str]
    repairable_issues: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

def _norm(p: str) -> str:
    p = p.replace("\\", "/")
    if p.startswith("/") or ".." in p.split("/") or ":" in p:
        raise ValueError("VPK 内部路径不安全。")
    return p.lstrip("./").lower()

def _load_rules(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def validate_vpk(vpk_path: str, rules_path: str, max_size_mb_override: Optional[int] = None,
                 allow_repair: bool = False) -> ValidationResult:
    rules = _load_rules(rules_path)
    max_size_mb = max_size_mb_override if max_size_mb_override is not None else rules.get("max_size_mb", 600)
    require_files = [s.lower() for s in rules.get("require_files", [])]
    block_globs = [s.lower() for s in rules.get("block_globs", [])]
    warn_globs = [s.lower() for s in rules.get("warn_globs", [])]

    size_bytes = os.path.getsize(vpk_path)
    size_mb = size_bytes / (1024 * 1024)

    inspection = inspect_vpk(vpk_path, allow_repair=allow_repair,
                             max_content_bytes=max_size_mb * 1024 * 1024)
    entries = [_norm(entry.path) for entry in inspection.entries]

    file_count = len(entries)

    required_present, missing_required = [], []
    lower_entries = set(entries)
    for req in require_files:
        hit = any(e.endswith("/" + req) or e == req for e in lower_entries)
        (required_present if hit else missing_required).append(req)

    blocked_hits, warned_hits = [], []
    for e in entries:
        if any(fnmatch.fnmatch(e, pat) for pat in block_globs):
            blocked_hits.append(e)
            continue
        if any(fnmatch.fnmatch(e, pat) for pat in warn_globs):
            warned_hits.append(e)

    ok = size_mb <= max_size_mb and not missing_required and not blocked_hits

    return ValidationResult(
        ok=ok,
        size_mb=round(size_mb, 2),
        max_size_mb=max_size_mb,
        required_present=required_present,
        missing_required=missing_required,
        blocked_hits=blocked_hits[:50],
        warned_hits=warned_hits[:50],
        file_count=file_count,
        sample_files=entries[:20],
        repairable_issues=inspection.repairs,
    )
