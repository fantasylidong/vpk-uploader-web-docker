import os
import fnmatch
import yaml
from dataclasses import dataclass, asdict
from typing import List, Dict
from vpk import VPK

@dataclass
class ValidationResult:
    ok: bool
    size_mb: float
    required_present: List[str]
    missing_required: List[str]
    blocked_hits: List[str]
    warned_hits: List[str]
    file_count: int
    sample_files: List[str]

    def to_dict(self):
        return asdict(self)

def _norm(p: str) -> str:
    return p.replace("\\", "/").lstrip("./").lower()

def _load_rules(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def validate_vpk(vpk_path: str, rules_path: str) -> ValidationResult:
    rules = _load_rules(rules_path)
    max_size_mb = rules.get("max_size_mb", 600)
    require_files = [s.lower() for s in rules.get("require_files", [])]
    block_globs = [s.lower() for s in rules.get("block_globs", [])]
    warn_globs = [s.lower() for s in rules.get("warn_globs", [])]

    size_mb = os.path.getsize(vpk_path) / (1024 * 1024)

    with VPK(vpk_path) as arch:
        entries = [_norm(rel) for rel in arch]  # 注意：返回的是路径字符串

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
        required_present=required_present,
        missing_required=missing_required,
        blocked_hits=blocked_hits[:50],
        warned_hits=warned_hits[:50],
        file_count=file_count,
        sample_files=entries[:20],
    )
