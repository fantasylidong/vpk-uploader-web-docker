import os
from typing import Tuple

from vpk import VPK


DEFAULT_PATH_ENCODINGS: Tuple[str, ...] = (
    "utf-8",
    "gb18030",
    "cp936",
    "big5",
    "shift_jis",
    "cp1252",
    "latin-1",
)


def _path_encodings() -> Tuple[str, ...]:
    raw = os.getenv("VPK_PATH_ENCODINGS", "")
    encodings = tuple(part.strip() for part in raw.split(",") if part.strip())
    return encodings or DEFAULT_PATH_ENCODINGS


def open_vpk(vpk_path: str):
    """
    Open a VPK and eagerly read its index with a tolerant path encoding fallback.

    Some community VPKs store directory entries in local code pages such as GBK
    instead of UTF-8. The upstream library decodes paths while iterating the
    index, so we force that read here and retry with compatible encodings.
    """
    decode_errors = []
    attempted = []

    for encoding in _path_encodings():
        attempted.append(encoding)
        try:
            arch = VPK(vpk_path, path_enc=encoding)
            arch.read_index()
        except UnicodeDecodeError as exc:
            decode_errors.append(f"{encoding}: {exc}")
            continue

        arch.path_encoding = encoding
        return arch

    if decode_errors:
        raise ValueError(
            "VPK 目录路径无法按支持的编码读取（已尝试："
            + ", ".join(attempted)
            + "）"
        )

    raise ValueError("VPK 目录路径无法读取")
