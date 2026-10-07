import os
import shutil
from typing import Dict

from .vpk_integrity import inspect_vpk, repack_vpk


def process_server_vpk(
    src_vpk_path: str,
    work_dir_root: str,
    output_dir: str,
    output_filename: str,
    max_size_bytes: int = 1024 * 1024 * 1024,
) -> Dict:
    """完整原包默认直存；只有可无损修复的目录错误才重新打包。"""
    inspection = inspect_vpk(src_vpk_path, allow_repair=True, max_content_bytes=max_size_bytes)
    total_entries = len(inspection.entries)
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, output_filename)
    # 原位写入调用方已锁定的临时文件，不能替换 inode，否则清理锁会失效。
    if inspection.repairs:
        repack_vpk(src_vpk_path, out_path, inspection, max_size_bytes)
    else:
        shutil.copyfile(src_vpk_path, out_path)
    # The publication caller performs strict format + rules validation on this staged output.
    os.remove(src_vpk_path)
    return {
        "mode": "repaired" if inspection.repairs else "original",
        "repairs": inspection.repairs,
        "entries": total_entries,
        "server": {
            "path": out_path,
            "kept": total_entries,
            "removed": 0,
            "removed_list": [],
        },
        "size": os.path.getsize(out_path),
    }
