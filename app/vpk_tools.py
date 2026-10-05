import os
import shutil
from typing import Dict

from .vpk_reader import open_vpk


def process_server_vpk(
    src_vpk_path: str,
    work_dir_root: str,
    output_dir: str,
    output_filename: str
) -> Dict:
    """原样暂存已校验的 VPK；保留调用签名和报告结构以兼容既有发布流程。"""
    with open_vpk(src_vpk_path) as arch:
        total_entries = len(arch)
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, output_filename)
    # 原位写入调用方已锁定的临时文件，不能替换 inode，否则清理锁会失效。
    shutil.copyfile(src_vpk_path, out_path)
    os.remove(src_vpk_path)
    return {
        "mode": "original",
        "entries": total_entries,
        "server": {
            "path": out_path,
            "kept": total_entries,
            "removed": 0,
            "removed_list": [],
        },
        "size": os.path.getsize(out_path),
    }
