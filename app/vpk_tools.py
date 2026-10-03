import os
import errno
import fcntl
import shutil
import tempfile
from typing import List, Dict

from .vpk_reader import open_vpk
from .thirdparty.l4d2_vpk_lib import NewVPK

# 服务器保留白名单（包含 vscripts 与 missions，避免“没有模式/机关不触发”）
SERVER_KEEP_GLOBS = [
    "maps/*.bsp",
    "maps/*.nav",
    "maps/*.txt",
    "maps/*.cfg",
    "maps/*.kv",
    "maps/*.lmp",
    "maps/*.ain",
    "addoninfo.txt",
    "scripts/vscripts/**",
    "missions/**",
]

def _norm(p: str) -> str:
    return p.replace("\\", "/").lstrip("./")

def _match_glob(path: str, pattern: str) -> bool:
    import fnmatch
    path = path.lower()
    pattern = pattern.lower().replace("**", "*")
    return fnmatch.fnmatch(path, pattern)

def extract_vpk_to_dir(vpk_path: str, out_dir: str) -> int:
    """解包 VPK 到目录，返回条目数量"""
    os.makedirs(out_dir, exist_ok=True)
    count = 0
    with open_vpk(vpk_path) as arch:
        for rel in arch:  # 返回的是路径字符串
            norm_rel = _norm(rel)
            dst = os.path.join(out_dir, norm_rel)
            if os.path.commonpath([os.path.abspath(out_dir), os.path.abspath(dst)]) != os.path.abspath(out_dir):
                raise ValueError("VPK 内部路径不安全，无法解包。")
            try:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                data = arch.get_file(rel).read()
                with open(dst, "wb") as w:
                    w.write(data)
            except OSError as exc:
                if exc.errno in (errno.EEXIST, errno.ENOTDIR, errno.EISDIR, errno.ENAMETOOLONG):
                    raise ValueError("VPK 内部路径冲突或过长，无法解包。") from exc
                raise
            count += 1
    return count

def _filter_copy(in_dir: str, out_dir: str, keep_globs: List[str]) -> Dict:
    """把 in_dir 中符合白名单的文件拷贝到 out_dir，并返回统计"""
    os.makedirs(out_dir, exist_ok=True)
    kept = 0
    removed = 0
    removed_list: List[str] = []
    for root, _, files in os.walk(in_dir):
        for name in files:
            rel = _norm(os.path.relpath(os.path.join(root, name), in_dir))
            keep = any(_match_glob(rel, pat) for pat in keep_globs) if keep_globs else True
            if keep:
                dst = os.path.join(out_dir, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(os.path.join(in_dir, rel), dst)
                kept += 1
            else:
                removed += 1
                removed_list.append(rel)
    return {"kept": kept, "removed": removed, "removed_list": removed_list[:200]}

def build_vpk_from_dir(dir_path: str, dest_vpk_path: str) -> None:
    """把目录重新打成 VPK"""
    vp = NewVPK(dir_path)
    try:
        vp.tree_length = vp.calculate_tree_length()
    except Exception:
        pass
    vp.save(dest_vpk_path)

def process_server_vpk(
    src_vpk_path: str,
    work_dir_root: str,
    output_dir: str,
    output_filename: str
) -> Dict:
    """
    在独占的临时目录中解包、筛选、重打包，异常时也清理工作目录。
    工作目录锁供定时清理识别仍在运行的构建。
    """
    with tempfile.TemporaryDirectory(prefix="vpk-work-", dir=work_dir_root) as work:
        with open(os.path.join(work, ".lock"), "wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            ext_dir = os.path.join(work, "extracted")
            server_dir = os.path.join(work, "server_dir")
            total_entries = extract_vpk_to_dir(src_vpk_path, ext_dir)
            os.remove(src_vpk_path)
            stats = _filter_copy(ext_dir, server_dir, SERVER_KEEP_GLOBS)
            os.makedirs(output_dir, exist_ok=True)
            out_path = os.path.join(output_dir, output_filename)
            build_vpk_from_dir(server_dir, out_path)

    return {
        "entries": total_entries,
        "server": {
            "path": out_path,
            "kept": stats["kept"],
            "removed": stats["removed"],
            "removed_list": stats["removed_list"],
        },
        "size": os.path.getsize(out_path) if os.path.exists(out_path) else 0,
        "work_dir": work,
    }
