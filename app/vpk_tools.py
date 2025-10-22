\
    import os
    import shutil
    from typing import List, Tuple, Dict
    from vpk import VPK
    from .thirdparty.l4d2_vpk_lib import NewVPK

    # Whitelist for server build
    SERVER_KEEP_GLOBS = [
        "maps/*.bsp",
        "maps/*.nav",
        "maps/*.txt",
        "maps/*.cfg",
        "maps/*.kv",
        "maps/*.lmp",
        "maps/*.ain",
        "addoninfo.txt",
        # If server logic needs vscripts, uncomment:
        # "scripts/vscripts/**",
    ]

    CLIENT_TRIM_GLOBS: List[str] = []

    def _norm(p: str) -> str:
        return p.replace("\\\\", "/").lstrip("./")

    def _match_glob(path: str, pattern: str) -> bool:
        import fnmatch
        path = path.lower()
        pattern = pattern.lower().replace("**", "*")
        return fnmatch.fnmatch(path, pattern)

    def extract_vpk_to_dir(vpk_path: str, out_dir: str) -> List[str]:
        os.makedirs(out_dir, exist_ok=True)
        entries: List[str] = []
        with VPK(vpk_path) as arch:
            for f in arch:
                rel = _norm(f.filename)
                entries.append(rel)
                dst = os.path.join(out_dir, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "wb") as w:
                    w.write(f.read())
        return entries

    def _filter_copy(in_dir: str, out_dir: str, keep_globs: List[str], trim_globs: List[str]=None) -> Tuple[int, int, List[str]]:
        os.makedirs(out_dir, exist_ok=True)
        kept = 0
        removed = 0
        removed_list: List[str] = []
        for root, dirs, files in os.walk(in_dir):
            for name in files:
                rel = _norm(os.path.relpath(os.path.join(root, name), in_dir))
                keep = any(_match_glob(rel, pat) for pat in keep_globs) if keep_globs else True
                if trim_globs and any(_match_glob(rel, pat) for pat in trim_globs):
                    keep = False
                if keep:
                    dst = os.path.join(out_dir, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(os.path.join(in_dir, rel), dst)
                    kept += 1
                else:
                    removed += 1
                    removed_list.append(rel)
        return kept, removed, removed_list

    def build_vpk_from_dir(dir_path: str, dest_vpk_path: str):
        vp = NewVPK(dir_path)
        try:
            vp.tree_length = vp.calculate_tree_length()
        except Exception:
            pass
        vp.save(dest_vpk_path)

    def process_map_vpk(src_vpk_path: str, out_dir: str) -> Dict:
        \"\"\"
        Extract VPK, then build:
          - client vpk: full contents (optionally trimmed by CLIENT_TRIM_GLOBS)
          - server vpk: whitelist (SERVER_KEEP_GLOBS)
        Returns stats & paths.
        \"\"\"
        work = os.path.join(out_dir, "work")
        ext_dir = os.path.join(work, "extracted")
        client_dir = os.path.join(work, "client_dir")
        server_dir = os.path.join(work, "server_dir")
        for d in [work, ext_dir, client_dir, server_dir]:
            os.makedirs(d, exist_ok=True)

        entries = extract_vpk_to_dir(src_vpk_path, ext_dir)
        kept_c, removed_c, removed_list_c = _filter_copy(ext_dir, client_dir, keep_globs=[], trim_globs=CLIENT_TRIM_GLOBS or [])
        kept_s, removed_s, removed_list_s = _filter_copy(ext_dir, server_dir, keep_globs=SERVER_KEEP_GLOBS, trim_globs=[])

        base = os.path.splitext(os.path.basename(src_vpk_path))[0]
        client_vpk = os.path.join(out_dir, f"{base}_client.vpk")
        server_vpk = os.path.join(out_dir, f"{base}_server.vpk")

        build_vpk_from_dir(client_dir, client_vpk)
        build_vpk_from_dir(server_dir, server_vpk)

        def _size(p: str) -> int:
            return os.path.getsize(p) if os.path.exists(p) else 0

        return {
            "entries": len(entries),
            "client": {"path": client_vpk, "kept": kept_c, "removed": removed_c, "size": _size(client_vpk), "removed_list": removed_list_c[:200],},
            "server": {"path": server_vpk, "kept": kept_s, "removed": removed_s, "size": _size(server_vpk), "removed_list": removed_list_s[:200],},
        }
