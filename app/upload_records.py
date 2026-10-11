"""随地图目录保留生命周期记录，SQLite 丢失时仍能识别网页上传。"""

import hashlib
import json
import os
import tempfile
from datetime import datetime


FIELDS = (
    "id", "original_name", "stored_name", "sha256", "size", "role",
    "created_at", "expires_at", "vpk_valid", "vpk_report", "status", "uploader_ip",
)


def file_fingerprint(stat) -> dict:
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            "ctime_ns": stat.st_ctime_ns, "inode": stat.st_ino}


def record_path(upload_dir: str, name: str) -> str:
    key = hashlib.sha256(name.encode("utf-8")).hexdigest()
    return os.path.join(upload_dir, ".upload-records", key + ".json")


def write_record(upload_dir: str, upload, file_stat=None) -> None:
    path = record_path(upload_dir, upload.stored_name)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    values = {key: getattr(upload, key) for key in FIELDS}
    for key in ("created_at", "expires_at"):
        values[key] = values[key].isoformat() if values[key] else None
    # 只能缓存调用方校验内容时看到的 stat，不能把随后 SFTP 写入的新 stat 配给旧哈希。
    payload = {"version": 1, "upload": values, "file_stat": file_stat}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=os.path.dirname(path),
                                         prefix=".record-", delete=False) as output:
            temporary = output.name
            json.dump(payload, output, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.remove(temporary)


def read_record(upload_dir: str, name: str):
    path = record_path(upload_dir, name)
    try:
        with open(path, encoding="utf-8") as source:
            record = json.load(source)
    except FileNotFoundError:
        return None
    values = record.get("upload") if isinstance(record, dict) else None
    if (not isinstance(record, dict) or record.get("version") != 1 or not isinstance(values, dict)
            or set(values) != set(FIELDS) or values["stored_name"] != name):
        raise ValueError("Invalid persistent upload record")
    for key in ("created_at", "expires_at"):
        values[key] = datetime.fromisoformat(values[key]) if values[key] else None
    return record
