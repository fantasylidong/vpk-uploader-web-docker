import asyncio
import os
import fcntl
import hashlib
import shutil
import secrets
import json
import logging
import threading
import time
import select
import subprocess
from contextlib import contextmanager
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import FastAPI, Request, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeSerializer, BadSignature

from .vpkcheck import validate_vpk, ValidationResult
from .vpk_tools import process_server_vpk
from .vpk_reader import open_vpk
from .db import init_db, SessionLocal, Upload, AppSetting, ReplicationReservation, WorkshopJob
from .docker_manager import DockerManager
from .aggregation import client_ip_is_allowed, token_is_valid
from .chunked_upload import ChunkUploadError, ChunkUploadStore
from .lan_replication import (
    PROTOCOL_VERSION,
    ReplicationArtifact,
    load_lan_replication_config,
    replicate_artifacts,
)
from .steam_workshop import (
    MAX_ITEMS_PER_JOB,
    SteamCmdRunner,
    SteamWebApiClient,
    WorkshopError,
    WorkshopItemDetails,
    collect_vpk_files,
    describe_files,
    details_from_payload,
    download_direct,
    looks_like_vpk,
    load_workshop_config,
    parse_supplied_details,
    parse_workshop_ids,
)

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
INSTANCE_NAME = os.getenv("INSTANCE_NAME", "VPK Uploader")
FEDERATION_API_TOKEN = os.getenv("FEDERATION_API_TOKEN", "")
FEDERATION_ALLOWED_CIDRS = os.getenv("FEDERATION_ALLOWED_CIDRS", "")
LAN_REPLICATION = load_lan_replication_config()
WORKSHOP = load_workshop_config()
logger = logging.getLogger("vpk_uploader")
DEFAULT_MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "1024"))
DEFAULT_TOTAL_UPLOAD_LIMIT_MB = int(os.getenv("MAX_TOTAL_UPLOAD_MB", "0"))
DEFAULT_GUEST_TTL_HOURS = int(os.getenv("DEFAULT_GUEST_TTL_HOURS", "24"))
UPLOAD_MAX_MB_SETTING_KEY = "upload_max_mb"
TOTAL_UPLOAD_LIMIT_SETTING_KEY = "total_upload_limit_mb"
GUEST_TTL_SETTING_KEY = "guest_ttl_hours"
RULES_FILE = os.getenv("RULES_FILE", "rules.yml")
UPLOAD_EXTENSIONS = (".vpk", ".zip", ".rar", ".7z")
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
UPLOAD_ACCEPT = ",".join(UPLOAD_EXTENSIONS)
UPLOAD_TYPE_LABEL = ".vpk / .zip / .rar / .7z"
DEFAULT_MAX_ARCHIVE_VPK_COUNT = int(os.getenv("MAX_ARCHIVE_VPK_COUNT", "50"))
ARCHIVE_VPK_COUNT_SETTING_KEY = "archive_vpk_count"
ARCHIVE_LIST_TIMEOUT_SECONDS = int(os.getenv("ARCHIVE_LIST_TIMEOUT_SECONDS", "120"))
ARCHIVE_EXTRACT_TIMEOUT_SECONDS = int(os.getenv("ARCHIVE_EXTRACT_TIMEOUT_SECONDS", "600"))
CHUNK_UPLOAD_SIZE_MB = max(1, min(32, int(os.getenv("CHUNK_UPLOAD_SIZE_MB", "8"))))
CHUNK_UPLOAD_PARALLELISM = max(1, min(8, int(os.getenv("CHUNK_UPLOAD_PARALLELISM", "4"))))
CHUNK_UPLOAD_MAX_AGE_HOURS = max(1, int(os.getenv("CHUNK_UPLOAD_MAX_AGE_HOURS", "48")))
CHUNK_UPLOAD_DISK_RESERVE_MB = max(0, int(os.getenv("CHUNK_UPLOAD_DISK_RESERVE_MB", "512")))
CHUNK_UPLOAD_MAX_ACTIVE_SESSIONS = max(1, int(os.getenv("CHUNK_UPLOAD_MAX_ACTIVE_SESSIONS", "64")))
CHUNK_UPLOAD_MAX_SESSIONS_PER_CLIENT = max(1, int(os.getenv("CHUNK_UPLOAD_MAX_SESSIONS_PER_CLIENT", "4")))

# 清理策略（分钟/小时）
TMP_MAX_AGE_MIN = int(os.getenv("TMP_MAX_AGE_MIN", "30"))
WORK_MAX_AGE_MIN = int(os.getenv("WORK_MAX_AGE_MIN", "60"))
SFTP_IMPORT_MIN_AGE_SECONDS = int(os.getenv("SFTP_IMPORT_MIN_AGE_SECONDS", "30"))
SFTP_SCAN_INTERVAL_SECONDS = max(5, int(os.getenv("SFTP_SCAN_INTERVAL_SECONDS", "60")))

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(BASE_DIR), "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
CHUNK_UPLOAD_DIR = os.path.join(DATA_DIR, "upload_sessions")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

# 重要：上传文件与工作目录在系统 /tmp
TMP_DIR = os.getenv("TMP_DIR", "/tmp")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)
CAPACITY_LOCK_PATH = os.path.join(DATA_DIR, ".capacity.lock")
CHUNK_UPLOAD_STORE = ChunkUploadStore(
    CHUNK_UPLOAD_DIR,
    chunk_size=CHUNK_UPLOAD_SIZE_MB * 1024 * 1024,
    max_age_seconds=CHUNK_UPLOAD_MAX_AGE_HOURS * 60 * 60,
)

app = FastAPI(title="VPK Uploader")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
templates.env.filters['tojson'] = lambda v: json.dumps(v, ensure_ascii=False, indent=2)

signer = URLSafeSerializer(APP_SECRET, salt="session")
init_db()
_sftp_scan_lock = threading.Lock()
_sftp_scan_task: Optional[asyncio.Task] = None
WORKSHOP_API = SteamWebApiClient(WORKSHOP)
WORKSHOP_STEAMCMD = SteamCmdRunner(WORKSHOP)
WORKSHOP_JOB_ACTIVE_STATES = ("queued", "running")
WORKSHOP_ROLES = ("guest", "admin")
WORKSHOP_DEFAULT_ROLE = "guest"
_workshop_queue: Optional[asyncio.Queue] = None
_workshop_worker_task: Optional[asyncio.Task] = None
WORKSHOP_CLEANUP_INTERVAL_SECONDS = 300
_workshop_cleanup_at = 0.0


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _disposition_utf8(filename: str) -> str:
    ascii_fallback = "".join(c if 32 <= ord(c) < 127 else "_" for c in filename)
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(filename)}"


def _normalize_hours(hours: int) -> int:
    return max(0, int(hours))


def _normalize_mb(mb: int) -> int:
    return max(0, int(mb))


def _normalize_positive_int(value: int) -> int:
    return max(1, int(value))


def _format_mb(byte_count: int) -> str:
    return f"{byte_count / 1024 / 1024:.2f} MB"


def guest_ttl_label(hours: int) -> str:
    hours = _normalize_hours(hours)
    if hours == 0:
        return "永久保存"
    return f"自动保留 {hours} 小时"


def total_upload_limit_label(limit_mb: int) -> str:
    limit_mb = _normalize_mb(limit_mb)
    if limit_mb == 0:
        return "不限"
    return f"{limit_mb} MB"


def _get_int_setting(db, key: str, default_value: int, normalizer) -> int:
    try:
        setting = db.get(AppSetting, key)
        if not setting:
            return normalizer(default_value)
        return normalizer(setting.value)
    except (TypeError, ValueError):
        return normalizer(default_value)


def _set_int_setting(key: str, value: int, normalizer) -> None:
    value = normalizer(value)
    db = SessionLocal()
    try:
        setting = db.get(AppSetting, key)
        if setting:
            setting.value = str(value)
        else:
            setting = AppSetting(key=key, value=str(value))
            db.add(setting)
        db.commit()
    finally:
        db.close()


def get_guest_ttl_hours(db=None) -> int:
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        return _get_int_setting(db, GUEST_TTL_SETTING_KEY, DEFAULT_GUEST_TTL_HOURS, _normalize_hours)
    finally:
        if own_db:
            db.close()


def set_guest_ttl_hours(hours: int) -> None:
    _set_int_setting(GUEST_TTL_SETTING_KEY, hours, _normalize_hours)


def get_upload_max_mb(db=None) -> int:
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        return _get_int_setting(db, UPLOAD_MAX_MB_SETTING_KEY, DEFAULT_MAX_UPLOAD_MB, _normalize_positive_int)
    finally:
        if own_db:
            db.close()


def set_upload_max_mb(max_mb: int) -> None:
    _set_int_setting(UPLOAD_MAX_MB_SETTING_KEY, max_mb, _normalize_positive_int)


def get_total_upload_limit_mb(db=None) -> int:
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        return _get_int_setting(db, TOTAL_UPLOAD_LIMIT_SETTING_KEY, DEFAULT_TOTAL_UPLOAD_LIMIT_MB, _normalize_mb)
    finally:
        if own_db:
            db.close()


def set_total_upload_limit_mb(limit_mb: int) -> None:
    _set_int_setting(TOTAL_UPLOAD_LIMIT_SETTING_KEY, limit_mb, _normalize_mb)


def get_archive_vpk_count(db=None) -> int:
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        return _get_int_setting(
            db,
            ARCHIVE_VPK_COUNT_SETTING_KEY,
            DEFAULT_MAX_ARCHIVE_VPK_COUNT,
            _normalize_positive_int,
        )
    finally:
        if own_db:
            db.close()


def set_archive_vpk_count(count: int) -> None:
    _set_int_setting(ARCHIVE_VPK_COUNT_SETTING_KEY, count, _normalize_positive_int)


def active_upload_usage_bytes(db) -> int:
    rows = db.query(Upload.size).filter(Upload.status == "active").all()
    return sum((size or 0) for (size,) in rows)


@contextmanager
def capacity_guard():
    lock_fd = os.open(CAPACITY_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _expire_replication_reservations(db) -> bool:
    changed = False
    current = now_utc()
    rows = db.query(ReplicationReservation).filter(
        ReplicationReservation.status == "active"
    ).all()
    for row in rows:
        expires_at = _as_aware_utc(row.expires_at)
        if expires_at is not None and expires_at <= current:
            row.status = "expired"
            row.reserved_bytes = 0
            changed = True
    return changed


def active_replication_reserved_bytes(db) -> int:
    changed = _expire_replication_reservations(db)
    rows = db.query(ReplicationReservation.reserved_bytes).filter(
        ReplicationReservation.status == "active"
    ).all()
    if changed:
        db.commit()
    return sum(max(0, reserved or 0) for (reserved,) in rows)


def replication_storage_snapshot(db) -> dict[str, Any]:
    used_bytes = active_upload_usage_bytes(db)
    reserved_bytes = active_replication_reserved_bytes(db)
    chunk_reserved_bytes = CHUNK_UPLOAD_STORE.reserved_bytes()
    limit_mb = get_total_upload_limit_mb(db)
    limit_bytes = limit_mb * 1024 * 1024
    disk_free_bytes = shutil.disk_usage(UPLOAD_DIR).free
    disk_available_bytes = max(
        0,
        disk_free_bytes - LAN_REPLICATION.disk_reserve_bytes - reserved_bytes - chunk_reserved_bytes,
    )
    quota_available_bytes = None
    if limit_bytes > 0:
        quota_available_bytes = max(0, limit_bytes - used_bytes - reserved_bytes - chunk_reserved_bytes)
    available_bytes = disk_available_bytes
    if quota_available_bytes is not None:
        available_bytes = min(available_bytes, quota_available_bytes)
    return {
        "limit_bytes": limit_bytes,
        "used_bytes": used_bytes,
        "reserved_bytes": reserved_bytes,
        "chunk_reserved_bytes": chunk_reserved_bytes,
        "quota_available_bytes": quota_available_bytes,
        "disk_free_bytes": disk_free_bytes,
        "disk_reserve_bytes": LAN_REPLICATION.disk_reserve_bytes,
        "available_bytes": available_bytes,
    }


def storage_context(db) -> dict:
    snapshot = replication_storage_snapshot(db)
    used_bytes = int(snapshot["used_bytes"])
    reserved_bytes = int(snapshot["reserved_bytes"])
    chunk_reserved_bytes = int(snapshot["chunk_reserved_bytes"])
    all_reserved_bytes = reserved_bytes + chunk_reserved_bytes
    limit_mb = get_total_upload_limit_mb(db)
    limit_bytes = limit_mb * 1024 * 1024
    usage_percent = 0
    remaining_bytes = None

    if limit_bytes > 0:
        usage_percent = min(100, round(used_bytes / limit_bytes * 100, 1))
        remaining_bytes = max(0, limit_bytes - used_bytes - all_reserved_bytes)

    usage_label = f"已用 {_format_mb(used_bytes)} / {total_upload_limit_label(limit_mb)}"
    if remaining_bytes is not None:
        usage_label = f"{usage_label}，剩余 {_format_mb(remaining_bytes)}"
    if all_reserved_bytes:
        usage_label = f"{usage_label}，预留 {_format_mb(all_reserved_bytes)}"

    return {
        "total_upload_limit_mb": limit_mb,
        "total_upload_limit_label": total_upload_limit_label(limit_mb),
        "total_upload_limit_bytes": limit_bytes,
        "total_upload_used_bytes": used_bytes,
        "total_upload_reserved_bytes": all_reserved_bytes,
        "chunk_upload_reserved_bytes": chunk_reserved_bytes,
        "total_upload_available_bytes": int(snapshot["available_bytes"]),
        "total_upload_used_label": _format_mb(used_bytes),
        "total_upload_usage_label": usage_label,
        "total_upload_usage_percent": usage_percent,
        "disk_free_bytes": int(snapshot["disk_free_bytes"]),
        "disk_reserve_bytes": int(snapshot["disk_reserve_bytes"]),
    }


def _public_url(path: str) -> str:
    if path.startswith(("http://", "https://", "//")):
        return path
    if not path.startswith("/"):
        path = f"/{path}"
    if not PUBLIC_BASE_URL:
        return path
    return f"{PUBLIC_BASE_URL}{path}"


def thirdparty_map_api_payload() -> dict:
    db = SessionLocal()
    try:
        rows = (
            db.query(Upload)
            .filter(Upload.status == "active")
            .order_by(Upload.created_at.desc())
            .limit(200)
            .all()
        )
        maps = []
        for item in rows:
            maps.append({
                "id": item.id,
                "name": item.original_name,
                "original_name": item.original_name,
                "stored_name": item.stored_name,
                "size": item.size,
                "size_label": _format_mb(item.size or 0),
                "role": item.role,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "expires_at": item.expires_at.isoformat() if item.expires_at else None,
                "detail_url": _public_url(f"/detail/{item.id}"),
                "download_url": _public_url(f"/d/{item.id}"),
                "files_url": _public_url(f"/api/uploads/{item.id}/files"),
            })
    finally:
        db.close()

    return {
        "generated_at": now_utc().isoformat(),
        "public_base_url": PUBLIC_BASE_URL,
        "upload_url": _public_url("/"),
        "admin_url": _public_url("/admin"),
        "map_count": len(maps),
        "maps": maps,
    }


def index_context(
    request: Request,
    error: Optional[str] = None,
    report=None,
    batch_results: Optional[dict] = None,
) -> dict:
    db = SessionLocal()
    try:
        guest_ttl_hours = get_guest_ttl_hours(db)
        upload_max_mb = get_upload_max_mb(db)
        context = {
            "request": request,
            "max_mb": upload_max_mb,
            "upload_accept": UPLOAD_ACCEPT,
            "upload_type_label": UPLOAD_TYPE_LABEL,
            "guest_ttl_hours": guest_ttl_hours,
            "guest_ttl_label": guest_ttl_label(guest_ttl_hours),
            "error": error,
            "report": report,
            "batch_results": batch_results,
        }
        context.update(storage_context(db))
        return context
    finally:
        db.close()


def admin_context(
    request: Request,
    q: Optional[str] = None,
    settings_saved: bool = False,
    upload_error: Optional[str] = None,
    upload_message: Optional[str] = None,
) -> dict:
    db = SessionLocal()
    try:
        guest_ttl_hours = get_guest_ttl_hours(db)
        upload_max_mb = get_upload_max_mb(db)
        archive_vpk_count = get_archive_vpk_count(db)
        query = db.query(Upload).order_by(Upload.created_at.desc())
        if q:
            like = f"%{q}%"
            query = query.filter(Upload.original_name.like(like))
        items = query.limit(200).all()
        context = {
            "request": request,
            "items": items,
            "q": q or "",
            "max_mb": upload_max_mb,
            "archive_vpk_count": archive_vpk_count,
            "upload_accept": UPLOAD_ACCEPT,
            "upload_type_label": UPLOAD_TYPE_LABEL,
            "guest_ttl_hours": guest_ttl_hours,
            "guest_ttl_label": guest_ttl_label(guest_ttl_hours),
            "settings_saved": settings_saved,
            "upload_error": upload_error,
            "upload_message": upload_message,
        }
        context.update(storage_context(db))
        return context
    finally:
        db.close()


def upload_error_response(request: Request, role: str, message: str, report=None):
    if role == "admin":
        return templates.TemplateResponse("admin_dashboard.html", admin_context(request, upload_error=message))
    return templates.TemplateResponse("index.html", index_context(request, error=message, report=report))


def upload_batch_response(request: Request, role: str, results: dict):
    if role == "admin":
        ok_count = len(results.get("uploaded", []))
        failed_count = len(results.get("failed", []))
        message = f"批量上传完成：成功 {ok_count} 个"
        if failed_count:
            message = f"{message}，失败 {failed_count} 个"
        return templates.TemplateResponse("admin_dashboard.html", admin_context(request, upload_message=message))

    return templates.TemplateResponse("index.html", index_context(request, batch_results=results))


def total_capacity_error(
    db,
    new_file_size: int,
    current_chunk_reservation: int = 0,
) -> Optional[str]:
    limit_mb = get_total_upload_limit_mb(db)
    if limit_mb <= 0:
        return None

    limit_bytes = limit_mb * 1024 * 1024
    used_bytes = active_upload_usage_bytes(db)
    reserved_bytes = active_replication_reserved_bytes(db)
    chunk_reserved_bytes = max(0, CHUNK_UPLOAD_STORE.reserved_bytes() - current_chunk_reservation)
    if used_bytes + reserved_bytes + chunk_reserved_bytes + new_file_size <= limit_bytes:
        return None

    remaining_bytes = max(0, limit_bytes - used_bytes - reserved_bytes - chunk_reserved_bytes)
    reserved_detail = f"，复制预留 {_format_mb(reserved_bytes)}" if reserved_bytes else ""
    chunk_detail = f"，分片上传预留 {_format_mb(chunk_reserved_bytes)}" if chunk_reserved_bytes else ""
    return (
        "上传失败：已超过上传总容量限制。"
        f"总容量上限 {total_upload_limit_label(limit_mb)}，"
        f"当前已用 {_format_mb(used_bytes)}{reserved_detail}{chunk_detail}，"
        f"剩余 {_format_mb(remaining_bytes)}，"
        f"本次生成文件 {_format_mb(new_file_size)}。"
    )


def _basename_only(filename: str) -> str:
    """取纯文件名（去路径），并禁止目录穿越。"""
    base = os.path.basename((filename or "").replace("\\", "/"))
    return base.replace("/", "").replace("\\", "").replace("\x00", "").strip()


def _split_supported_upload(filename: str):
    """上传文件必须是 VPK 或受支持的压缩包。"""
    base = _basename_only(filename)
    lower = base.lower()
    for ext in UPLOAD_EXTENSIONS:
        if lower.endswith(ext) and base[:-len(ext)].strip():
            return base, ext
    raise HTTPException(status_code=400, detail=f"文件名非法：仅支持 {UPLOAD_TYPE_LABEL}")


def _ensure_vpk_filename(filename: str) -> str:
    """返回安全的 VPK 文件名。"""
    base = _basename_only(filename)
    if not base.lower().endswith(".vpk") or not base[:-4].strip():
        raise HTTPException(status_code=400, detail="VPK 文件名非法：必须以 .vpk 结尾")
    return base


def _safe_base_no_ext(filename: str) -> str:
    """基于原始上传名生成工作目录名（不含扩展名），保留中文与空格，移除斜杠。"""
    base = _ensure_vpk_filename(filename)
    name_no_ext = os.path.splitext(base)[0]
    name_no_ext = name_no_ext.strip().replace("/", "").replace("\\", "")
    return name_no_ext or "upload"


def _remove_file_quietly(path: Optional[str]) -> None:
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _bsdtar_path() -> str:
    path = shutil.which("bsdtar")
    if not path:
        raise HTTPException(status_code=500, detail="服务器未安装压缩包解包工具 bsdtar")
    return path


def _archive_error(stderr: str) -> str:
    stderr = (stderr or "").strip()
    if not stderr:
        return "压缩包读取失败"
    return f"压缩包读取失败：{stderr[:300]}"


def _list_archive_members(archive_path: str) -> list[str]:
    try:
        proc = subprocess.run(
            [_bsdtar_path(), "-tf", archive_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ARCHIVE_LIST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=400, detail="压缩包读取超时")

    if proc.returncode != 0:
        raise HTTPException(status_code=400, detail=_archive_error(proc.stderr))

    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _extract_archive_member_to_file(
    archive_path: str,
    member: str,
    dest_path: str,
    max_bytes: int,
    max_mb: int,
) -> int:
    cmd = [_bsdtar_path(), "-x", "-O", "-f", archive_path, "--", member]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_fd = proc.stdout.fileno()
    stderr_fd = proc.stderr.fileno()
    open_fds = {stdout_fd, stderr_fd}
    stderr_chunks: list[bytes] = []
    stderr_size = 0
    extracted_bytes = 0
    started_at = time.monotonic()

    try:
        with open(dest_path, "wb") as out:
            while open_fds:
                if time.monotonic() - started_at > ARCHIVE_EXTRACT_TIMEOUT_SECONDS:
                    proc.kill()
                    raise HTTPException(status_code=400, detail="压缩包解压超时")

                ready, _, _ = select.select(list(open_fds), [], [], 1)
                if not ready:
                    continue

                for fd in ready:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        open_fds.discard(fd)
                        continue

                    if fd == stdout_fd:
                        extracted_bytes += len(chunk)
                        if extracted_bytes > max_bytes:
                            proc.kill()
                            raise HTTPException(status_code=400, detail=f"压缩包内的 VPK 解压后超过 {max_mb} MB 限制")
                        out.write(chunk)
                    elif stderr_size < 8192:
                        stderr_chunks.append(chunk)
                        stderr_size += len(chunk)

        return_code = proc.wait(timeout=5)
    except HTTPException:
        proc.kill()
        proc.wait(timeout=5)
        _remove_file_quietly(dest_path)
        raise
    except Exception:
        proc.kill()
        proc.wait(timeout=5)
        _remove_file_quietly(dest_path)
        raise

    stderr = b"".join(stderr_chunks).decode("utf-8", "replace")
    if return_code != 0:
        _remove_file_quietly(dest_path)
        raise HTTPException(status_code=400, detail=_archive_error(stderr))
    if extracted_bytes <= 0:
        _remove_file_quietly(dest_path)
        raise HTTPException(status_code=400, detail="压缩包内的 VPK 为空")

    return extracted_bytes


def _archive_vpk_members(archive_path: str, max_count: int) -> list[str]:
    members = _list_archive_members(archive_path)
    vpk_members = [member for member in members if _basename_only(member).lower().endswith(".vpk")]

    if not vpk_members:
        raise HTTPException(status_code=400, detail="压缩包中没有找到 .vpk 文件")
    if len(vpk_members) > max_count:
        raise HTTPException(
            status_code=400,
            detail=f"压缩包中包含 {len(vpk_members)} 个 .vpk，超过单次最多 {max_count} 个限制",
        )

    return vpk_members


def _extract_archive_vpk_member(archive_path: str, archive_name: str, member: str, max_bytes: int, max_mb: int):
    vpk_name = _ensure_vpk_filename(member)
    tmp_vpk_path = os.path.join(TMP_DIR, f"{secrets.token_hex(6)}.vpk")
    extracted_bytes = _extract_archive_member_to_file(archive_path, member, tmp_vpk_path, max_bytes, max_mb)

    return tmp_vpk_path, vpk_name, {
        "source": "archive",
        "uploaded_name": archive_name,
        "archive_member": member,
        "source_vpk_name": vpk_name,
        "extracted_size": extracted_bytes,
    }


def _sha256_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def _unique_server_filename(db, work_base: str) -> str:
    base = work_base or "upload"
    candidate = f"{base}_server.vpk"
    index = 2

    while True:
        path = os.path.join(UPLOAD_DIR, candidate)
        exists_in_db = db.query(Upload.id).filter(Upload.stored_name == candidate).first() is not None
        if not exists_in_db and not os.path.exists(path):
            return candidate
        candidate = f"{base}_{index}_server.vpk"
        index += 1


def _upload_item_result(up: Upload) -> dict:
    return {
        "id": up.id,
        "original_name": up.original_name,
        "stored_name": up.stored_name,
        "sha256": up.sha256,
        "size": up.size,
        "size_label": _format_mb(up.size or 0),
        "detail_url": f"/detail/{up.id}",
        "download_url": f"/d/{up.id}",
        "role": up.role,
        "expires_at": up.expires_at.isoformat() if up.expires_at else None,
    }


def _extend_expiry(existing: Upload, expires_at: Optional[datetime]) -> None:
    """同一个文件再传一次就续期：永久的保持永久，有期限的取更晚的那个。"""
    current = _as_aware_utc(existing.expires_at)
    if current is None:
        return
    if expires_at is None:
        existing.expires_at = None
        return
    candidate = _as_aware_utc(expires_at)
    if candidate is not None and candidate > current:
        existing.expires_at = expires_at


def _find_active_upload_by_sha256(db, sha256: str, size: int) -> Optional[Upload]:
    candidates = db.query(Upload).filter(
        Upload.status == "active",
        Upload.size == size,
    ).all()
    for item in candidates:
        path = os.path.join(UPLOAD_DIR, item.stored_name)
        if not os.path.isfile(path):
            continue
        try:
            actual_sha256 = _sha256_file(path)
        except OSError:
            continue
        if actual_sha256 == sha256:
            item.sha256 = sha256
            db.flush()
            return item
    return None


def _expiry_for_upload(db, role: str, ttl_hours: Optional[int]) -> Optional[datetime]:
    if role == "guest":
        guest_ttl_hours = get_guest_ttl_hours(db)
        if guest_ttl_hours > 0:
            return now_utc() + timedelta(hours=guest_ttl_hours)
        return None

    if ttl_hours is not None and ttl_hours > 0:
        return now_utc() + timedelta(hours=ttl_hours)
    return None


def _process_vpk_upload(
    uploader_ip: Optional[str],
    role: str,
    ttl_hours: Optional[int],
    tmp_vpk_path: str,
    source_vpk_name: str,
    upload_sha256: str,
    upload_source: dict,
    upload_max_mb: int,
    current_chunk_reservation: int = 0,
):
    display_name = _ensure_vpk_filename(source_vpk_name)
    work_base = _safe_base_no_ext(display_name)

    try:
        vr: ValidationResult = validate_vpk(tmp_vpk_path, RULES_FILE, max_size_mb_override=upload_max_mb)
    except Exception as exc:
        _remove_file_quietly(tmp_vpk_path)
        raise HTTPException(status_code=400, detail=f"VPK 读取失败：{exc}")

    if not vr.ok:
        _remove_file_quietly(tmp_vpk_path)
        return None, {
            "name": display_name,
            "error": "VPK 不符合要求",
            "report": vr.to_dict(),
        }

    db = SessionLocal()
    final_name = None
    try:
        expires_at = _expiry_for_upload(db, role, ttl_hours)
        final_name = _unique_server_filename(db, work_base)

        build_report = process_server_vpk(
            src_vpk_path=tmp_vpk_path,
            work_dir_root=TMP_DIR,
            work_base_name=f"{work_base}_{secrets.token_hex(4)}",
            output_dir=UPLOAD_DIR,
            output_filename=final_name,
        )

        server_path = os.path.join(UPLOAD_DIR, final_name)
        server_size = os.path.getsize(server_path) if os.path.exists(server_path) else 0
        server_sha256 = _sha256_file(server_path)
        upload_source = {**upload_source, "uploaded_sha256": upload_sha256}
        report = {"upload_source": upload_source, "validation": vr.to_dict(), "server_build": build_report}

        with capacity_guard():
            existing = _find_active_upload_by_sha256(db, server_sha256, server_size)
            if existing is not None:
                _remove_file_quietly(server_path)
                _extend_expiry(existing, expires_at)
                db.commit()
                result = _upload_item_result(existing)
                result["deduplicated"] = True
                return existing, result

            capacity_error = total_capacity_error(
                db,
                server_size,
                current_chunk_reservation=current_chunk_reservation,
            )
            if capacity_error:
                _remove_file_quietly(server_path)
                return None, {"name": display_name, "error": capacity_error}

            up = Upload(
                original_name=display_name,
                stored_name=final_name,
                sha256=server_sha256,
                size=server_size,
                role=role,
                created_at=now_utc(),
                expires_at=expires_at,
                vpk_valid=True,
                vpk_report=json.dumps(report, ensure_ascii=False),
                status="active",
                uploader_ip=uploader_ip,
            )
            db.add(up)
            db.commit()
            db.refresh(up)
            result = _upload_item_result(up)
            return up, result
    except Exception:
        if final_name:
            _remove_file_quietly(os.path.join(UPLOAD_DIR, final_name))
        _remove_file_quietly(tmp_vpk_path)
        raise
    finally:
        db.close()


def _file_newer_than_upload_record(stat: os.stat_result, upload: Upload) -> bool:
    created_at = _as_aware_utc(upload.created_at)
    if not created_at:
        return False
    return stat.st_mtime > created_at.timestamp() + 1


def sync_sftp_uploads(now_ts: Optional[float] = None) -> dict[str, int | bool]:
    """把 SFTP 放进 uploads 的 .vpk 登记为管理员上传，避免被当作无主文件处理。"""
    stats: dict[str, int | bool] = {
        "scanned": 0,
        "imported": 0,
        "updated": 0,
        "existing": 0,
        "deferred": 0,
        "errors": 0,
        "busy": False,
    }
    if not _sftp_scan_lock.acquire(blocking=False):
        stats["busy"] = True
        return stats

    if now_ts is None:
        now_ts = time.time()

    db = None
    try:
        db = SessionLocal()
        by_name = {row.stored_name: row for row in db.query(Upload).all()}
        for name in sorted(os.listdir(UPLOAD_DIR)):
            if not name.lower().endswith(".vpk"):
                continue

            path = os.path.join(UPLOAD_DIR, name)
            if not os.path.isfile(path):
                continue
            stats["scanned"] += 1

            try:
                stat = os.stat(path)
            except OSError:
                stats["errors"] += 1
                continue

            if now_ts - stat.st_mtime < SFTP_IMPORT_MIN_AGE_SECONDS:
                stats["deferred"] += 1
                continue

            existing = by_name.get(name)
            if existing and existing.status == "active" and not _file_newer_than_upload_record(stat, existing):
                stats["existing"] += 1
                continue

            try:
                imported_at = now_utc()
                file_sha256 = _sha256_file(path)
                final_stat = os.stat(path)
                if final_stat.st_size != stat.st_size or final_stat.st_mtime_ns != stat.st_mtime_ns:
                    stats["deferred"] += 1
                    continue
                report = {
                    "validation": {
                        "ok": True,
                        "source": "sftp",
                        "message": "SFTP 上传按管理员上传处理，未经过网页端校验和重打包。",
                    },
                    "sftp_import": {
                        "imported_at": imported_at.isoformat(),
                        "mtime": stat.st_mtime,
                        "note": "SFTP 上传文件按管理员上传处理，未经过网页端重打包。",
                    }
                }
                if existing:
                    existing.original_name = name
                    existing.sha256 = file_sha256
                    existing.size = stat.st_size
                    existing.role = "admin"
                    existing.created_at = imported_at
                    existing.expires_at = None
                    existing.vpk_valid = True
                    existing.vpk_report = json.dumps(report, ensure_ascii=False)
                    existing.status = "active"
                    existing.uploader_ip = "sftp"
                    stats["updated"] += 1
                else:
                    existing = Upload(
                        original_name=name,
                        stored_name=name,
                        sha256=file_sha256,
                        size=stat.st_size,
                        role="admin",
                        created_at=imported_at,
                        expires_at=None,
                        vpk_valid=True,
                        vpk_report=json.dumps(report, ensure_ascii=False),
                        status="active",
                        uploader_ip="sftp",
                    )
                    db.add(existing)
                    stats["imported"] += 1

                db.commit()
                by_name[name] = existing
            except Exception:
                db.rollback()
                stats["errors"] += 1
                logger.exception("Failed to import SFTP VPK: %s", name)

        return stats
    finally:
        if db is not None:
            db.close()
        _sftp_scan_lock.release()


async def _sftp_sync_loop() -> None:
    while True:
        try:
            stats = await asyncio.to_thread(sync_sftp_uploads)
            if stats["imported"] or stats["updated"] or stats["errors"]:
                logger.info("SFTP upload scan completed: %s", stats)
            await asyncio.sleep(SFTP_SCAN_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("SFTP upload scan failed")
            await asyncio.sleep(SFTP_SCAN_INTERVAL_SECONDS)


@app.on_event("startup")
async def start_sftp_sync() -> None:
    global _sftp_scan_task
    if _sftp_scan_task is None or _sftp_scan_task.done():
        _sftp_scan_task = asyncio.create_task(_sftp_sync_loop())


@app.on_event("shutdown")
async def stop_sftp_sync() -> None:
    global _sftp_scan_task
    task = _sftp_scan_task
    _sftp_scan_task = None
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def cleanup_expired():
    db = SessionLocal()
    try:
        utcnow = now_utc()
        candidates = db.query(Upload).filter(
            Upload.expires_at.isnot(None),
            Upload.status == "active",
        ).all()

        expired = [
            u for u in candidates
            if (_as_aware_utc(u.expires_at) and _as_aware_utc(u.expires_at) < utcnow)
        ]

        for u in expired:
            try:
                path = os.path.join(UPLOAD_DIR, u.stored_name)
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            u.status = "deleted"

        if expired:
            db.commit()
    finally:
        db.close()


def cleanup_replication_reservations():
    db = SessionLocal()
    try:
        with capacity_guard():
            changed = _expire_replication_reservations(db)
            cutoff = now_utc() - timedelta(hours=24)
            rows = db.query(ReplicationReservation).filter(
                ReplicationReservation.status != "active"
            ).all()
            for row in rows:
                created_at = _as_aware_utc(row.created_at)
                if created_at is not None and created_at < cutoff:
                    db.delete(row)
                    changed = True
            if changed:
                db.commit()
    finally:
        db.close()


def cleanup_tmp_and_work():
    now_ts = time.time()

    # 清理 /tmp 中遗留的工作目录（/tmp/<原名>/...）
    try:
        for name in os.listdir(TMP_DIR):
            p = os.path.join(TMP_DIR, name)
            # 仅清理我们创建的工作目录痕迹：目录且最近未改动
            if os.path.isdir(p):
                age = now_ts - os.path.getmtime(p)
                if age > WORK_MAX_AGE_MIN * 60:
                    try:
                        shutil.rmtree(p, ignore_errors=True)
                    except Exception:
                        pass
    except Exception:
        pass

    try:
        CHUNK_UPLOAD_STORE.cleanup_expired()
    except Exception:
        pass

    # 创意工坊下载会先把 VPK 落到 TMP_DIR；进程在处理途中被杀就会留下大文件。
    try:
        for name in os.listdir(TMP_DIR):
            if not (name.startswith("workshop_") and name.endswith(".vpk")):
                continue
            path = os.path.join(TMP_DIR, name)
            if os.path.isfile(path) and now_ts - os.path.getmtime(path) > WORK_MAX_AGE_MIN * 60:
                _remove_file_quietly(path)
    except Exception:
        pass

    # 接收内网复制时先写隐藏分片；进程被强制终止后由这里清理孤立文件。
    try:
        max_partial_age = max(WORK_MAX_AGE_MIN * 60, LAN_REPLICATION.reservation_ttl_seconds)
        for name in os.listdir(UPLOAD_DIR):
            if not (name.startswith(".lan-") and name.endswith(".part")):
                continue
            path = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(path) and now_ts - os.path.getmtime(path) > max_partial_age:
                _remove_file_quietly(path)
    except Exception:
        pass

@app.middleware("http")
async def tidy_mw(request: Request, call_next):
    cleanup_tmp_and_work()
    cleanup_expired()
    cleanup_replication_reservations()
    cleanup_workshop_jobs()
    response = await call_next(request)
    return response


def get_session(request: Request) -> dict:
    cookie = request.cookies.get("session")
    if not cookie:
        return {}
    try:
        return signer.loads(cookie)
    except BadSignature:
        return {}


def set_session(response, data: dict):
    response.set_cookie("session", signer.dumps(data), httponly=True, samesite="lax")


def clear_session(response):
    response.delete_cookie("session")


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"


@app.get("/api/thirdparty-maps")
async def thirdparty_maps():
    return thirdparty_map_api_payload()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", index_context(request))


def _process_staged_upload(
    *,
    uploader_ip: Optional[str],
    tmp_upload_path: str,
    original_name: str,
    upload_ext: str,
    read_bytes: int,
    upload_sha256: str,
    role: str,
    ttl_hours: Optional[int],
    upload_max_mb: int,
    archive_vpk_count: int,
    current_chunk_reservation: int,
):
    max_bytes = upload_max_mb * 1024 * 1024
    uploaded = []
    failed = []
    uploads = []

    try:
        if upload_ext in ARCHIVE_EXTENSIONS:
            archive_members = _archive_vpk_members(tmp_upload_path, archive_vpk_count)
            for index, member in enumerate(archive_members, start=1):
                tmp_vpk_path = None
                try:
                    tmp_vpk_path, source_vpk_name, upload_source = _extract_archive_vpk_member(
                        tmp_upload_path,
                        original_name,
                        member,
                        max_bytes,
                        upload_max_mb,
                    )
                    upload_source.update({
                        "uploaded_size": read_bytes,
                        "archive_vpk_index": index,
                        "archive_vpk_count": len(archive_members),
                    })
                    up, result = _process_vpk_upload(
                        uploader_ip=uploader_ip,
                        role=role,
                        ttl_hours=ttl_hours,
                        tmp_vpk_path=tmp_vpk_path,
                        source_vpk_name=source_vpk_name,
                        upload_sha256=upload_sha256,
                        upload_source=upload_source,
                        upload_max_mb=upload_max_mb,
                        current_chunk_reservation=current_chunk_reservation,
                    )
                    tmp_vpk_path = None
                    if up is not None:
                        uploads.append(up)
                        uploaded.append(result)
                    else:
                        failed.append(result)
                except HTTPException as exc:
                    _remove_file_quietly(tmp_vpk_path)
                    failed.append({"name": _basename_only(member) or member, "error": str(exc.detail)})
                except Exception as exc:
                    _remove_file_quietly(tmp_vpk_path)
                    failed.append({"name": _basename_only(member) or member, "error": f"处理失败：{exc}"})
        else:
            upload_source = {
                "source": "vpk",
                "uploaded_name": original_name,
                "source_vpk_name": original_name,
                "uploaded_size": read_bytes,
            }
            up, result = _process_vpk_upload(
                uploader_ip=uploader_ip,
                role=role,
                ttl_hours=ttl_hours,
                tmp_vpk_path=tmp_upload_path,
                source_vpk_name=original_name,
                upload_sha256=upload_sha256,
                upload_source=upload_source,
                upload_max_mb=upload_max_mb,
                current_chunk_reservation=current_chunk_reservation,
            )
            tmp_upload_path = None
            if up is not None:
                uploads.append(up)
                uploaded.append(result)
            else:
                failed.append(result)
    finally:
        _remove_file_quietly(tmp_upload_path)

    return uploads, {"uploaded": uploaded, "failed": failed}


async def _handle_upload(
    request: Request,
    file: UploadFile,
    role: str,
    ttl_hours: Optional[int],
    render_error: bool = True,
    current_chunk_reservation: int = 0,
):
    # 1) 文件名校验：允许直接上传 VPK，或上传包含多个 VPK 的压缩包。
    original_name, upload_ext = _split_supported_upload(file.filename)

    # 2) 上传流写入系统 /tmp
    db = SessionLocal()
    try:
        upload_max_mb = get_upload_max_mb(db)
        archive_vpk_count = get_archive_vpk_count(db)
    finally:
        db.close()

    max_bytes = upload_max_mb * 1024 * 1024
    tmp_upload_path = os.path.join(TMP_DIR, f"{secrets.token_hex(6)}{upload_ext}")

    read_bytes = 0
    sha256 = hashlib.sha256()

    with open(tmp_upload_path, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > max_bytes:
                out.close()
                _remove_file_quietly(tmp_upload_path)
                raise HTTPException(status_code=400, detail=f"文件过大，超过 {upload_max_mb} MB 限制")
            sha256.update(chunk)
            out.write(chunk)

    uploads, results = await asyncio.to_thread(
        _process_staged_upload,
        uploader_ip=request.client.host if request.client else None,
        tmp_upload_path=tmp_upload_path,
        original_name=original_name,
        upload_ext=upload_ext,
        read_bytes=read_bytes,
        upload_sha256=sha256.hexdigest(),
        role=role,
        ttl_hours=ttl_hours,
        upload_max_mb=upload_max_mb,
        archive_vpk_count=archive_vpk_count,
        current_chunk_reservation=current_chunk_reservation,
    )

    if results["uploaded"]:
        return uploads, results, None

    failed = results["failed"]
    first_failure = failed[0] if failed else {"error": "没有成功处理任何 VPK"}
    report = first_failure.get("report")
    response = upload_error_response(request, role, first_failure["error"], report=report) if render_error else None
    return [], results, response


@app.post("/upload")
async def guest_upload(request: Request, file: UploadFile):
    uploads, results, resp = await _handle_upload(request, file, role="guest", ttl_hours=None)
    if resp is not None:
        return resp
    if len(uploads) == 1 and not results["failed"]:
        return RedirectResponse(url=f"/detail/{uploads[0].id}", status_code=302)
    return upload_batch_response(request, "guest", results)


def require_admin(request: Request):
    sess = get_session(request)
    if sess.get("role") == "admin":
        return True
    raise HTTPException(status_code=401, detail="需要管理员登录")


def _chunk_upload_http_error(exc: ChunkUploadError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


async def _authorized_chunk_upload(request: Request, upload_id: str):
    token = request.headers.get("X-Upload-Token", "")
    try:
        status = await asyncio.to_thread(CHUNK_UPLOAD_STORE.status, upload_id, token)
    except ChunkUploadError as exc:
        _chunk_upload_http_error(exc)
    if status["role"] == "admin":
        require_admin(request)
    status["parallelism"] = CHUNK_UPLOAD_PARALLELISM
    return token, status


def _create_chunk_upload_session(
    *,
    filename: str,
    size: int,
    role: str,
    ttl_hours: Optional[int],
    owner_key: str,
):
    with capacity_guard():
        db = SessionLocal()
        try:
            max_bytes = get_upload_max_mb(db) * 1024 * 1024
            limit_mb = get_total_upload_limit_mb(db)
            used_bytes = active_upload_usage_bytes(db)
            replication_reserved = active_replication_reserved_bytes(db)
        finally:
            db.close()

        chunk_reserved = CHUNK_UPLOAD_STORE.reserved_bytes()
        total_sessions, owned_sessions = CHUNK_UPLOAD_STORE.active_session_counts(owner_key)
        if total_sessions >= CHUNK_UPLOAD_MAX_ACTIVE_SESSIONS:
            raise ChunkUploadError(429, "当前进行中的上传会话过多，请稍后再试")
        if owned_sessions >= CHUNK_UPLOAD_MAX_SESSIONS_PER_CLIENT:
            raise ChunkUploadError(429, "当前来源进行中的上传会话过多，请先完成或取消已有上传")
        if limit_mb > 0:
            limit_bytes = limit_mb * 1024 * 1024
            if used_bytes + replication_reserved + chunk_reserved + size > limit_bytes:
                raise ChunkUploadError(400, "上传失败：已超过上传总容量限制")

        disk_free = shutil.disk_usage(CHUNK_UPLOAD_DIR).free
        disk_reserve = max(
            CHUNK_UPLOAD_DISK_RESERVE_MB * 1024 * 1024,
            LAN_REPLICATION.disk_reserve_bytes,
        )
        if disk_free - disk_reserve - chunk_reserved - replication_reserved < size:
            raise ChunkUploadError(507, "服务器磁盘空间不足，无法建立上传会话")

        return CHUNK_UPLOAD_STORE.create(
            filename=filename,
            size=size,
            role=role,
            ttl_hours=ttl_hours,
            max_bytes=max_bytes,
            owner_key=owner_key,
        )


def _chunk_completion_space_error(current_size: int, assembled_ready: bool) -> Optional[str]:
    with capacity_guard():
        db = SessionLocal()
        try:
            replication_reserved = active_replication_reserved_bytes(db)
        finally:
            db.close()
        other_chunk_reserved = max(0, CHUNK_UPLOAD_STORE.reserved_bytes() - current_size)
        disk_reserve = max(
            CHUNK_UPLOAD_DISK_RESERVE_MB * 1024 * 1024,
            LAN_REPLICATION.disk_reserve_bytes,
        )
        data_free = shutil.disk_usage(CHUNK_UPLOAD_DIR).free
        shared_reservations = disk_reserve + replication_reserved + other_chunk_reserved
        same_device = os.stat(CHUNK_UPLOAD_DIR).st_dev == os.stat(TMP_DIR).st_dev
        if same_device:
            required_data_bytes = current_size + (0 if assembled_ready else current_size)
        else:
            required_data_bytes = 0 if assembled_ready else current_size
        if data_free - shared_reservations < required_data_bytes:
            return "服务器磁盘空间不足，无法合并并处理上传文件"
        if not same_device and shutil.disk_usage(TMP_DIR).free - disk_reserve < current_size:
            return "服务器临时空间不足，无法处理上传文件"
        return None


@app.post("/api/chunked-uploads", status_code=201)
async def create_chunk_upload(request: Request):
    try:
        request_body = bytearray()
        async for block in request.stream():
            request_body.extend(block)
            if len(request_body) > 16 * 1024:
                raise HTTPException(status_code=413, detail="请求体过大")
        payload = json.loads(request_body)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="请求体必须是 JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")

    original_name, _ = _split_supported_upload(str(payload.get("filename", "")))
    if len(original_name.encode("utf-8")) > 240:
        raise HTTPException(status_code=400, detail="文件名过长")
    try:
        size = int(payload.get("size", 0))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="文件大小非法") from exc

    role = str(payload.get("role", "guest"))
    ttl_hours = None
    if role == "admin":
        require_admin(request)
        try:
            ttl_hours = int(payload.get("ttl_hours", 0))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="有效期非法") from exc
        if ttl_hours < 0:
            raise HTTPException(status_code=400, detail="有效期不能小于 0 小时")
    elif role != "guest":
        raise HTTPException(status_code=400, detail="上传角色非法")

    try:
        status = await asyncio.to_thread(
            _create_chunk_upload_session,
            filename=original_name,
            size=size,
            role=role,
            ttl_hours=ttl_hours,
            owner_key=request.client.host if request.client else "unknown",
        )
    except ChunkUploadError as exc:
        _chunk_upload_http_error(exc)
    status["parallelism"] = CHUNK_UPLOAD_PARALLELISM
    status["expires_after_hours"] = CHUNK_UPLOAD_MAX_AGE_HOURS
    return status


@app.get("/api/chunked-uploads/{upload_id}")
async def chunk_upload_status(request: Request, upload_id: str):
    _, status = await _authorized_chunk_upload(request, upload_id)
    return status


@app.put("/api/chunked-uploads/{upload_id}/chunks/{chunk_index}")
async def upload_chunk(request: Request, upload_id: str, chunk_index: int):
    token, status = await _authorized_chunk_upload(request, upload_id)
    if status["status"] not in {"uploading", "failed"}:
        raise HTTPException(status_code=409, detail="当前上传会话不能接收分片")
    if chunk_index < 0 or chunk_index >= status["total_chunks"]:
        raise HTTPException(status_code=404, detail="分片序号超出范围")
    if chunk_index == status["total_chunks"] - 1:
        expected_size = status["size"] - chunk_index * status["chunk_size"]
    else:
        expected_size = status["chunk_size"]

    blocks = []
    received = 0
    async for block in request.stream():
        if not block:
            continue
        received += len(block)
        if received > expected_size:
            raise HTTPException(status_code=400, detail="分片大小超过预期")
        blocks.append(block)
    try:
        return await asyncio.to_thread(
            CHUNK_UPLOAD_STORE.write_chunk,
            upload_id,
            token,
            chunk_index,
            iter(blocks),
        )
    except ChunkUploadError as exc:
        _chunk_upload_http_error(exc)


@app.post("/api/chunked-uploads/{upload_id}/complete")
async def complete_chunk_upload(request: Request, upload_id: str):
    token, status = await _authorized_chunk_upload(request, upload_id)
    if status["status"] == "completed":
        return status["result"]
    if status["status"] == "processing":
        return JSONResponse(status_code=202, content={"ok": True, "status": "processing"})

    owns_processing = False
    processing_finished = False
    try:
        space_error = await asyncio.to_thread(
            _chunk_completion_space_error,
            status["size"],
            bool(status.get("assembled")),
        )
        if space_error:
            raise HTTPException(status_code=507, detail=space_error)

        processing = await asyncio.to_thread(CHUNK_UPLOAD_STORE.begin_processing, upload_id, token)
        if processing["status"] == "completed":
            return processing["result"]
        owns_processing = True
        assembled_path, _ = await asyncio.to_thread(CHUNK_UPLOAD_STORE.assemble, upload_id, token)
        with open(assembled_path, "rb") as source:
            upload_file = UploadFile(filename=status["filename"], file=source)
            uploads, results, _ = await _handle_upload(
                request,
                upload_file,
                role=status["role"],
                ttl_hours=status.get("ttl_hours"),
                render_error=False,
                current_chunk_reservation=status["size"],
            )
        if not uploads:
            failed = results.get("failed", [])
            detail = failed[0].get("error", "没有成功处理任何 VPK") if failed else "没有成功处理任何 VPK"
            await asyncio.to_thread(CHUNK_UPLOAD_STORE.mark_failed, upload_id, token, detail)
            raise HTTPException(status_code=400, detail=detail)

        redirect_url = None
        if status["role"] == "admin" and not results["failed"]:
            redirect_url = "/admin"
        elif len(uploads) == 1 and not results["failed"]:
            redirect_url = f"/detail/{uploads[0].id}"
        result = {
            "ok": True,
            "status": "completed",
            "uploaded": results["uploaded"],
            "failed": results["failed"],
            "redirect_url": redirect_url,
        }
        await asyncio.to_thread(CHUNK_UPLOAD_STORE.mark_completed, upload_id, token, result)
        processing_finished = True
        return result
    except asyncio.CancelledError:
        if owns_processing and not processing_finished:
            try:
                await asyncio.shield(asyncio.to_thread(
                    CHUNK_UPLOAD_STORE.mark_failed,
                    upload_id,
                    token,
                    "服务器处理被中断，可以重新完成上传",
                ))
            except ChunkUploadError:
                pass
        raise
    except HTTPException as exc:
        try:
            detail = exc.detail if isinstance(exc.detail, str) else "服务器处理失败"
            await asyncio.to_thread(CHUNK_UPLOAD_STORE.mark_failed, upload_id, token, detail)
        except ChunkUploadError:
            pass
        raise
    except ChunkUploadError as exc:
        if exc.status_code == 409 and "正在处理" in exc.detail:
            return JSONResponse(status_code=202, content={"ok": True, "status": "processing"})
        _chunk_upload_http_error(exc)
    except Exception as exc:
        logger.exception("chunked upload completion failed upload_id=%s", upload_id)
        try:
            await asyncio.to_thread(CHUNK_UPLOAD_STORE.mark_failed, upload_id, token, "服务器处理失败")
        except ChunkUploadError:
            pass
        raise HTTPException(status_code=500, detail="服务器处理失败") from exc


@app.delete("/api/chunked-uploads/{upload_id}")
async def cancel_chunk_upload(request: Request, upload_id: str):
    token, _ = await _authorized_chunk_upload(request, upload_id)
    try:
        await asyncio.to_thread(CHUNK_UPLOAD_STORE.delete, upload_id, token)
    except ChunkUploadError as exc:
        _chunk_upload_http_error(exc)
    return {"ok": True, "status": "cancelled"}


def require_federation_token(request: Request) -> None:
    if not FEDERATION_API_TOKEN:
        raise HTTPException(status_code=503, detail="当前节点未配置 FEDERATION_API_TOKEN")
    client_ip = request.client.host if request.client else ""
    if not client_ip_is_allowed(client_ip, FEDERATION_ALLOWED_CIDRS):
        logger.warning("federation request denied source=%s", client_ip or "unknown")
        raise HTTPException(status_code=403, detail="当前来源地址不允许访问节点聚合 API")
    if not token_is_valid(request.headers.get("Authorization"), FEDERATION_API_TOKEN):
        raise HTTPException(status_code=401, detail="节点 API Token 无效")


def require_lan_peer(request: Request) -> str:
    if not LAN_REPLICATION.receiver_enabled:
        raise HTTPException(status_code=503, detail="当前节点未启用内网复制接收接口")
    client_ip = request.client.host if request.client else ""
    if not client_ip_is_allowed(client_ip, LAN_REPLICATION.allowed_cidrs):
        logger.warning("lan replication request denied source=%s", client_ip or "unknown")
        raise HTTPException(status_code=403, detail="当前来源地址不允许访问内网复制接口")
    if not token_is_valid(request.headers.get("Authorization"), LAN_REPLICATION.token):
        raise HTTPException(status_code=401, detail="内网复制 Token 无效")
    if not secrets.compare_digest(request.headers.get("X-LAN-Group", ""), LAN_REPLICATION.group):
        raise HTTPException(status_code=409, detail="内网组不一致")
    source_node_id = request.headers.get("X-LAN-Node", "").strip()
    if not source_node_id or len(source_node_id) > 128:
        raise HTTPException(status_code=400, detail="来源节点 ID 无效")
    return source_node_id


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _replication_manifest_items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="复制预检请求必须是 JSON 对象")
    raw_items = payload.get("artifacts", [])
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 50:
        raise HTTPException(status_code=400, detail="复制文件清单数量必须在 1 到 50 之间")

    db = SessionLocal()
    try:
        max_bytes = get_upload_max_mb(db) * 1024 * 1024
    finally:
        db.close()

    items: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    for index, raw_item in enumerate(raw_items, start=1):
        if not isinstance(raw_item, dict):
            raise HTTPException(status_code=400, detail=f"复制文件清单第 {index} 项无效")
        original_name = _ensure_vpk_filename(str(raw_item.get("original_name", "")))
        stored_name = _ensure_vpk_filename(str(raw_item.get("stored_name", original_name)))
        sha256 = str(raw_item.get("sha256", "")).strip().lower()
        try:
            size = int(raw_item.get("size", 0))
            source_upload_id = int(raw_item.get("source_upload_id", 0))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"复制文件清单第 {index} 项大小或 ID 无效") from exc
        if not _valid_sha256(sha256):
            raise HTTPException(status_code=400, detail=f"复制文件清单第 {index} 项 SHA-256 无效")
        if sha256 in seen_hashes:
            raise HTTPException(status_code=400, detail=f"复制文件清单第 {index} 项重复")
        if size < 1 or size > max_bytes:
            raise HTTPException(status_code=400, detail=f"复制文件 {original_name} 大小超出单文件限制")
        if source_upload_id < 1:
            raise HTTPException(status_code=400, detail=f"复制文件 {original_name} 来源 ID 无效")
        seen_hashes.add(sha256)
        items.append({
            "source_upload_id": source_upload_id,
            "original_name": original_name,
            "stored_name": stored_name,
            "size": size,
            "sha256": sha256,
            "status": "pending",
        })
    return items


def _load_reservation_manifest(row: ReplicationReservation) -> dict[str, Any]:
    try:
        payload = json.loads(row.manifest)
    except (TypeError, ValueError):
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        raise HTTPException(status_code=500, detail="容量预留记录损坏")
    return payload


def _save_reservation_manifest(row: ReplicationReservation, manifest: dict[str, Any]) -> None:
    row.manifest = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))


def _reservation_item(
    row: ReplicationReservation,
    sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _load_reservation_manifest(row)
    for item in manifest["artifacts"]:
        if isinstance(item, dict) and str(item.get("sha256", "")) == sha256:
            return manifest, item
    raise HTTPException(status_code=404, detail="容量预留中没有这个文件")


def _public_replication_storage(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "limit_bytes": int(snapshot["limit_bytes"]),
        "used_bytes": int(snapshot["used_bytes"]),
        "reserved_bytes": int(snapshot["reserved_bytes"]),
        "available_bytes": int(snapshot["available_bytes"]),
        "disk_free_bytes": int(snapshot["disk_free_bytes"]),
        "disk_reserve_bytes": int(snapshot["disk_reserve_bytes"]),
    }


def _replication_preflight(source_node_id: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="复制预检请求必须是 JSON 对象")
    if str(payload.get("source_node_id", "")).strip() != source_node_id:
        raise HTTPException(status_code=400, detail="来源节点 ID 与请求头不一致")
    if str(payload.get("lan_group", "")).strip() != LAN_REPLICATION.group:
        raise HTTPException(status_code=409, detail="内网组不一致")
    items = _replication_manifest_items(payload)
    requested_ttl = payload.get("reservation_ttl_seconds", LAN_REPLICATION.reservation_ttl_seconds)
    try:
        ttl_seconds = int(requested_ttl)
    except (TypeError, ValueError):
        ttl_seconds = LAN_REPLICATION.reservation_ttl_seconds
    ttl_seconds = max(300, min(LAN_REPLICATION.reservation_ttl_seconds, ttl_seconds))

    db = SessionLocal()
    try:
        with capacity_guard():
            already_present = []
            missing = []
            for item in items:
                existing = _find_active_upload_by_sha256(db, item["sha256"], item["size"])
                if existing is None:
                    missing.append(item)
                else:
                    already_present.append(_upload_item_result(existing))
            db.commit()

            snapshot = replication_storage_snapshot(db)
            required_bytes = sum(int(item["size"]) for item in missing)
            if not missing:
                return {
                    "ok": True,
                    "status": "already_present",
                    "required_bytes": 0,
                    "accepted": [],
                    "already_present": already_present,
                    "storage": _public_replication_storage(snapshot),
                }
            if required_bytes > int(snapshot["available_bytes"]):
                return {
                    "ok": True,
                    "status": "insufficient_capacity",
                    "detail": "目标节点容量不足，已跳过本次内网复制。",
                    "required_bytes": required_bytes,
                    "accepted": [],
                    "already_present": already_present,
                    "storage": _public_replication_storage(snapshot),
                }

            reservation_id = secrets.token_hex(24)
            created_at = now_utc()
            manifest = {
                "source_node_id": source_node_id,
                "artifacts": missing,
            }
            db.add(ReplicationReservation(
                id=reservation_id,
                source_node_id=source_node_id,
                lan_group=LAN_REPLICATION.group,
                manifest=json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
                reserved_bytes=required_bytes,
                created_at=created_at,
                expires_at=created_at + timedelta(seconds=ttl_seconds),
                status="active",
            ))
            db.commit()
            snapshot = replication_storage_snapshot(db)
            return {
                "ok": True,
                "status": "reserved",
                "reservation_id": reservation_id,
                "expires_at": (created_at + timedelta(seconds=ttl_seconds)).isoformat(),
                "required_bytes": required_bytes,
                "accepted": [{key: item[key] for key in ("sha256", "size", "original_name")} for item in missing],
                "already_present": already_present,
                "storage": _public_replication_storage(snapshot),
            }
    finally:
        db.close()


def _ensure_active_reservation(
    db,
    reservation_id: str,
    source_node_id: str,
) -> ReplicationReservation:
    row = db.get(ReplicationReservation, reservation_id)
    if row is None or row.source_node_id != source_node_id or row.lan_group != LAN_REPLICATION.group:
        raise HTTPException(status_code=404, detail="容量预留不存在")
    expires_at = _as_aware_utc(row.expires_at)
    if row.status != "active" or expires_at is None or expires_at <= now_utc():
        if row.status == "active":
            row.status = "expired"
            row.reserved_bytes = 0
            db.commit()
        raise HTTPException(status_code=409, detail="容量预留已经失效")
    return row


def _replication_artifacts_for_uploads(uploads: list[Upload]) -> list[ReplicationArtifact]:
    artifacts: list[ReplicationArtifact] = []
    for upload in uploads:
        path = os.path.join(UPLOAD_DIR, upload.stored_name)
        if not os.path.isfile(path):
            logger.error("replication source file missing upload_id=%s path=%s", upload.id, path)
            continue
        sha256 = str(upload.sha256 or "").lower()
        if not _valid_sha256(sha256):
            sha256 = _sha256_file(path)
        artifacts.append(ReplicationArtifact(
            upload_id=int(upload.id),
            original_name=str(upload.original_name),
            stored_name=str(upload.stored_name),
            path=path,
            size=int(upload.size or os.path.getsize(path)),
            sha256=sha256,
        ))
    return artifacts


def get_docker_manager() -> DockerManager:
    try:
        return DockerManager()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"无法连接 Docker：{exc}") from exc


def delete_upload_item(item_id: int) -> None:
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="上传文件不存在")
        path = os.path.join(UPLOAD_DIR, item.stored_name)
        if os.path.exists(path):
            os.remove(path)
        item.status = "deleted"
        db.commit()
    finally:
        db.close()


async def receive_lan_replication_upload(
    request: Request,
    source_node_id: str,
    reservation_id: str,
    source_upload_id: int,
    original_name: str,
    expected_sha256: str,
    expected_size: int,
    file: UploadFile,
) -> dict[str, Any]:
    reservation_id = reservation_id.strip().lower()
    expected_sha256 = expected_sha256.strip().lower()
    original_name = _ensure_vpk_filename(original_name)
    if len(reservation_id) != 48 or not all(character in "0123456789abcdef" for character in reservation_id):
        raise HTTPException(status_code=400, detail="容量预留 ID 无效")
    if not _valid_sha256(expected_sha256):
        raise HTTPException(status_code=400, detail="复制文件 SHA-256 无效")
    if expected_size < 1 or source_upload_id < 1:
        raise HTTPException(status_code=400, detail="复制文件大小或来源 ID 无效")
    _ensure_vpk_filename(file.filename or "upload.vpk")

    db = SessionLocal()
    try:
        row = _ensure_active_reservation(db, reservation_id, source_node_id)
        _, item = _reservation_item(row, expected_sha256)
        if (
            int(item.get("source_upload_id", 0)) != source_upload_id
            or str(item.get("original_name", "")) != original_name
            or int(item.get("size", 0)) != expected_size
        ):
            raise HTTPException(status_code=409, detail="复制文件与容量预留清单不一致")
        if str(item.get("status", "")) != "pending":
            target_upload_id = int(item.get("target_upload_id", 0))
            existing = db.get(Upload, target_upload_id) if target_upload_id else None
            return {
                "ok": True,
                "status": "already_present",
                "upload": _upload_item_result(existing) if existing else {
                    "original_name": original_name,
                    "sha256": expected_sha256,
                    "size": expected_size,
                },
            }
    finally:
        db.close()

    tmp_path = os.path.join(UPLOAD_DIR, f".lan-{secrets.token_hex(12)}.part")
    read_bytes = 0
    digest = hashlib.sha256()
    try:
        with open(tmp_path, "xb") as output:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                read_bytes += len(chunk)
                if read_bytes > expected_size:
                    raise HTTPException(status_code=400, detail="复制文件大小超过预留值")
                digest.update(chunk)
                output.write(chunk)
        if read_bytes != expected_size:
            raise HTTPException(status_code=400, detail="复制文件大小与预留值不一致")
        if not secrets.compare_digest(digest.hexdigest(), expected_sha256):
            raise HTTPException(status_code=400, detail="复制文件 SHA-256 校验失败")

        try:
            validation: ValidationResult = validate_vpk(
                tmp_path,
                RULES_FILE,
                max_size_mb_override=get_upload_max_mb(),
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"复制的 VPK 读取失败：{exc}") from exc
        if not validation.ok:
            raise HTTPException(status_code=400, detail="复制的 VPK 不符合当前节点规则")

        final_path = ""
        db = SessionLocal()
        try:
            with capacity_guard():
                row = _ensure_active_reservation(db, reservation_id, source_node_id)
                manifest, item = _reservation_item(row, expected_sha256)
                if str(item.get("status", "")) != "pending":
                    target_upload_id = int(item.get("target_upload_id", 0))
                    existing = db.get(Upload, target_upload_id) if target_upload_id else None
                    return {
                        "ok": True,
                        "status": "already_present",
                        "upload": _upload_item_result(existing) if existing else {
                            "original_name": original_name,
                            "sha256": expected_sha256,
                            "size": expected_size,
                        },
                    }

                existing = _find_active_upload_by_sha256(db, expected_sha256, expected_size)
                if existing is not None:
                    item["status"] = "already_present"
                    item["target_upload_id"] = existing.id
                    row.reserved_bytes = max(0, int(row.reserved_bytes or 0) - expected_size)
                    _save_reservation_manifest(row, manifest)
                    db.commit()
                    return {
                        "ok": True,
                        "status": "already_present",
                        "upload": _upload_item_result(existing),
                    }

                work_base = _safe_base_no_ext(original_name)
                final_name = _unique_server_filename(db, work_base)
                final_path = os.path.join(UPLOAD_DIR, final_name)
                os.replace(tmp_path, final_path)

                report = {
                    "upload_source": {
                        "source": "lan_replication",
                        "source_node_id": source_node_id,
                        "source_upload_id": source_upload_id,
                        "received_sha256": expected_sha256,
                        "received_size": expected_size,
                    },
                    "validation": validation.to_dict(),
                    "replication": {
                        "lan_group": LAN_REPLICATION.group,
                        "received_at": now_utc().isoformat(),
                    },
                }
                upload = Upload(
                    original_name=original_name,
                    stored_name=final_name,
                    sha256=expected_sha256,
                    size=expected_size,
                    role="admin",
                    created_at=now_utc(),
                    expires_at=None,
                    vpk_valid=True,
                    vpk_report=json.dumps(report, ensure_ascii=False),
                    status="active",
                    uploader_ip=f"lan:{source_node_id}"[:64],
                )
                db.add(upload)
                db.flush()
                item["status"] = "stored"
                item["target_upload_id"] = upload.id
                row.reserved_bytes = max(0, int(row.reserved_bytes or 0) - expected_size)
                _save_reservation_manifest(row, manifest)
                db.commit()
                db.refresh(upload)
                return {"ok": True, "status": "stored", "upload": _upload_item_result(upload)}
        except Exception:
            if final_path:
                _remove_file_quietly(final_path)
            db.rollback()
            raise
        finally:
            db.close()
    finally:
        _remove_file_quietly(tmp_path)


def complete_lan_replication_reservation(source_node_id: str, reservation_id: str) -> dict[str, Any]:
    db = SessionLocal()
    try:
        with capacity_guard():
            row = db.get(ReplicationReservation, reservation_id)
            if row is None or row.source_node_id != source_node_id or row.lan_group != LAN_REPLICATION.group:
                raise HTTPException(status_code=404, detail="容量预留不存在")
            manifest = _load_reservation_manifest(row)
            pending_count = 0
            for item in manifest["artifacts"]:
                if isinstance(item, dict) and item.get("status") == "pending":
                    item["status"] = "released"
                    pending_count += 1
            row.reserved_bytes = 0
            row.status = "completed" if pending_count == 0 else "partial"
            _save_reservation_manifest(row, manifest)
            db.commit()
            return {
                "ok": True,
                "status": row.status,
                "released_item_count": pending_count,
            }
    finally:
        db.close()


def federation_summary_payload() -> dict:
    db = SessionLocal()
    try:
        items = (
            db.query(Upload)
            .filter(Upload.status == "active")
            .order_by(Upload.created_at.desc())
            .limit(50)
            .all()
        )
        site = {
            "name": INSTANCE_NAME,
            "upload_count": db.query(Upload).filter(Upload.status == "active").count(),
            "lan_replication": LAN_REPLICATION.public_status(),
            "workshop": workshop_public_status(db),
            **storage_context(db),
        }
        uploads = [{
            "id": item.id,
            "name": item.original_name,
            "size": item.size or 0,
            "role": item.role,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "detail_path": f"/detail/{item.id}",
            "download_path": f"/d/{item.id}",
        } for item in items]
    finally:
        db.close()

    containers = []
    docker_error = None
    try:
        containers = get_docker_manager().list_containers()
    except Exception as exc:
        docker_error = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
    return {
        "generated_at": now_utc().isoformat(),
        "site": site,
        "uploads": uploads,
        "containers": containers,
        "docker_error": docker_error,
    }


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})


@app.post("/admin/login")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        resp = RedirectResponse(url="/admin", status_code=302)
        set_session(resp, {"role": "admin", "user": username})
        return resp
    return templates.TemplateResponse("admin_login.html", {"request": request, "error": "用户名或密码错误"})


@app.get("/admin/logout")
async def admin_logout(request: Request):
    resp = RedirectResponse(url="/admin/login", status_code=302)
    clear_session(resp)
    return resp


@app.get("/admin", response_class=HTMLResponse)
async def admin_home(request: Request):
    require_admin(request)
    q = request.query_params.get("q")
    settings_saved = request.query_params.get("settings_saved") == "1"
    return templates.TemplateResponse("admin_dashboard.html", admin_context(request, q=q, settings_saved=settings_saved))


@app.get("/admin/docker", response_class=HTMLResponse)
async def docker_dashboard(request: Request):
    require_admin(request)
    return templates.TemplateResponse("docker_dashboard.html", {"request": request})


@app.get("/api/admin/docker/containers")
async def docker_containers(request: Request):
    require_admin(request)
    try:
        items = get_docker_manager().list_containers()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"读取 Docker 数据失败：{exc}") from exc
    return {"generated_at": now_utc().isoformat(), "containers": items}


@app.post("/api/admin/docker/containers/{container_id}/exec")
async def docker_container_exec(request: Request, container_id: str):
    require_admin(request)
    try:
        payload = await request.json()
        command = str(payload.get("command", "")) if isinstance(payload, dict) else ""
        result = get_docker_manager().exec_command(container_id, command)
        logger.info("admin docker exec container=%s exit=%s", container_id, result["exit_code"])
        return {"ok": True, **result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"容器命令执行失败：{exc}") from exc


@app.post("/api/admin/docker/containers/{container_id}/{action}")
async def docker_container_action(request: Request, container_id: str, action: str):
    require_admin(request)
    try:
        get_docker_manager().action(container_id, action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"容器操作失败：{exc}") from exc
    return {"ok": True, "action": action}


@app.get("/api/admin/docker/containers/{container_id}/files")
async def docker_container_files(request: Request, container_id: str, path: str = "/"):
    require_admin(request)
    try:
        return get_docker_manager().list_files(container_id, path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"读取容器文件失败：{exc}") from exc


@app.get("/api/federation/summary")
def federation_summary(request: Request):
    require_federation_token(request)
    return federation_summary_payload()


@app.get("/api/lan/replication/capabilities")
def lan_replication_capabilities(request: Request):
    require_lan_peer(request)
    db = SessionLocal()
    try:
        storage = _public_replication_storage(replication_storage_snapshot(db))
    finally:
        db.close()
    return {
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "node_id": LAN_REPLICATION.node_id,
        "lan_group": LAN_REPLICATION.group,
        "instance_name": INSTANCE_NAME,
        "storage": storage,
    }


@app.post("/api/lan/replication/preflight")
async def lan_replication_preflight(request: Request):
    source_node_id = require_lan_peer(request)
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="复制预检请求不是合法 JSON") from exc
    return _replication_preflight(source_node_id, payload)


@app.post("/api/lan/replication/uploads")
async def lan_replication_upload(
    request: Request,
    file: UploadFile,
    reservation_id: str = Form(...),
    source_node_id: str = Form(...),
    source_upload_id: int = Form(...),
    original_name: str = Form(...),
    sha256: str = Form(...),
    size: int = Form(...),
):
    authenticated_source = require_lan_peer(request)
    if source_node_id.strip() != authenticated_source:
        raise HTTPException(status_code=400, detail="来源节点 ID 与请求头不一致")
    return await receive_lan_replication_upload(
        request=request,
        source_node_id=authenticated_source,
        reservation_id=reservation_id,
        source_upload_id=source_upload_id,
        original_name=original_name,
        expected_sha256=sha256,
        expected_size=size,
        file=file,
    )


@app.post("/api/lan/replication/reservations/{reservation_id}/complete")
def lan_replication_complete(request: Request, reservation_id: str):
    source_node_id = require_lan_peer(request)
    return complete_lan_replication_reservation(source_node_id, reservation_id.strip().lower())


@app.post("/api/federation/uploads")
async def federation_upload(request: Request, file: UploadFile, role: str = Form("admin")):
    require_federation_token(request)
    # 缺省仍按管理员处理（聚合后台的手动上传）；NewAnneWeb 替玩家部署时传 guest。
    role = (role or "admin").strip().lower()
    if role not in WORKSHOP_ROLES:
        raise HTTPException(status_code=400, detail="role 只能是 guest 或 admin")
    uploads, results, _ = await _handle_upload(
        request,
        file,
        role=role,
        ttl_hours=None,
        render_error=False,
    )
    if not uploads:
        failed = results.get("failed", [])
        detail = failed[0].get("error", "没有成功处理任何 VPK") if failed else "没有成功处理任何 VPK"
        return JSONResponse(
            status_code=400,
            content={"ok": False, "detail": detail, **results},
        )
    artifacts = _replication_artifacts_for_uploads(uploads)
    replication = await replicate_artifacts(LAN_REPLICATION, artifacts)
    logger.info(
        "lan replication source=%s peers=%s completed=%s skipped=%s failed=%s",
        LAN_REPLICATION.node_id or "disabled",
        len(replication.get("peers", [])),
        replication.get("completed_peer_count", 0),
        replication.get("skipped_peer_count", 0),
        replication.get("failed_peer_count", 0),
    )
    return {"ok": True, **results, "replication": replication}


@app.post("/api/federation/docker/{container_id}/exec")
async def federation_docker_exec(request: Request, container_id: str):
    require_federation_token(request)
    try:
        payload = await request.json()
        command = str(payload.get("command", "")) if isinstance(payload, dict) else ""
        result = get_docker_manager().exec_command(container_id, command)
        logger.info("federation docker exec container=%s exit=%s", container_id, result["exit_code"])
        return {"ok": True, **result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"容器命令执行失败：{exc}") from exc


@app.post("/api/federation/docker/{container_id}/{action}")
def federation_docker_action(request: Request, container_id: str, action: str):
    require_federation_token(request)
    try:
        get_docker_manager().action(container_id, action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"容器操作失败：{exc}") from exc
    return {"ok": True, "action": action}


@app.get("/api/federation/docker/{container_id}/files")
def federation_docker_files(request: Request, container_id: str, path: str = "/"):
    require_federation_token(request)
    try:
        return get_docker_manager().list_files(container_id, path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"读取容器文件失败：{exc}") from exc


@app.post("/api/federation/uploads/{item_id}/delete")
def federation_upload_delete(request: Request, item_id: int):
    require_federation_token(request)
    delete_upload_item(item_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Steam 创意工坊导入
#
# NewAnneWeb 负责面向用户的鉴权和界面，本节点只暴露受 FEDERATION_API_TOKEN 保护的
# 异步任务接口：POST 建任务立即返回 job_id，GET 轮询进度。下载完成的 VPK 直接进入
# 既有的"校验 → 服务器版 → 入库 → 内网复制"流水线。
# ---------------------------------------------------------------------------

_WORKSHOP_NAME_BAD_CHARS = set('\\/:*?"<>|')


def workshop_public_status(db) -> dict[str, Any]:
    status = WORKSHOP.public_status()
    status["active_jobs"] = db.query(WorkshopJob).filter(
        WorkshopJob.status.in_(WORKSHOP_JOB_ACTIVE_STATES)
    ).count()
    # steamcmd_available 只说明镜像里有它；能不能真的用要看连不连得上自更新服务器。
    ready, reason = WORKSHOP_STEAMCMD.readiness()
    status["steamcmd_ready"] = ready
    status["steamcmd_error"] = "" if ready else reason
    # 创意工坊导入默认按普通用户（无管理员）的规则入库：保存时间和单文件上限都跟网页上传一致。
    status["default_role"] = WORKSHOP_DEFAULT_ROLE
    status["upload_max_mb"] = get_upload_max_mb(db)
    status["guest_ttl_hours"] = get_guest_ttl_hours(db)
    return status


def _workshop_json(raw: Optional[str], fallback):
    try:
        value = json.loads(raw) if raw else fallback
    except (TypeError, ValueError):
        return fallback
    return value


def _workshop_job_items(job: WorkshopJob) -> list[dict[str, Any]]:
    items = _workshop_json(job.items, [])
    return items if isinstance(items, list) else []


def _workshop_job_payload(job: WorkshopJob) -> dict[str, Any]:
    items = _workshop_job_items(job)
    counts: dict[str, int] = {}
    uploads: list[dict[str, Any]] = []
    for item in items:
        state = str(item.get("state") or "pending")
        counts[state] = counts.get(state, 0) + 1
        uploads.extend(item.get("uploads") or [])
    request_payload = _workshop_json(job.request, {})
    return {
        "job_id": job.id,
        "status": job.status,
        "role": job.role,
        "ttl_hours": job.ttl_hours,
        "request": request_payload if isinstance(request_payload, dict) else {},
        "items": items,
        "item_total": len(items),
        "item_counts": counts,
        "upload_count": len(uploads),
        "uploads": uploads,
        "replication": _workshop_json(job.replication, None),
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "status_url": _public_url(f"/api/federation/workshop/{job.id}"),
    }


def _save_workshop_items(job_id: str, items: list[dict[str, Any]]) -> None:
    db = SessionLocal()
    try:
        job = db.get(WorkshopJob, job_id)
        if job is None:
            return
        job.items = json.dumps(items, ensure_ascii=False)
        db.commit()
    finally:
        db.close()


def _finish_workshop_job(job_id: str, status: str, error: Optional[str] = None) -> None:
    db = SessionLocal()
    try:
        job = db.get(WorkshopJob, job_id)
        if job is None:
            return
        job.status = status
        job.error = error
        job.finished_at = now_utc()
        db.commit()
    finally:
        db.close()


def _store_workshop_replication(job_id: str, replication: dict[str, Any]) -> None:
    db = SessionLocal()
    try:
        job = db.get(WorkshopJob, job_id)
        if job is None:
            return
        job.replication = json.dumps(replication, ensure_ascii=False)
        db.commit()
    finally:
        db.close()


def _workshop_replication_artifacts(upload_ids: list[int]) -> list[ReplicationArtifact]:
    db = SessionLocal()
    try:
        rows = db.query(Upload).filter(
            Upload.id.in_(upload_ids),
            Upload.status == "active",
        ).all()
        return _replication_artifacts_for_uploads(rows)
    finally:
        db.close()


def _workshop_available_bytes() -> int:
    db = SessionLocal()
    try:
        return int(replication_storage_snapshot(db)["available_bytes"])
    finally:
        db.close()


def _workshop_vpk_filename(
    details: Optional[WorkshopItemDetails],
    workshop_id: str,
    index: int,
    total: int,
) -> str:
    """用创意工坊标题生成 VPK 文件名，附带物品 ID 方便回溯。"""
    title = details.display_title if details is not None else f"workshop_{workshop_id}"
    cleaned = "".join(
        "_" if (ch in _WORKSHOP_NAME_BAD_CHARS or ord(ch) < 32) else ch for ch in title
    )
    cleaned = cleaned.strip().strip(". ")[:120].strip()
    if not cleaned:
        cleaned = f"workshop_{workshop_id}"
    suffix = f"_{index}" if total > 1 else ""
    return f"{cleaned}_{workshop_id}{suffix}.vpk"


def _workshop_stage_downloads(
    workshop_id: str,
    details: Optional[WorkshopItemDetails],
    upload_max_mb: int,
) -> tuple[list[str], str]:
    """把一个创意工坊物品的 VPK 取到 TMP_DIR，返回（本地路径列表，下载方式）。"""
    max_bytes = upload_max_mb * 1024 * 1024

    if details is not None:
        if details.banned:
            raise WorkshopError(f"该物品已被 Steam 封禁：{details.ban_reason or '未说明原因'}")
        if WORKSHOP.enforce_appid and details.consumer_app_id and details.consumer_app_id != WORKSHOP.appid:
            raise WorkshopError(
                f"物品属于 appid {details.consumer_app_id}，本节点只接受 appid {WORKSHOP.appid}"
            )
        # file_size 只有在确实存在老式内容文件时才是 VPK 的大小，否则是预览图大小。
        if details.has_legacy_vpk and details.file_size:
            if details.file_size > max_bytes:
                raise WorkshopError(
                    f"创意工坊文件 {_format_mb(details.file_size)}，超过单文件上限 {upload_max_mb} MB"
                )
            available = _workshop_available_bytes()
            if details.file_size > available:
                raise WorkshopError(
                    f"节点可用容量不足：本次需要 {_format_mb(details.file_size)}，"
                    f"当前可用 {_format_mb(available)}"
                )

    # 旧版 UGC 带真正的 file_url，直接 HTTPS 取回比拉一次 steamcmd 快得多。
    direct_error: Optional[str] = None
    if details is not None and details.has_legacy_vpk and WORKSHOP.direct_download_enabled:
        dest = os.path.join(TMP_DIR, f"workshop_{workshop_id}_{secrets.token_hex(4)}.vpk")
        try:
            download_direct(
                details,
                dest,
                max_bytes,
                WORKSHOP.download_timeout_seconds,
                attempts=WORKSHOP.direct_download_attempts,
            )
            if not looks_like_vpk(dest):
                raise WorkshopError("创意工坊直链返回的不是 VPK 文件")
            return [dest], "direct"
        except WorkshopError as exc:
            _remove_file_quietly(dest)
            direct_error = str(exc)
            logger.warning("workshop direct download failed item=%s error=%s", workshop_id, exc)
            # steamcmd 用不了就别拿它的报错盖掉直链失败的真实原因。
            ready, reason = WORKSHOP_STEAMCMD.readiness(block=True)
            if not ready:
                raise WorkshopError(f"{direct_error}；节点的 steamcmd 也不可用：{reason}") from exc

    try:
        content_dir = WORKSHOP_STEAMCMD.download(workshop_id)
    except WorkshopError as exc:
        if direct_error is not None:
            raise WorkshopError(f"{direct_error}；改用 steamcmd 也失败了：{exc}") from exc
        if details is None:
            raise WorkshopError(f"节点没拿到这个物品的 Steam 信息（连不上 Steam Web API），只能用 steamcmd：{exc}") from exc
        if not details.has_legacy_vpk:
            raise WorkshopError(f"这个物品没有可直接下载的文件，只能用 steamcmd：{exc}") from exc
        raise
    staged: list[str] = []
    try:
        sources = collect_vpk_files(content_dir)
        if not sources:
            raise WorkshopError(f"创意工坊物品里没有 VPK 文件（下载到的是：{describe_files(content_dir)}）")
        for source_path in sources:
            size = os.path.getsize(source_path)
            if size > max_bytes:
                raise WorkshopError(
                    f"{os.path.basename(source_path)} 为 {_format_mb(size)}，"
                    f"超过单文件上限 {upload_max_mb} MB"
                )
            dest = os.path.join(TMP_DIR, f"workshop_{workshop_id}_{secrets.token_hex(4)}.vpk")
            shutil.move(source_path, dest)
            staged.append(dest)
    except Exception:
        for path in staged:
            _remove_file_quietly(path)
        raise
    finally:
        WORKSHOP_STEAMCMD.cleanup(workshop_id)
    return staged, "steamcmd"


def _workshop_import_item(
    job_id: str,
    items: list[dict[str, Any]],
    item: dict[str, Any],
    details: Optional[WorkshopItemDetails],
    role: str,
    ttl_hours: Optional[int],
    upload_max_mb: int,
) -> list[int]:
    """下载并入库单个物品，就地更新 item 状态，返回新建的 Upload id。"""
    workshop_id = item["workshop_id"]
    if details is not None:
        item["title"] = details.display_title
        item["file_size"] = details.file_size
    item["state"] = "downloading"
    _save_workshop_items(job_id, items)

    try:
        staged, download_source = _workshop_stage_downloads(workshop_id, details, upload_max_mb)
    except WorkshopError as exc:
        item["state"] = "failed"
        item["error"] = str(exc)
        return []
    except Exception as exc:
        logger.exception("workshop download crashed item=%s", workshop_id)
        item["state"] = "failed"
        item["error"] = f"下载失败：{exc}"
        return []

    item["download_source"] = download_source
    item["state"] = "processing"
    _save_workshop_items(job_id, items)

    upload_ids: list[int] = []
    failures: list[dict[str, str]] = []
    try:
        for index, tmp_vpk_path in enumerate(staged, start=1):
            display_name = _workshop_vpk_filename(details, workshop_id, index, len(staged))
            try:
                upload_source = {
                    "source": "steam_workshop",
                    "workshop_id": workshop_id,
                    "workshop_title": details.display_title if details is not None else None,
                    "workshop_url": f"https://steamcommunity.com/sharedfiles/filedetails/?id={workshop_id}",
                    "download_source": download_source,
                    "uploaded_name": os.path.basename(tmp_vpk_path),
                    "source_vpk_name": display_name,
                    "uploaded_size": os.path.getsize(tmp_vpk_path),
                    "workshop_vpk_index": index,
                    "workshop_vpk_count": len(staged),
                }
                up, result = _process_vpk_upload(
                    uploader_ip=f"workshop:{workshop_id}"[:64],
                    role=role,
                    ttl_hours=ttl_hours,
                    tmp_vpk_path=tmp_vpk_path,
                    source_vpk_name=display_name,
                    upload_sha256=_sha256_file(tmp_vpk_path),
                    upload_source=upload_source,
                    upload_max_mb=upload_max_mb,
                )
            except HTTPException as exc:
                failures.append({"name": display_name, "error": str(exc.detail)})
                continue
            except Exception as exc:
                logger.exception("workshop vpk processing crashed item=%s", workshop_id)
                failures.append({"name": display_name, "error": f"处理失败：{exc}"})
                continue
            if up is None:
                failures.append({"name": display_name, "error": result.get("error", "VPK 不符合要求")})
                if result.get("report"):
                    item["report"] = result["report"]
                continue
            upload_ids.append(int(up.id))
            item["uploads"].append(result)
    finally:
        # _process_vpk_upload 会消费掉临时文件，这里只兜底清理没走到的路径。
        for tmp_vpk_path in staged:
            _remove_file_quietly(tmp_vpk_path)

    item["failed"] = failures
    if item["uploads"]:
        item["state"] = "succeeded" if not failures else "partial"
    else:
        item["state"] = "failed"
        item["error"] = failures[0]["error"] if failures else "没有生成服务器版 VPK"
    return upload_ids


def _run_workshop_job(job_id: str) -> list[int]:
    db = SessionLocal()
    try:
        job = db.get(WorkshopJob, job_id)
        if job is None:
            logger.warning("workshop job vanished job_id=%s", job_id)
            return []
        job.status = "running"
        job.started_at = now_utc()
        db.commit()
        role = str(job.role or "admin")
        ttl_hours = job.ttl_hours
        request_payload = _workshop_json(job.request, {})
    finally:
        db.close()

    if not isinstance(request_payload, dict):
        request_payload = {}

    items: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_item(workshop_id: str, origin: str) -> None:
        if workshop_id in seen or len(items) >= MAX_ITEMS_PER_JOB:
            return
        seen.add(workshop_id)
        items.append({
            "workshop_id": workshop_id,
            "origin": origin,
            "state": "pending",
            "title": None,
            "uploads": [],
            "error": None,
        })

    for workshop_id in request_payload.get("ids") or []:
        add_item(str(workshop_id), "item")

    notes: list[str] = []
    for collection_id in request_payload.get("collections") or []:
        collection_id = str(collection_id)
        try:
            members = WORKSHOP_API.expand_collection(collection_id)
        except WorkshopError as exc:
            notes.append(f"合集 {collection_id}：{exc}")
            continue
        if not members:
            notes.append(f"合集 {collection_id}：没有读到成员，可能不是合集或者未公开")
            continue
        for member in members:
            add_item(member, f"collection:{collection_id}")

    if not items:
        _finish_workshop_job(job_id, "failed", "；".join(notes) or "没有可处理的创意工坊物品")
        return []

    _save_workshop_items(job_id, items)

    details_by_id: dict[str, WorkshopItemDetails] = {}
    workshop_ids = [item["workshop_id"] for item in items]

    # 上游带来的元数据优先：它那边能访问 Steam Web API，节点这边未必能。
    supplied = request_payload.get("details")
    supplied = supplied if isinstance(supplied, dict) else {}
    for workshop_id in workshop_ids:
        candidate = details_from_payload(workshop_id, supplied.get(workshop_id), WORKSHOP.appid)
        if candidate is not None:
            details_by_id[workshop_id] = candidate
    if details_by_id:
        logger.info(
            "workshop job %s using caller-supplied details for %s/%s items",
            job_id, len(details_by_id), len(workshop_ids),
        )

    pending_ids = [item_id for item_id in workshop_ids if item_id not in details_by_id]
    for start in range(0, len(pending_ids), 50):
        chunk = pending_ids[start:start + 50]
        try:
            details_by_id.update(WORKSHOP_API.get_details(chunk))
        except WorkshopError as exc:
            # 拿不到元数据不阻断下载，只是少了标题、大小预检和直链加速。
            logger.warning("workshop details lookup failed: %s", exc)
            notes.append(f"读取物品信息失败：{exc}")

    db = SessionLocal()
    try:
        upload_max_mb = get_upload_max_mb(db)
    finally:
        db.close()

    upload_ids: list[int] = []
    for item in items:
        upload_ids.extend(_workshop_import_item(
            job_id=job_id,
            items=items,
            item=item,
            details=details_by_id.get(item["workshop_id"]),
            role=role,
            ttl_hours=ttl_hours,
            upload_max_mb=upload_max_mb,
        ))
        _save_workshop_items(job_id, items)

    done = sum(1 for item in items if item["state"] in ("succeeded", "partial"))
    if done == len(items):
        status = "succeeded"
    elif done:
        status = "partial"
    else:
        status = "failed"
    _finish_workshop_job(job_id, status, "；".join(notes) or None)
    logger.info(
        "workshop job finished job_id=%s status=%s items=%s uploads=%s",
        job_id, status, len(items), len(upload_ids),
    )
    return upload_ids


async def _workshop_worker_loop() -> None:
    queue = _workshop_queue
    if queue is None:
        return
    while True:
        job_id = await queue.get()
        try:
            upload_ids = await asyncio.to_thread(_run_workshop_job, job_id)
            if upload_ids:
                artifacts = await asyncio.to_thread(_workshop_replication_artifacts, upload_ids)
                replication = await replicate_artifacts(LAN_REPLICATION, artifacts)
                await asyncio.to_thread(_store_workshop_replication, job_id, replication)
                logger.info(
                    "workshop lan replication job=%s peers=%s completed=%s skipped=%s failed=%s",
                    job_id,
                    len(replication.get("peers", [])),
                    replication.get("completed_peer_count", 0),
                    replication.get("skipped_peer_count", 0),
                    replication.get("failed_peer_count", 0),
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("workshop job crashed job_id=%s", job_id)
            try:
                await asyncio.to_thread(
                    _finish_workshop_job, job_id, "failed", "任务执行异常，请查看节点日志"
                )
            except Exception:
                logger.exception("workshop job failure could not be recorded job_id=%s", job_id)
        finally:
            queue.task_done()


def _fail_orphaned_workshop_jobs() -> None:
    """进程重启会丢掉队列，把留在队列/执行中的任务标记为失败，让上游能重试。"""
    db = SessionLocal()
    try:
        rows = db.query(WorkshopJob).filter(
            WorkshopJob.status.in_(WORKSHOP_JOB_ACTIVE_STATES)
        ).all()
        for row in rows:
            row.status = "failed"
            row.error = "节点重启导致任务中断，请重新触发"
            row.finished_at = now_utc()
        if rows:
            db.commit()
            logger.info("workshop jobs interrupted by restart: %s", len(rows))
    finally:
        db.close()


def cleanup_workshop_jobs() -> None:
    global _workshop_cleanup_at
    now_ts = time.time()
    if now_ts - _workshop_cleanup_at < WORKSHOP_CLEANUP_INTERVAL_SECONDS:
        return
    _workshop_cleanup_at = now_ts

    cutoff = now_utc() - timedelta(hours=WORKSHOP.job_retention_hours)
    db = SessionLocal()
    try:
        # 只取 id 和时间，任务记录里的 items JSON 可能很大，不要为清理把它读出来。
        rows = db.query(WorkshopJob.id, WorkshopJob.created_at).filter(
            WorkshopJob.status.notin_(WORKSHOP_JOB_ACTIVE_STATES)
        ).all()
        expired = [
            job_id for job_id, created_at in rows
            if (_as_aware_utc(created_at) or cutoff) < cutoff
        ]
        if expired:
            db.query(WorkshopJob).filter(WorkshopJob.id.in_(expired)).delete(
                synchronize_session=False
            )
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
async def start_workshop_worker() -> None:
    global _workshop_queue, _workshop_worker_task
    if _workshop_queue is None:
        _workshop_queue = asyncio.Queue()
    await asyncio.to_thread(_fail_orphaned_workshop_jobs)
    if _workshop_worker_task is None or _workshop_worker_task.done():
        _workshop_worker_task = asyncio.create_task(_workshop_worker_loop())
    WORKSHOP_STEAMCMD.refresh_readiness_async()


@app.on_event("shutdown")
async def stop_workshop_worker() -> None:
    global _workshop_worker_task
    task = _workshop_worker_task
    _workshop_worker_task = None
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _workshop_request_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")
    try:
        ids = parse_workshop_ids(payload.get("items", payload.get("ids")))
        collections = parse_workshop_ids(payload.get("collections", payload.get("collection_id")))
    except WorkshopError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ids and not collections:
        raise HTTPException(status_code=400, detail="请至少提供一个创意工坊物品 ID / 链接或合集 ID")

    role = str(payload.get("role") or WORKSHOP_DEFAULT_ROLE).strip().lower()
    if role not in WORKSHOP_ROLES:
        raise HTTPException(status_code=400, detail="role 只能是 guest 或 admin")

    ttl_hours = payload.get("ttl_hours")
    if ttl_hours is not None:
        try:
            ttl_hours = max(0, int(ttl_hours))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="ttl_hours 必须是整数") from None
    if role == "guest":
        # 普通用户的保存时间只由节点后台的「普通用户保存时间」决定，调用方改不了。
        ttl_hours = None

    # 上游（NewAnneWeb）可以把已经查好的 Steam 元数据一起带过来，
    # 这样节点不必自己访问 api.steampowered.com —— 很多机房连不上它。
    try:
        details = parse_supplied_details(payload.get("details"))
    except WorkshopError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"ids": ids, "collections": collections, "role": role, "ttl_hours": ttl_hours, "details": details}


def _create_workshop_job(parsed: dict[str, Any], source_ip: Optional[str]) -> dict[str, Any]:
    db = SessionLocal()
    try:
        active = db.query(WorkshopJob).filter(
            WorkshopJob.status.in_(WORKSHOP_JOB_ACTIVE_STATES)
        ).count()
        if active >= WORKSHOP.max_queued_jobs:
            raise HTTPException(
                status_code=429,
                detail=f"创意工坊导入队列已满（{active} 个任务未完成），请稍后再试",
            )
        job = WorkshopJob(
            id=secrets.token_hex(16),
            status="queued",
            role=parsed.get("role") or WORKSHOP_DEFAULT_ROLE,
            ttl_hours=parsed["ttl_hours"],
            request=json.dumps(
                {
                    "ids": parsed["ids"],
                    "collections": parsed["collections"],
                    "details": parsed.get("details") or {},
                },
                ensure_ascii=False,
            ),
            items="[]",
            source_ip=(source_ip or "")[:64] or None,
            created_at=now_utc(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return _workshop_job_payload(job)
    finally:
        db.close()


@app.post("/api/federation/workshop", status_code=202)
async def federation_workshop_import(request: Request):
    require_federation_token(request)
    if not WORKSHOP.steamcmd_available() and not WORKSHOP.direct_download_enabled:
        raise HTTPException(status_code=503, detail="当前节点没有可用的创意工坊下载方式")
    if _workshop_queue is None:
        raise HTTPException(status_code=503, detail="创意工坊导入后台任务尚未启动")
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="请求体不是合法 JSON") from exc

    parsed = _workshop_request_payload(payload)
    job = await asyncio.to_thread(
        _create_workshop_job, parsed, request.client.host if request.client else None
    )
    _workshop_queue.put_nowait(job["job_id"])
    logger.info(
        "workshop job queued job_id=%s items=%s collections=%s",
        job["job_id"], len(parsed["ids"]), len(parsed["collections"]),
    )
    return {"ok": True, **job}


@app.get("/api/federation/workshop")
def federation_workshop_jobs(request: Request, limit: int = 20):
    require_federation_token(request)
    limit = max(1, min(100, limit))
    db = SessionLocal()
    try:
        rows = (
            db.query(WorkshopJob)
            .order_by(WorkshopJob.created_at.desc())
            .limit(limit)
            .all()
        )
        return {
            "generated_at": now_utc().isoformat(),
            "workshop": workshop_public_status(db),
            "jobs": [_workshop_job_payload(row) for row in rows],
        }
    finally:
        db.close()


@app.get("/api/federation/workshop/{job_id}")
def federation_workshop_job(request: Request, job_id: str):
    require_federation_token(request)
    db = SessionLocal()
    try:
        job = db.get(WorkshopJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="导入任务不存在")
        return _workshop_job_payload(job)
    finally:
        db.close()


@app.post("/admin/settings")
async def admin_set_settings(
    request: Request,
    upload_max_mb: int = Form(...),
    archive_vpk_count: int = Form(...),
    guest_ttl_hours: int = Form(...),
    total_upload_limit_mb: int = Form(...),
):
    require_admin(request)
    if upload_max_mb < 1:
        raise HTTPException(status_code=400, detail="单文件上传上限不能小于 1 MB")
    if archive_vpk_count < 1:
        raise HTTPException(status_code=400, detail="压缩包内 VPK 数量上限不能小于 1")
    if guest_ttl_hours < 0:
        raise HTTPException(status_code=400, detail="普通用户保存时间不能小于 0 小时")
    if total_upload_limit_mb < 0:
        raise HTTPException(status_code=400, detail="上传总容量限制不能小于 0 MB")
    set_upload_max_mb(upload_max_mb)
    set_archive_vpk_count(archive_vpk_count)
    set_guest_ttl_hours(guest_ttl_hours)
    set_total_upload_limit_mb(total_upload_limit_mb)
    return RedirectResponse(url="/admin?settings_saved=1", status_code=302)


@app.post("/admin/upload")
async def admin_upload(request: Request, file: UploadFile, ttl_hours: Optional[int] = Form(None)):
    require_admin(request)
    uploads, results, resp = await _handle_upload(request, file, role="admin", ttl_hours=ttl_hours)
    if resp is not None:
        return resp
    if len(uploads) > 1 or results["failed"]:
        return upload_batch_response(request, "admin", results)
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/set_expiry/{item_id}")
async def admin_set_expiry(request: Request, item_id: int, hours: int = Form(...)):
    require_admin(request)
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item:
            raise HTTPException(status_code=404)
        item.expires_at = (now_utc() + timedelta(hours=hours)) if hours > 0 else None
        db.commit()
    finally:
        db.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/delete/{item_id}")
async def admin_delete(request: Request, item_id: int):
    require_admin(request)
    delete_upload_item(item_id)
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/detail/{item_id}", response_class=HTMLResponse)
async def detail(request: Request, item_id: int):
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item:
            raise HTTPException(status_code=404)
    finally:
        db.close()
    report = json.loads(item.vpk_report or '{}')
    return templates.TemplateResponse("detail.html", {
        "request": request,
        "item": item,
        "report": report
    })


@app.get("/api/uploads/{item_id}/files")
async def upload_files(item_id: int):
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item or item.status != "active":
            raise HTTPException(status_code=404)

        exp = _as_aware_utc(item.expires_at)
        if exp and exp < now_utc():
            raise HTTPException(status_code=410, detail="文件已过期")

        path = os.path.join(UPLOAD_DIR, item.stored_name)
        if not os.path.exists(path):
            raise HTTPException(status_code=404)
    finally:
        db.close()

    try:
        with open_vpk(path) as arch:
            files = sorted(str(rel).replace("\\", "/").lstrip("./") for rel in arch)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"读取 VPK 文件列表失败：{exc}")

    return {
        "id": item_id,
        "original_name": item.original_name,
        "stored_name": item.stored_name,
        "file_count": len(files),
        "files": files,
    }


# 下载：仅用 id，响应头用 RFC 5987 兼容中文和空格
@app.get("/d/{item_id}")
async def download(item_id: int):
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item or item.status != "active":
            raise HTTPException(status_code=404)

        exp = _as_aware_utc(item.expires_at)
        if exp and exp < now_utc():
            raise HTTPException(status_code=410, detail="文件已过期")

        path = os.path.join(UPLOAD_DIR, item.stored_name)
        if not os.path.exists(path):
            raise HTTPException(status_code=404)

        headers = {"Content-Disposition": _disposition_utf8(item.original_name)}
        return FileResponse(path, media_type="application/octet-stream", headers=headers)
    finally:
        db.close()
