import os
import fcntl
import hashlib
import shutil
import secrets
import json
import logging
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
from .db import init_db, SessionLocal, Upload, AppSetting, ReplicationReservation
from .docker_manager import DockerManager
from .aggregation import client_ip_is_allowed, token_is_valid
from .lan_replication import (
    PROTOCOL_VERSION,
    ReplicationArtifact,
    load_lan_replication_config,
    replicate_artifacts,
)

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
INSTANCE_NAME = os.getenv("INSTANCE_NAME", "VPK Uploader")
FEDERATION_API_TOKEN = os.getenv("FEDERATION_API_TOKEN", "")
FEDERATION_ALLOWED_CIDRS = os.getenv("FEDERATION_ALLOWED_CIDRS", "")
LAN_REPLICATION = load_lan_replication_config()
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

# 清理策略（分钟/小时）
TMP_MAX_AGE_MIN = int(os.getenv("TMP_MAX_AGE_MIN", "30"))
WORK_MAX_AGE_MIN = int(os.getenv("WORK_MAX_AGE_MIN", "60"))
SFTP_IMPORT_MIN_AGE_SECONDS = int(os.getenv("SFTP_IMPORT_MIN_AGE_SECONDS", "30"))

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(BASE_DIR), "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

# 重要：上传文件与工作目录在系统 /tmp
TMP_DIR = os.getenv("TMP_DIR", "/tmp")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)
CAPACITY_LOCK_PATH = os.path.join(DATA_DIR, ".capacity.lock")

app = FastAPI(title="VPK Uploader")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
templates.env.filters['tojson'] = lambda v: json.dumps(v, ensure_ascii=False, indent=2)

signer = URLSafeSerializer(APP_SECRET, salt="session")
init_db()


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
    limit_mb = get_total_upload_limit_mb(db)
    limit_bytes = limit_mb * 1024 * 1024
    disk_free_bytes = shutil.disk_usage(UPLOAD_DIR).free
    disk_available_bytes = max(
        0,
        disk_free_bytes - LAN_REPLICATION.disk_reserve_bytes - reserved_bytes,
    )
    quota_available_bytes = None
    if limit_bytes > 0:
        quota_available_bytes = max(0, limit_bytes - used_bytes - reserved_bytes)
    available_bytes = disk_available_bytes
    if quota_available_bytes is not None:
        available_bytes = min(available_bytes, quota_available_bytes)
    return {
        "limit_bytes": limit_bytes,
        "used_bytes": used_bytes,
        "reserved_bytes": reserved_bytes,
        "quota_available_bytes": quota_available_bytes,
        "disk_free_bytes": disk_free_bytes,
        "disk_reserve_bytes": LAN_REPLICATION.disk_reserve_bytes,
        "available_bytes": available_bytes,
    }


def storage_context(db) -> dict:
    snapshot = replication_storage_snapshot(db)
    used_bytes = int(snapshot["used_bytes"])
    reserved_bytes = int(snapshot["reserved_bytes"])
    limit_mb = get_total_upload_limit_mb(db)
    limit_bytes = limit_mb * 1024 * 1024
    usage_percent = 0
    remaining_bytes = None

    if limit_bytes > 0:
        usage_percent = min(100, round(used_bytes / limit_bytes * 100, 1))
        remaining_bytes = max(0, limit_bytes - used_bytes)

    usage_label = f"已用 {_format_mb(used_bytes)} / {total_upload_limit_label(limit_mb)}"
    if remaining_bytes is not None:
        usage_label = f"{usage_label}，剩余 {_format_mb(remaining_bytes)}"

    return {
        "total_upload_limit_mb": limit_mb,
        "total_upload_limit_label": total_upload_limit_label(limit_mb),
        "total_upload_limit_bytes": limit_bytes,
        "total_upload_used_bytes": used_bytes,
        "total_upload_reserved_bytes": reserved_bytes,
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


def total_capacity_error(db, new_file_size: int) -> Optional[str]:
    limit_mb = get_total_upload_limit_mb(db)
    if limit_mb <= 0:
        return None

    limit_bytes = limit_mb * 1024 * 1024
    used_bytes = active_upload_usage_bytes(db)
    reserved_bytes = active_replication_reserved_bytes(db)
    if used_bytes + reserved_bytes + new_file_size <= limit_bytes:
        return None

    remaining_bytes = max(0, limit_bytes - used_bytes - reserved_bytes)
    reserved_detail = f"，复制预留 {_format_mb(reserved_bytes)}" if reserved_bytes else ""
    return (
        "上传失败：已超过上传总容量限制。"
        f"总容量上限 {total_upload_limit_label(limit_mb)}，"
        f"当前已用 {_format_mb(used_bytes)}{reserved_detail}，"
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
    }


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
    request: Request,
    role: str,
    ttl_hours: Optional[int],
    tmp_vpk_path: str,
    source_vpk_name: str,
    upload_sha256: str,
    upload_source: dict,
    upload_max_mb: int,
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
                db.commit()
                result = _upload_item_result(existing)
                result["deduplicated"] = True
                return existing, result

            capacity_error = total_capacity_error(db, server_size)
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
                uploader_ip=request.client.host if request.client else None,
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


def sync_sftp_uploads(now_ts: Optional[float] = None):
    """把 SFTP 放进 uploads 的 .vpk 登记为管理员上传，避免被当作无主文件处理。"""
    if now_ts is None:
        now_ts = time.time()

    db = SessionLocal()
    try:
        by_name = {row.stored_name: row for row in db.query(Upload).all()}
        changed = False

        for name in os.listdir(UPLOAD_DIR):
            if not name.lower().endswith(".vpk"):
                continue

            path = os.path.join(UPLOAD_DIR, name)
            if not os.path.isfile(path):
                continue

            try:
                stat = os.stat(path)
            except OSError:
                continue

            if now_ts - stat.st_mtime < SFTP_IMPORT_MIN_AGE_SECONDS:
                continue

            existing = by_name.get(name)
            if existing and not _file_newer_than_upload_record(stat, existing):
                continue

            imported_at = now_utc()
            file_sha256 = _sha256_file(path)
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
            else:
                db.add(Upload(
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
                ))

            changed = True

        if changed:
            db.commit()
    finally:
        db.close()


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

    # SFTP 直接放进 uploads 的 .vpk 等同管理员上传：自动登记、永久保存。
    try:
        sync_sftp_uploads(now_ts)
    except Exception:
        pass


@app.middleware("http")
async def tidy_mw(request: Request, call_next):
    cleanup_tmp_and_work()
    cleanup_expired()
    cleanup_replication_reservations()
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


async def _handle_upload(
    request: Request,
    file: UploadFile,
    role: str,
    ttl_hours: Optional[int],
    render_error: bool = True,
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

    upload_sha256 = sha256.hexdigest()
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
                        request=request,
                        role=role,
                        ttl_hours=ttl_hours,
                        tmp_vpk_path=tmp_vpk_path,
                        source_vpk_name=source_vpk_name,
                        upload_sha256=upload_sha256,
                        upload_source=upload_source,
                        upload_max_mb=upload_max_mb,
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
                request=request,
                role=role,
                ttl_hours=ttl_hours,
                tmp_vpk_path=tmp_upload_path,
                source_vpk_name=original_name,
                upload_sha256=upload_sha256,
                upload_source=upload_source,
                upload_max_mb=upload_max_mb,
            )
            tmp_upload_path = None
            if up is not None:
                uploads.append(up)
                uploaded.append(result)
            else:
                failed.append(result)
    finally:
        _remove_file_quietly(tmp_upload_path)

    results = {"uploaded": uploaded, "failed": failed}

    if uploaded:
        return uploads, results, None

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
async def federation_upload(request: Request, file: UploadFile):
    require_federation_token(request)
    uploads, results, _ = await _handle_upload(
        request,
        file,
        role="admin",
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
