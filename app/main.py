import os
import hashlib
import shutil
import secrets
import json
import time
import select
import subprocess
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeSerializer, BadSignature

from .vpkcheck import validate_vpk, ValidationResult
from .vpk_tools import process_server_vpk
from .vpk_reader import open_vpk
from .db import init_db, SessionLocal, Upload, AppSetting

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
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
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

# 重要：上传文件与工作目录在系统 /tmp
TMP_DIR = os.getenv("TMP_DIR", "/tmp")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

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


def storage_context(db) -> dict:
    used_bytes = active_upload_usage_bytes(db)
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
        "total_upload_used_label": _format_mb(used_bytes),
        "total_upload_usage_label": usage_label,
        "total_upload_usage_percent": usage_percent,
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
    if used_bytes + new_file_size <= limit_bytes:
        return None

    remaining_bytes = max(0, limit_bytes - used_bytes)
    return (
        "上传失败：已超过上传总容量限制。"
        f"总容量上限 {total_upload_limit_label(limit_mb)}，"
        f"当前已用 {_format_mb(used_bytes)}，"
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
        "size": up.size,
        "size_label": _format_mb(up.size or 0),
        "detail_url": f"/detail/{up.id}",
        "download_url": f"/d/{up.id}",
    }


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
        capacity_error = total_capacity_error(db, server_size)
        if capacity_error:
            _remove_file_quietly(server_path)
            return None, {"name": display_name, "error": capacity_error}

        report = {"upload_source": upload_source, "validation": vr.to_dict(), "server_build": build_report}

        up = Upload(
            original_name=display_name,
            stored_name=final_name,
            sha256=upload_sha256,
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

    # SFTP 直接放进 uploads 的 .vpk 等同管理员上传：自动登记、永久保存。
    try:
        sync_sftp_uploads(now_ts)
    except Exception:
        pass


@app.middleware("http")
async def tidy_mw(request: Request, call_next):
    cleanup_tmp_and_work()
    cleanup_expired()
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


async def _handle_upload(request: Request, file: UploadFile, role: str, ttl_hours: Optional[int]):
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
    return [], results, upload_error_response(request, role, first_failure["error"], report=report)


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
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item:
            raise HTTPException(status_code=404)
        path = os.path.join(UPLOAD_DIR, item.stored_name)
        if os.path.exists(path):
            os.remove(path)
        item.status = "deleted"
        db.commit()
    finally:
        db.close()
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
