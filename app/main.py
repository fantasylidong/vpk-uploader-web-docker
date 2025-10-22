import os
import hashlib
import shutil
import secrets
import json
import time
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
from .db import init_db, SessionLocal, Upload

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "1024"))
DEFAULT_GUEST_TTL_HOURS = int(os.getenv("DEFAULT_GUEST_TTL_HOURS", "24"))
RULES_FILE = os.getenv("RULES_FILE", "rules.yml")

TMP_MAX_AGE_MIN = int(os.getenv("TMP_MAX_AGE_MIN", "30"))
WORK_MAX_AGE_MIN = int(os.getenv("WORK_MAX_AGE_MIN", "60"))
ORPHAN_KEEP_HOURS = int(os.getenv("ORPHAN_KEEP_HOURS", "12"))

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
TMP_DIR = os.path.join(DATA_DIR, "tmp")

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

def _disposition_utf8(filename: str) -> str:
    ascii_fallback = "".join(c if 32 <= ord(c) < 127 else "_" for c in filename)
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(filename)}"

def cleanup_expired():
    db = SessionLocal()
    try:
        utcnow = now_utc()
        expired = db.query(Upload).filter(Upload.expires_at.isnot(None), Upload.expires_at < utcnow, Upload.status == "active").all()
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
    now = time.time()
    # tmp
    try:
        for name in os.listdir(TMP_DIR):
            path = os.path.join(TMP_DIR, name)
            if os.path.isfile(path):
                age = now - os.path.getmtime(path)
                if age > TMP_MAX_AGE_MIN * 60:
                    try: os.remove(path)
                    except Exception: pass
    except Exception:
        pass
    # _work_
    try:
        for name in os.listdir(UPLOAD_DIR):
            if name.startswith("_work_"):
                path = os.path.join(UPLOAD_DIR, name)
                if os.path.isdir(path):
                    age = now - os.path.getmtime(path)
                    if age > WORK_MAX_AGE_MIN * 60:
                        try: shutil.rmtree(path, ignore_errors=True)
                        except Exception: pass
    except Exception:
        pass
    # orphan vpk
    try:
        db = SessionLocal()
        tracked = {row[0] for row in db.query(Upload.stored_name).all()}
        db.close()
        for name in os.listdir(UPLOAD_DIR):
            if not name.endswith(".vpk") or name.startswith("_work_"):
                continue
            if name not in tracked:
                path = os.path.join(UPLOAD_DIR, name)
                age = now - os.path.getmtime(path)
                if age > ORPHAN_KEEP_HOURS * 3600:
                    try: os.remove(path)
                    except Exception: pass
    except Exception:
        pass

@app.middleware("http")
async def tidy_mw(request: Request, call_next):
    cleanup_expired()
    cleanup_tmp_and_work()
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

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "max_mb": MAX_UPLOAD_MB,
        "guest_ttl_hours": DEFAULT_GUEST_TTL_HOURS
    })

async def _handle_upload(request: Request, file: UploadFile, role: str, ttl_hours: Optional[int]):
    if not file.filename.lower().endswith(".vpk"):
        raise HTTPException(status_code=400, detail="只允许上传 .vpk 文件")

    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    tmp_name = f"tmp_{secrets.token_hex(8)}.vpk"
    tmp_path = os.path.join(TMP_DIR, tmp_name)

    read_bytes = 0
    sha256 = hashlib.sha256()

    with open(tmp_path, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > max_bytes:
                out.close()
                os.remove(tmp_path)
                raise HTTPException(status_code=400, detail=f"文件过大，超过 {MAX_UPLOAD_MB} MB 限制")
            sha256.update(chunk)
            out.write(chunk)

    # 校验 VPK
    vr: ValidationResult = validate_vpk(tmp_path, RULES_FILE)
    if not vr.ok:
        os.remove(tmp_path)
        return None, templates.TemplateResponse("index.html", {
            "request": request,
            "max_mb": MAX_UPLOAD_MB,
            "guest_ttl_hours": DEFAULT_GUEST_TTL_HOURS,
            "error": "VPK 不符合要求",
            "report": vr.to_dict(),
        })

    # 构建仅服务器版
    stored_base = f"{sha256.hexdigest()}_{secrets.token_hex(4)}"
    stored_name = f"{stored_base}_server.vpk"
    build_report = process_server_vpk(tmp_path, UPLOAD_DIR, stored_name)
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    # 入库
    db = SessionLocal()
    try:
        expires_at = None
        if role == "guest":
            expires_at = now_utc() + timedelta(hours=DEFAULT_GUEST_TTL_HOURS)
        else:
            if ttl_hours is not None and ttl_hours > 0:
                expires_at = now_utc() + timedelta(hours=ttl_hours)
        server_path = os.path.join(UPLOAD_DIR, stored_name)
        up = Upload(
            original_name=file.filename,
            stored_name=stored_name,
            sha256=sha256.hexdigest(),
            size=os.path.getsize(server_path) if os.path.exists(server_path) else 0,
            role=role,
            created_at=now_utc(),
            expires_at=expires_at,
            vpk_valid=True,
            vpk_report=json.dumps({"validation": vr.to_dict(), "server_build": build_report}, ensure_ascii=False),
            status="active",
            uploader_ip=request.client.host if request.client else None,
        )
        db.add(up)
        db.commit()
        db.refresh(up)
    finally:
        db.close()

    return up, None

@app.post("/upload")
async def guest_upload(request: Request, file: UploadFile):
    up, resp = await _handle_upload(request, file, role="guest", ttl_hours=None)
    if resp is not None:
        return resp
    return RedirectResponse(url=f"/detail/{up.id}", status_code=302)

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
    db = SessionLocal()
    try:
        query = db.query(Upload).order_by(Upload.created_at.desc())
        if q:
            like = f"%{q}%"
            query = query.filter(Upload.original_name.like(like))
        items = query.limit(200).all()
    finally:
        db.close()
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "items": items,
        "q": q or "",
        "max_mb": MAX_UPLOAD_MB
    })

@app.post("/admin/upload")
async def admin_upload(request: Request, file: UploadFile, ttl_hours: Optional[int] = Form(None)):
    require_admin(request)
    up, resp = await _handle_upload(request, file, role="admin", ttl_hours=ttl_hours)
    if resp is not None:
        return resp
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

# 下载路由：只带 id，使用 RFC5987 处理中文文件名
@app.get("/d/{item_id}")
async def download(item_id: int):
    db = SessionLocal()
    try:
        item = db.get(Upload, item_id)
        if not item or item.status != "active":
            raise HTTPException(status_code=404)
        if item.expires_at and item.expires_at < now_utc():
            raise HTTPException(status_code=410, detail="文件已过期")
        path = os.path.join(UPLOAD_DIR, item.stored_name)
        if not os.path.exists(path):
            raise HTTPException(status_code=404)
        headers = {"Content-Disposition": _disposition_utf8(item.original_name)}
        return FileResponse(path, media_type="application/octet-stream", headers=headers)
    finally:
        db.close()
