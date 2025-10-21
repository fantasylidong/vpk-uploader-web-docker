import os
import io
import hashlib
import shutil
import secrets
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeSerializer, BadSignature

from .vpkcheck import validate_vpk, ValidationResult
from .db import init_db, SessionLocal, Upload

APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "1024"))
DEFAULT_GUEST_TTL_HOURS = int(os.getenv("DEFAULT_GUEST_TTL_HOURS", "24"))
RULES_FILE = os.getenv("RULES_FILE", "rules.yml")

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
TMP_DIR = os.path.join(DATA_DIR, "tmp")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

app = FastAPI(title="VPK Uploader")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# add a simple tojson filter for templates
templates.env.filters['tojson'] = lambda v: json.dumps(v, ensure_ascii=False, indent=2)

signer = URLSafeSerializer(APP_SECRET, salt="session")

init_db()

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

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

@app.middleware("http")
async def tidy_mw(request: Request, call_next):
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
    cookie = signer.dumps(data)
    response.set_cookie("session", cookie, httponly=True, samesite="lax")

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

@app.post("/upload")
async def guest_upload(request: Request, file: UploadFile):
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

    vr: ValidationResult = validate_vpk(tmp_path, RULES_FILE)
    if not vr.ok:
        os.remove(tmp_path)
        return templates.TemplateResponse("index.html", {
            "request": request,
            "max_mb": MAX_UPLOAD_MB,
            "guest_ttl_hours": DEFAULT_GUEST_TTL_HOURS,
            "error": "VPK 不符合要求",
            "report": vr.to_dict(),
        })

    stored = f"{sha256.hexdigest()}_{secrets.token_hex(4)}.vpk"
    final_path = os.path.join(UPLOAD_DIR, stored)
    shutil.move(tmp_path, final_path)

    db = SessionLocal()
    try:
        up = Upload(
            original_name=file.filename,
            stored_name=stored,
            sha256=sha256.hexdigest(),
            size=read_bytes,
            role="guest",
            created_at=now_utc(),
            expires_at=now_utc() + timedelta(hours=DEFAULT_GUEST_TTL_HOURS),
            vpk_valid=True,
            vpk_report=json.dumps(vr.to_dict(), ensure_ascii=False),
            status="active",
            uploader_ip=request.client.host if request.client else None,
        )
        db.add(up)
        db.commit()
        db.refresh(up)
    finally:
        db.close()

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

    vr = validate_vpk(tmp_path, RULES_FILE)
    if not vr.ok:
        os.remove(tmp_path)
        return RedirectResponse(url=f"/admin?error=VPK校验失败", status_code=302)

    stored = f"{sha256.hexdigest()}_{secrets.token_hex(4)}.vpk"
    final_path = os.path.join(UPLOAD_DIR, stored)
    shutil.move(tmp_path, final_path)

    expires = None
    if ttl_hours is not None and ttl_hours > 0:
        expires = now_utc() + timedelta(hours=ttl_hours)

    db = SessionLocal()
    try:
        up = Upload(
            original_name=file.filename,
            stored_name=stored,
            sha256=sha256.hexdigest(),
            size=read_bytes,
            role="admin",
            created_at=now_utc(),
            expires_at=expires,
            vpk_valid=True,
            vpk_report=json.dumps(vr.to_dict(), ensure_ascii=False),
            status="active",
            uploader_ip=request.client.host if request.client else None,
        )
        db.add(up)
        db.commit()
    finally:
        db.close()

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

@app.get("/d/{item_id}/{name}")
async def download(item_id: int, name: str):
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
        return FileResponse(path, filename=item.original_name, media_type="application/octet-stream")
    finally:
        db.close()
