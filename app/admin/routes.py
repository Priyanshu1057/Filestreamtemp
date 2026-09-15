"""Admin panel: password-protected dashboard, user / file / settings control."""

from fastapi import APIRouter, Request, HTTPException, Form, Query
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from app.database.connection import (
    files_col,
    users_col,
    logs_col,
    settings_col,
    settings,
)
from app.streamer.manager import session_manager

import asyncio
import datetime
import hashlib
import hmac
import logging
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")

COOKIE_NAME = "ff_admin"
SESSION_TTL = 60 * 60 * 12  # 12 hours
START_TIME = time.time()


# ---------------------------------------------------------------- auth ----
def _password() -> str:
    return (getattr(settings, "ADMIN_PASSWORD", "") or "").strip()


def _sign(expires: int) -> str:
    key = (_password() + settings.BOT_TOKEN).encode()
    mac = hmac.new(key, str(expires).encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{mac}"


def _valid(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    raw, _, mac = token.partition(".")
    try:
        expires = int(raw)
    except ValueError:
        return False
    if expires < time.time():
        return False
    return hmac.compare_digest(_sign(expires), token)


def is_admin(request: Request) -> bool:
    if not _password():
        return False
    return _valid(request.cookies.get(COOKIE_NAME))


def require_admin(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401, detail="Admin login required")


def _guard(request: Request):
    """Return a redirect response when the visitor is not logged in."""
    if not is_admin(request):
        return RedirectResponse("/admin/login", status_code=303)
    return None


@router.get("/login")
async def login_page(request: Request, error: str = ""):
    if is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    return templates.TemplateResponse(
        "admin/login.html",
        {
            "request": request,
            "error": error,
            "configured": bool(_password()),
        },
    )


@router.post("/login")
async def login_submit(request: Request, password: str = Form("")):
    if not _password():
        return RedirectResponse("/admin/login?error=notset", status_code=303)
    if not hmac.compare_digest(password, _password()):
        await asyncio.sleep(1)
        return RedirectResponse("/admin/login?error=bad", status_code=303)

    expires = int(time.time()) + SESSION_TTL
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        _sign(expires),
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=settings.BASE_URL.startswith("https"),
    )
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


# ------------------------------------------------------------- helpers ----
async def _app_settings() -> dict:
    doc = await settings_col.find_one({"_id": "app"}) or {}
    return {
        "maintenance_mode": bool(doc.get("maintenance_mode", False)),
        "auto_delete_hours": int(doc.get("auto_delete_hours", settings.DEFAULT_EXPIRY)),
        "downloads_enabled": bool(doc.get("downloads_enabled", True)),
        "notice": doc.get("notice", ""),
    }


def _human(size) -> str:
    try:
        size = float(size or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


async def _stats() -> dict:
    now = datetime.datetime.utcnow()
    day = now - datetime.timedelta(days=1)
    week = now - datetime.timedelta(days=7)

    total_users, banned_users, new_users, active_users = await asyncio.gather(
        users_col.count_documents({}),
        users_col.count_documents({"is_banned": True}),
        users_col.count_documents({"joined_at": {"$gte": day}}),
        users_col.count_documents({"last_active": {"$gte": day}}),
    )
    total_files, files_today, files_week, expired = await asyncio.gather(
        files_col.count_documents({}),
        files_col.count_documents({"created_at": {"$gte": day}}),
        files_col.count_documents({"created_at": {"$gte": week}}),
        files_col.count_documents({"expiry_time": {"$lt": now, "$ne": None}}),
    )

    agg = await files_col.aggregate(
        [
            {
                "$group": {
                    "_id": None,
                    "bytes": {"$sum": "$file_size"},
                    "views": {"$sum": "$access_count"},
                }
            }
        ]
    ).to_list(1)
    totals = agg[0] if agg else {}

    return {
        "total_users": total_users,
        "banned_users": banned_users,
        "new_users": new_users,
        "active_users": active_users,
        "total_files": total_files,
        "files_today": files_today,
        "files_week": files_week,
        "expired_files": expired,
        "total_bytes": totals.get("bytes", 0),
        "total_size": _human(totals.get("bytes", 0)),
        "total_views": totals.get("views", 0),
    }


def _system() -> dict:
    cpu = ram = disk = 0.0
    ram_used = disk_used = ""
    if psutil:
        try:
            cpu = psutil.cpu_percent()
            vm = psutil.virtual_memory()
            ram = vm.percent
            ram_used = f"{_human(vm.used)} / {_human(vm.total)}"
            du = psutil.disk_usage("/")
            disk = du.percent
            disk_used = f"{_human(du.used)} / {_human(du.total)}"
        except Exception:
            pass
    uptime = int(time.time() - START_TIME)
    hours, rem = divmod(uptime, 3600)
    return {
        "cpu": round(cpu, 1),
        "ram": round(ram, 1),
        "disk": round(disk, 1),
        "ram_used": ram_used,
        "disk_used": disk_used,
        "uptime": f"{hours}h {rem // 60}m",
        "clients": len(getattr(session_manager, "clients", []) or []),
        "user_sessions": max(len(getattr(session_manager, "clients", []) or []) - 1, 0),
    }


# ----------------------------------------------------------- dashboard ----
@router.get("/")
async def admin_dashboard(request: Request):
    if (r := _guard(request)) is not None:
        return r

    stats = await _stats()
    recent_files = await files_col.find().sort("created_at", -1).to_list(8)
    recent_users = await users_col.find().sort("joined_at", -1).to_list(8)
    top_files = await files_col.find().sort("access_count", -1).to_list(8)

    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "page": "dashboard",
            "stats": stats,
            "sys": _system(),
            "recent_files": recent_files,
            "recent_users": recent_users,
            "top_files": top_files,
            "app_settings": await _app_settings(),
            "human": _human,
        },
    )


@router.get("/api/stats")
async def api_stats(request: Request):
    require_admin(request)
    return JSONResponse({"stats": await _stats(), "sys": _system()})


# --------------------------------------------------------------- users ----
@router.get("/users")
async def admin_users(
    request: Request,
    q: str = "",
    status: str = "all",
    page: int = Query(1, ge=1),
):
    if (r := _guard(request)) is not None:
        return r

    per_page = 25
    query: dict = {}
    if q:
        if q.strip().lstrip("-").isdigit():
            query["user_id"] = int(q.strip())
        else:
            query["$or"] = [
                {"username": {"$regex": q, "$options": "i"}},
                {"first_name": {"$regex": q, "$options": "i"}},
            ]
    if status == "banned":
        query["is_banned"] = True
    elif status == "active":
        query["is_banned"] = {"$ne": True}

    total = await users_col.count_documents(query)
    users = (
        await users_col.find(query)
        .sort("joined_at", -1)
        .skip((page - 1) * per_page)
        .to_list(per_page)
    )

    # file counts per user
    ids = [u.get("user_id") for u in users]
    counts = await files_col.aggregate(
        [
            {"$match": {"uploader_id": {"$in": ids}}},
            {"$group": {"_id": "$uploader_id", "n": {"$sum": 1}}},
        ]
    ).to_list(len(ids) or 1)
    count_map = {c["_id"]: c["n"] for c in counts}
    for u in users:
        u["file_count"] = count_map.get(u.get("user_id"), 0)

    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "page": "users",
            "users": users,
            "query": q,
            "status": status,
            "page_no": page,
            "pages": max((total + per_page - 1) // per_page, 1),
            "total": total,
            "owner_id": settings.OWNER_ID,
        },
    )


@router.post("/users/{user_id}/ban")
async def ban_user(request: Request, user_id: int):
    require_admin(request)
    if user_id == settings.OWNER_ID:
        raise HTTPException(status_code=400, detail="Cannot ban the owner")
    await users_col.update_one({"user_id": user_id}, {"$set": {"is_banned": True}})
    return {"status": "success"}


@router.post("/users/{user_id}/unban")
async def unban_user(request: Request, user_id: int):
    require_admin(request)
    await users_col.update_one({"user_id": user_id}, {"$set": {"is_banned": False}})
    return {"status": "success"}


@router.post("/users/{user_id}/delete")
async def delete_user(request: Request, user_id: int):
    require_admin(request)
    await users_col.delete_one({"user_id": user_id})
    await files_col.delete_many({"uploader_id": user_id})
    return {"status": "success"}


# --------------------------------------------------------------- files ----
@router.get("/files")
async def admin_files(
    request: Request,
    q: str = "",
    sort: str = "new",
    state: str = "all",
    page: int = Query(1, ge=1),
):
    if (r := _guard(request)) is not None:
        return r

    per_page = 25
    now = datetime.datetime.utcnow()
    query: dict = {}
    if q:
        query["$or"] = [
            {"filename": {"$regex": q, "$options": "i"}},
            {"short_code": q.strip()},
        ]
    if state == "expired":
        query["expiry_time"] = {"$lt": now, "$ne": None}
    elif state == "live":
        query["$and"] = [
            {"$or": [{"expiry_time": None}, {"expiry_time": {"$gte": now}}]}
        ]

    sort_key = {
        "new": ("created_at", -1),
        "old": ("created_at", 1),
        "views": ("access_count", -1),
        "size": ("file_size", -1),
    }.get(sort, ("created_at", -1))

    total = await files_col.count_documents(query)
    files = (
        await files_col.find(query)
        .sort(*sort_key)
        .skip((page - 1) * per_page)
        .to_list(per_page)
    )
    for f in files:
        exp = f.get("expiry_time")
        f["is_expired"] = bool(exp and exp < now)
        f["size_human"] = _human(f.get("file_size"))

    return templates.TemplateResponse(
        "admin/files.html",
        {
            "request": request,
            "page": "files",
            "files": files,
            "query": q,
            "sort": sort,
            "state": state,
            "page_no": page,
            "pages": max((total + per_page - 1) // per_page, 1),
            "total": total,
            "base_url": settings.BASE_URL.rstrip("/"),
        },
    )


@router.post("/files/delete/{short_code}")
async def delete_file(request: Request, short_code: str):
    require_admin(request)
    await files_col.delete_one({"short_code": short_code})
    return {"status": "success"}


@router.post("/files/expire/{short_code}")
async def expire_file(request: Request, short_code: str):
    require_admin(request)
    await files_col.update_one(
        {"short_code": short_code},
        {"$set": {"expiry_time": datetime.datetime.utcnow()}},
    )
    return {"status": "success"}


@router.post("/files/extend/{short_code}")
async def extend_file(request: Request, short_code: str, hours: int = Query(24, ge=0)):
    require_admin(request)
    new_expiry = (
        None
        if hours == 0
        else datetime.datetime.utcnow() + datetime.timedelta(hours=hours)
    )
    await files_col.update_one(
        {"short_code": short_code}, {"$set": {"expiry_time": new_expiry}}
    )
    return {"status": "success"}


@router.post("/files/purge-expired")
async def purge_expired(request: Request):
    require_admin(request)
    result = await files_col.delete_many(
        {"expiry_time": {"$lt": datetime.datetime.utcnow(), "$ne": None}}
    )
    return {"status": "success", "deleted": result.deleted_count}


# ------------------------------------------------------------ settings ----
@router.get("/settings")
async def admin_settings(request: Request, saved: str = ""):
    if (r := _guard(request)) is not None:
        return r
    return templates.TemplateResponse(
        "admin/settings.html",
        {
            "request": request,
            "page": "settings",
            "app_settings": await _app_settings(),
            "sys": _system(),
            "saved": saved,
            "env": {
                "base_url": settings.BASE_URL,
                "channel_id": settings.CHANNEL_ID,
                "owner_id": settings.OWNER_ID,
                "admins": settings.admin_list,
                "fsub": settings.fsub_list,
                "default_expiry": settings.DEFAULT_EXPIRY,
                "sessions": len(
                    [s for s in (settings.SESSIONS or "").split(",") if s.strip()]
                ),
            },
        },
    )


@router.post("/settings")
async def save_settings(
    request: Request,
    maintenance_mode: str = Form(""),
    downloads_enabled: str = Form(""),
    auto_delete_hours: int = Form(24),
    notice: str = Form(""),
):
    require_admin(request)
    await settings_col.update_one(
        {"_id": "app"},
        {
            "$set": {
                "maintenance_mode": maintenance_mode == "on",
                "downloads_enabled": downloads_enabled == "on",
                "auto_delete_hours": max(int(auto_delete_hours), 0),
                "notice": notice.strip()[:300],
            }
        },
        upsert=True,
    )
    return RedirectResponse("/admin/settings?saved=1", status_code=303)


# ----------------------------------------------------------- broadcast ----
@router.get("/broadcast")
async def broadcast_page(request: Request):
    if (r := _guard(request)) is not None:
        return r
    total = await users_col.count_documents({"is_banned": {"$ne": True}})
    return templates.TemplateResponse(
        "admin/broadcast.html",
        {"request": request, "page": "broadcast", "total": total},
    )


@router.post("/broadcast")
async def broadcast_send(request: Request, message: str = Form("")):
    require_admin(request)
    message = message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message is empty")

    bot = getattr(session_manager, "bot_client", None)
    if bot is None:
        raise HTTPException(status_code=503, detail="Bot is not running")

    sent = failed = 0
    cursor = users_col.find({"is_banned": {"$ne": True}}, {"user_id": 1})
    async for user in cursor:
        try:
            await bot.send_message(user["user_id"], message, parse_mode="html")
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.05)

    await logs_col.insert_one(
        {
            "type": "broadcast",
            "sent": sent,
            "failed": failed,
            "at": datetime.datetime.utcnow(),
        }
    )
    return {"status": "success", "sent": sent, "failed": failed}


# ---------------------------------------------------------------- logs ----
@router.get("/logs")
async def admin_logs(request: Request):
    if (r := _guard(request)) is not None:
        return r
    logs = await logs_col.find().sort("at", -1).to_list(100)
    return templates.TemplateResponse(
        "admin/logs.html", {"request": request, "page": "logs", "logs": logs}
    )
