import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlencode

import bcrypt
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

from db import ActivityLog, SessionLocal, User, get_db, init_db

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

EVENT_TYPES = [
    "VISIT",
    "LOGIN_OK",
    "LOGIN_FAIL",
    "LOGOUT",
    "UPLOAD",
    "DOWNLOAD",
    "DELETE",
]


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(User)) == 0:
            username = os.getenv("ADMIN_USER", "admin")
            password = os.getenv("ADMIN_PASSWORD", "admin123")
            db.add(User(username=username, password_hash=hash_password(password)))
            db.commit()
            print(f"[bootstrap] seeded user: {username}")
    yield


app = FastAPI(title="File Server", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(32))
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def current_user(request: Request) -> str | None:
    return request.session.get("user")


def require_user(request: Request) -> str:
    user = current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return user


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "?"


def safe_resolve(filename: str) -> Path:
    target = (UPLOAD_DIR / filename).resolve()
    if UPLOAD_DIR not in target.parents and target != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid path")
    return target


def list_files() -> list[dict]:
    items = []
    for entry in sorted(UPLOAD_DIR.iterdir()):
        if entry.is_file():
            stat = entry.stat()
            items.append(
                {
                    "name": entry.name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime(
                        "%Y-%m-%d %H:%M"
                    ),
                }
            )
    return items


def record(
    db: Session,
    request: Request,
    event: str,
    *,
    username: str | None = None,
    filename: str | None = None,
    size: int | None = None,
    detail: str | None = None,
) -> None:
    db.add(
        ActivityLog(
            event=event,
            username=username if username is not None else current_user(request),
            ip=client_ip(request),
            path=str(request.url.path),
            filename=filename,
            size=size,
            user_agent=request.headers.get("user-agent"),
            detail=detail,
        )
    )
    db.commit()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db)):
    record(db, request, "VISIT")
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": current_user(request),
            "files": list_files(),
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = None):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "error": error},
    )


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.username == username))
    ok = user is not None and verify_password(password, user.password_hash)
    if not ok:
        record(db, request, "LOGIN_FAIL", username=username)
        return RedirectResponse("/login?error=Invalid+credentials", status_code=303)
    request.session["user"] = username
    record(db, request, "LOGIN_OK", username=username)
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    user = current_user(request)
    request.session.clear()
    if user:
        record(db, request, "LOGOUT", username=user)
    return RedirectResponse("/", status_code=303)


@app.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(require_user),
    db: Session = Depends(get_db),
):
    filename = Path(file.filename or "").name
    if not filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    target = safe_resolve(filename)

    size = 0
    with target.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            out.write(chunk)
            size += len(chunk)

    record(db, request, "UPLOAD", username=user, filename=filename, size=size)
    return RedirectResponse("/", status_code=303)


@app.post("/delete/{filename}")
async def delete(
    request: Request,
    filename: str,
    user: str = Depends(require_user),
    db: Session = Depends(get_db),
):
    target = safe_resolve(filename)
    if target.exists() and target.is_file():
        target.unlink()
        record(db, request, "DELETE", username=user, filename=filename)
    return RedirectResponse("/", status_code=303)


@app.get("/files/{filename}")
async def download(request: Request, filename: str, db: Session = Depends(get_db)):
    target = safe_resolve(filename)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    record(
        db,
        request,
        "DOWNLOAD",
        filename=filename,
        size=target.stat().st_size,
    )
    return FileResponse(
        target,
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{quote(filename)}"'},
    )


@app.get("/logs", response_class=HTMLResponse)
async def logs(
    request: Request,
    event: str | None = None,
    q: str | None = None,
    page: int = 1,
    user: str = Depends(require_user),
    db: Session = Depends(get_db),
):
    page_size = 50
    page = max(page, 1)

    stmt = select(ActivityLog)
    if event:
        stmt = stmt.where(ActivityLog.event == event)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                ActivityLog.username.ilike(like),
                ActivityLog.ip.ilike(like),
                ActivityLog.filename.ilike(like),
                ActivityLog.user_agent.ilike(like),
            )
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(desc(ActivityLog.id))
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).all()
    total_pages = max((total + page_size - 1) // page_size, 1)

    base_query = {k: v for k, v in {"event": event, "q": q}.items() if v}

    def page_link(p: int) -> str:
        return "?" + urlencode({**base_query, "page": p})

    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "events": EVENT_TYPES,
            "selected_event": event or "",
            "q": q or "",
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "page_link": page_link,
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 9000)),
        reload=True,
        reload_includes=["*.py", "templates/*.html", "static/*.css"],
        reload_excludes=["uploads/*", "*.db", "*.db-journal", "__pycache__/*"],
    )
