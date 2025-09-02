import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, request, redirect, url_for, render_template, make_response
)
from sqlalchemy import (
    create_engine, Column, String, DateTime, text
)
from sqlalchemy.orm import declarative_base, sessionmaker

# --- Config ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///qrdata.db")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5000")

# Exactly 3 admin tokens (send these privately to each admin)
ADMIN_TOKENS = {
    os.getenv("ADMIN1_TOKEN", "admin1-demo-token"): "admin1",
    os.getenv("ADMIN2_TOKEN", "admin2-demo-token"): "admin2",
    os.getenv("ADMIN3_TOKEN", "admin3-demo-token"): "admin3",
}

# How long codes are valid in storage (for admin listing)
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))

# --- App ---
app = Flask(__name__, static_url_path="/static", static_folder="static", template_folder="templates")
app.secret_key = SECRET_KEY

# --- DB ---
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class QRCode(Base):
    __tablename__ = "qrcodes"
    code_id = Column(String, primary_key=True)  # UUID string
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    used_by = Column(String, nullable=True)  # admin id
    note = Column(String, nullable=True)     # optional label for admin

Base.metadata.create_all(engine)

# ---- Helpers ----
def get_admin_id_from_cookie(req):
    return req.cookies.get("admin_id")

# ---- Routes ----
@app.get("/")
def home():
    return render_template("neutral.html")

@app.get("/admin/login")
def admin_login():
    token = request.args.get("token", "")
    admin_id = ADMIN_TOKENS.get(token)
    if not admin_id:
        return render_template("neutral.html"), 403

    resp = make_response(redirect(url_for("admin_codes")))
    resp.set_cookie("admin_id", admin_id, max_age=60*60*24*7,
                    httponly=True, secure=True, samesite="Lax")
    return resp

@app.get("/admin/logout")
def admin_logout():
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("admin_id")
    return resp

@app.get("/admin/codes")
def admin_codes():
    admin_id = get_admin_id_from_cookie(request)
    if not admin_id:
        return render_template("neutral.html"), 403

    session = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
        codes = (
            session.query(QRCode)
            .filter(QRCode.created_at >= cutoff)
            .order_by(QRCode.created_at.desc())
            .limit(100)
            .all()
        )
        return render_template("admin_codes.html", codes=codes, base_url=APP_BASE_URL)
    finally:
        session.close()

@app.post("/admin/codes/new")
def admin_codes_new():
    admin_id = get_admin_id_from_cookie(request)
    if not admin_id:
        return render_template("neutral.html"), 403

    code_id = str(uuid.uuid4())
    note = request.form.get("note") or None

    session = SessionLocal()
    try:
        session.add(QRCode(code_id=code_id, note=note))
        session.commit()
    finally:
        session.close()

    return redirect(url_for("admin_codes"))

@app.get("/verify/<code_id>")
def verify(code_id: str):
    admin_id = get_admin_id_from_cookie(request)

    session = SessionLocal()
    try:
        with session.begin():
            now = datetime.now(timezone.utc)
            result = session.execute(
                text("""
                    UPDATE qrcodes
                    SET used_at = COALESCE(used_at, :now),
                        used_by = COALESCE(used_by, :admin_id)
                    WHERE code_id = :code_id AND used_at IS NULL
                    RETURNING code_id, used_at, used_by
                """),
                {"now": now, "admin_id": admin_id or "", "code_id": code_id},
            )
            updated = result.first()

        qr = session.get(QRCode, code_id)
    finally:
        session.close()

    if not admin_id:
        return render_template("neutral.html")

    if qr is None:
        return render_template("already_used.html")

    if qr.used_at and qr.used_by:
        if updated is not None and qr.used_by == admin_id:
            return render_template("grant.html")
        return render_template("already_used.html")

    return render_template("already_used.html")

# ---- Security headers ----
@app.after_request
def set_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=()")
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
