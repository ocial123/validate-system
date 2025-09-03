import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret")
app.wsgi_app = ProxyFix(app.wsgi_app)

# ✅ Database setup (Supabase or fallback SQLite)
# ✅ Database setup (Supabase or fallback SQLite)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///qrdata.db")

# Fix for Render: use pg8000 instead of psycopg2
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

# ✅ Token table
class Token(Base):
    __tablename__ = "tokens"
    token = Column(String, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

# ✅ Auto-create tables if not exist
Base.metadata.create_all(engine)

# === Routes ===
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/generate", methods=["POST"])
def generate():
    session = SessionLocal()
    token_str = str(uuid.uuid4())
    expires = datetime.utcnow() + timedelta(minutes=5)
    token = Token(token=token_str, expires_at=expires)
    session.add(token)
    session.commit()
    session.close()
    flash("QR Token generated!")
    return render_template("public_token.html", token=token_str)

@app.route("/validate/<token>")
def validate(token):
    session = SessionLocal()
    t = session.query(Token).filter_by(token=token).first()
    if not t:
        flash("❌ Invalid token")
    elif datetime.utcnow() > t.expires_at:
        flash("⏰ Token expired")
    else:
        flash("✅ Token valid")
    session.close()
    return redirect(url_for("landing"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
