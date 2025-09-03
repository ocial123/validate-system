import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, g
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a_very_secret_key_for_dev")
# This is important for Render to know it's behind a proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")

# Fallback to a local SQLite database if DATABASE_URL is not set
if not DATABASE_URL:
    print("WARNING: DATABASE_URL not found. Falling back to SQLite.")
    DATABASE_URL = "sqlite:///qrdata.db"

# Fix for Supabase/Render compatibility with pg8000# 
# Fix for Supabase/Render compatibility with pg8000
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)
elif DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Database Model (Updated) --- 
# This model now matches what your admin_codes.html template expects
class QRCode(Base):
    __tablename__ = "qrcodes"
    code_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    used_at = Column(DateTime, nullable=True) # Tracks when it was used
    used_by = Column(String, nullable=True)   # Optional: Tracks who used it (e.g., IP address)


# Auto-create the table if it doesn't exist
Base.metadata.create_all(engine)

# --- Helper to get DB session ---
def get_db():
    if 'db' not in g:
        g.db = SessionLocal()
    return g.db

@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# --- Routes (Updated) ---

@app.route("/")
def landing():
    """
    This is the main landing page, which can show flashed messages
    after a validation attempt.
    """
    return render_template("landing.html")

@app.route("/admin")
def admin_codes():
    """
    Admin dashboard to view all generated QR codes.
    """
    db = get_db()
    # Get the base URL from environment variables for link generation
    base_url = os.getenv("BASE_URL", "http://127.0.0.1:5000")
    all_codes = db.query(QRCode).order_by(QRCode.created_at.desc()).all()
    return render_template("admin_codes.html", codes=all_codes, base_url=base_url)

@app.route("/admin/new", methods=["POST"])
def admin_codes_new():
    """
    Handles the form submission from the admin page to create a new code.
    """
    db = get_db()
    note_text = request.form.get("note")
    new_code = QRCode(note=note_text)
    db.add(new_code)
    db.commit()
    flash("Successfully generated a new QR code link!")
    return redirect(url_for("admin_codes"))

@app.route("/verify/<code>")
def verify_code(code):
    """
    This is the link the QR code points to. It validates the code
    and marks it as used.
    """
    db = get_db()
    qr_code = db.query(QRCode).filter_by(code_id=code).first()

    if not qr_code:
        # If the code doesn't exist in the database at all.
        return render_template("neutral.html")

    if qr_code.used_at:
        # If the code has already been used.
        return render_template("already_used.html")

    # --- Success Case ---
    # Mark the code as used and save it to the database.
    qr_code.used_at = datetime.utcnow()
    qr_code.used_by = request.remote_addr # Store the IP address of the user
    db.commit()

    # Show the access granted page.
    return render_template("grant.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))