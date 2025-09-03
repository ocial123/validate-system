import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, g
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
# --- NEW: Imports for Login System ---
import bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a_very_secret_key_for_dev")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- NEW: Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to /login if user is not authenticated

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("WARNING: DATABASE_URL not found. Falling back to SQLite.")
    DATABASE_URL = "sqlite:///qrdata.db"

if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)
elif DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Database Models ---
# --- NEW: User Database Model for Admins ---
class User(UserMixin, Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class QRCode(Base):
    __tablename__ = "qrcodes"
    code_id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    used_at = Column(DateTime, nullable=True)
    used_by = Column(String, nullable=True)

Base.metadata.create_all(engine)

# --- NEW: User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    user = db.query(User).get(user_id)
    db.close()
    return user

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

# --- Routes ---
@app.route("/")
def landing():
    return render_template("landing.html")

# --- NEW: Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_codes'))
    if request.method == 'POST':
        db = get_db()
        user = db.query(User).filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('admin_codes'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))


# --- Admin Routes (Now Protected) ---
@app.route("/admin")
@login_required # <-- This line protects the page
def admin_codes():
    db = get_db()
    base_url = os.getenv("BASE_URL", "http://127.0.0.1:5000")
    all_codes = db.query(QRCode).order_by(QRCode.created_at.desc()).all()
    return render_template("admin_codes.html", codes=all_codes, base_url=base_url)

@app.route("/admin/new", methods=["POST"])
@login_required # <-- This line protects the page
def admin_codes_new():
    db = get_db()
    note_text = request.form.get("note")
    new_code = QRCode(note=note_text)
    db.add(new_code)
    db.commit()
    flash("Successfully generated a new QR code link!")
    return redirect(url_for("admin_codes"))


# --- Verification Route ---
@app.route("/verify/<code>")
def verify_code(code):
    db = get_db()
    qr_code = db.query(QRCode).filter_by(code_id=code).first()
    if not qr_code:
        return render_template("neutral.html")
    if qr_code.used_at:
        return render_template("already_used.html")
    qr_code.used_at = datetime.utcnow()
    qr_code.used_by = request.remote_addr
    db.commit()
    return render_template("grant.html")

# --- NEW: One-Time Route to Create First Admin (USE WITH CAUTION) ---
@app.route("/create_first_admin/<username>/<password>")
def create_first_admin(username, password):
    db = get_db()
    if db.query(User).first():
        return "An admin user already exists.", 403
    
    new_admin = User(username=username)
    new_admin.set_password(password)
    db.add(new_admin)
    db.commit()
    return f"Admin user '{username}' created. Please REMOVE the create_first_admin route from app.py now!", 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))