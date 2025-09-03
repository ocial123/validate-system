import os
import uuid
import bcrypt
import qrcode # <-- New import
import io     # <-- New import
import base64 # <-- New import
from flask import Flask, render_template, request, redirect, url_for, flash, g
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- App and Secret Key Setup ---
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a_very_secret_key_for_dev")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Setup ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///qrdata.db"

if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+pg8000://", 1)
elif DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+pg8000://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Database Models ---
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

# --- User Loader for Flask-Login ---
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

# --- Authentication Routes ---
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

# --- Admin Routes ---
@app.route("/admin")
@login_required
def admin_codes():
    db = get_db()
    base_url = os.getenv("BASE_URL")
    all_codes = db.query(QRCode).order_by(QRCode.created_at.desc()).all()
    return render_template("admin_codes.html", codes=all_codes, base_url=base_url)

# --- UPDATED: This now generates a QR code image ---
@app.route("/admin/new", methods=["POST"])
@login_required
def admin_codes_new():
    db = get_db()
    note_text = request.form.get("note")
    
    # 1. Create the new code record in the database
    new_code = QRCode(note=note_text)
    db.add(new_code)
    db.commit()

    # 2. Generate the full URL for the QR code to point to
    base_url = os.getenv("BASE_URL")
    full_url = f"{base_url}/verify/{new_code.code_id}"

    # 3. Generate the QR code image in memory
    img = qrcode.make(full_url)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    # 4. Encode the image to Base64 to display in HTML
    qr_image_b64 = base64.b64encode(buf.read()).decode('utf-8')

    # 5. Show the new page with the generated QR code
    return render_template("show_qr.html", qr_image=qr_image_b64, note=note_text)


# --- UPDATED: This verification route is now "smart" ---
@app.route("/verify/<code>")
def verify_code(code):
    db = get_db()
    qr_code = db.query(QRCode).filter_by(code_id=code).first()

    if not qr_code:
        return render_template("neutral.html")

    # If the person scanning is a logged-in admin
    if current_user.is_authenticated:
        if qr_code.used_at:
            return render_template("already_used.html")
        
        # Mark the code as used
        qr_code.used_at = datetime.utcnow()
        qr_code.used_by = f"Admin: {current_user.username}"
        db.commit()
        return render_template("grant.html")
    
    # If the person scanning is a guest
    else:
        # Don't change the status, just show the event page
        return render_template("public_event.html")

# You can remove the create_first_admin route if you have already created your users
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