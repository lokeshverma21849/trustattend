"""
TrustAttend — Cloud-Ready Production Backend  v3.0.0
FastAPI + SQLite + SQLAlchemy + bcrypt + SHA-256 Integrity
==========================================================
NEW in v3.0:
  - "manager" role (Technical Manager) with duty-config endpoint
  - duty_type field on employees: OFFICE | ON_SITE | TRAVEL
  - assigned_lat / assigned_lng for ON_SITE employees
  - TRAVEL attendance status (paid, no deduction)
  - POST /attendance/self-mark for employee self check-in
    * OFFICE  → blocked (HR only)
    * TRAVEL  → instant log, no GPS check
    * ON_SITE → Haversine GPS check, must be within 100 metres

Local run:
    pip install -r requirements.txt
    python trustattend_backend.py

Render.com deployment:
    Build Command : pip install -r requirements.txt
    Start Command : uvicorn trustattend_backend:app --host 0.0.0.0 --port $PORT
"""

import hashlib
import json
import math
import os
import random
import string
from datetime import date, datetime, timedelta, timezone
from typing import Optional

import bcrypt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import (Boolean, Column, DateTime, Float, Integer, String,
                        Text, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ══════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════
SECRET_KEY     = os.environ.get("SECRET_KEY", "trustattend-super-secret-change-in-production-2024")
ALGORITHM      = "HS256"
TOKEN_EXPIRE   = 24   # hours
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
PORT           = int(os.environ.get("PORT", 8000))

_db_path   = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustattend.db"))
DATABASE_URL = f"sqlite:///{_db_path}"
os.makedirs(os.path.dirname(_db_path), exist_ok=True)

# ══════════════════════════════════════════════════════════════
#  DATABASE SETUP
# ══════════════════════════════════════════════════════════════
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

# ── Models ──────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id            = Column(String, primary_key=True)
    username      = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role          = Column(String, nullable=False)   # 'admin' | 'employee' | 'manager'
    name          = Column(String, nullable=False)
    employee_id   = Column(String, nullable=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active     = Column(Boolean, default=True)

class Employee(Base):
    __tablename__ = "employees"
    id             = Column(String, primary_key=True)
    user_id        = Column(String, nullable=False)
    name           = Column(String, nullable=False)
    department     = Column(String, nullable=False)
    monthly_salary = Column(Integer, default=0)
    pl_balance     = Column(Integer, default=12)
    el_balance     = Column(Integer, default=15)
    join_date      = Column(String, nullable=False)
    created_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    # ── NEW v3 duty fields ──
    duty_type      = Column(String, default="OFFICE")   # OFFICE | ON_SITE | TRAVEL
    assigned_lat   = Column(Float, nullable=True)
    assigned_lng   = Column(Float, nullable=True)

class AttendanceRecord(Base):
    __tablename__ = "attendance"
    id          = Column(String, primary_key=True)
    employee_id = Column(String, nullable=False)
    date        = Column(String, nullable=False)
    status      = Column(String, nullable=False)   # PRESENT | ABSENT_PL | ABSENT_EL | ABSENT_LOP | TRAVEL
    marked_by   = Column(String, nullable=False)
    marked_at   = Column(String, nullable=False)
    row_hash    = Column(String, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id          = Column(String, primary_key=True)
    timestamp   = Column(String, nullable=False)
    user_id     = Column(String, nullable=False)
    employee_id = Column(String, nullable=True)
    action      = Column(String, nullable=False)
    old_value   = Column(Text, nullable=True)
    new_value   = Column(Text, nullable=True)
    row_hash    = Column(String, nullable=False)

class CandidateRequest(Base):
    __tablename__ = "candidate_requests"
    id            = Column(String, primary_key=True)
    name          = Column(String, nullable=False)
    email         = Column(String, nullable=False)
    phone         = Column(String, nullable=False)
    department    = Column(String, nullable=False)
    position      = Column(String, nullable=False)
    join_date     = Column(String, nullable=False)
    address       = Column(String, nullable=True)
    submitted_at  = Column(String, nullable=False)
    status        = Column(String, default="pending")
    temp_username = Column(String, nullable=True)
    temp_password = Column(String, nullable=True)
    approved_at   = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def today_iso() -> str:
    return date.today().isoformat()

def gen_id(prefix: str = "id") -> str:
    rnd = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{prefix}_{int(datetime.now().timestamp()*1000)}_{rnd}"

def gen_employee_id(db: Session) -> str:
    emps = db.query(Employee).all()
    max_n = 0
    for e in emps:
        try:
            n = int(e.id.replace("E", ""))
            if n > max_n:
                max_n = n
        except ValueError:
            pass
    return f"E{str(max_n + 1).zfill(3)}"

def gen_temp_username(name: str) -> str:
    base = name.lower().replace(" ", "")[:8]
    return f"{base}{random.randint(100, 999)}"

def gen_temp_password() -> str:
    return "Tmp@" + ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def attendance_canonical(record_id, emp_id, rec_date, status, marked_by, marked_at) -> str:
    return "|".join([record_id, emp_id, rec_date, status, marked_by, marked_at])

def audit_canonical(entry: dict) -> str:
    payload = {k: entry[k] for k in ["id", "timestamp", "user_id", "employee_id", "action", "old_value", "new_value"]}
    return json.dumps(payload, sort_keys=True)

# ── Haversine distance (metres) ───────────────────────────────
def haversine_metres(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6_371_000  # Earth radius in metres
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

# ── JWT ──────────────────────────────────────────────────────
def create_token(user_id: str, role: str, employee_id: Optional[str] = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE)
    payload = {"sub": user_id, "role": role, "exp": expire}
    if employee_id:
        payload["employee_id"] = employee_id
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return decode_token(credentials.credentials)

def require_admin(payload: dict = Depends(get_current_user)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return payload

def require_manager(payload: dict = Depends(get_current_user)):
    if payload.get("role") not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Manager or Admin access required.")
    return payload

def require_employee(payload: dict = Depends(get_current_user)):
    if payload.get("role") != "employee":
        raise HTTPException(status_code=403, detail="Employee access required.")
    return payload

def write_audit(db: Session, user_id: str, employee_id: str, action: str,
                old_value=None, new_value=None):
    entry_id = gen_id("log")
    ts = now_iso()
    entry = {
        "id": entry_id, "timestamp": ts, "user_id": user_id,
        "employee_id": employee_id, "action": action,
        "old_value": old_value, "new_value": new_value,
    }
    row_hash = sha256_str(audit_canonical(entry))
    log = AuditLog(id=entry_id, timestamp=ts, user_id=user_id,
                   employee_id=employee_id, action=action,
                   old_value=old_value, new_value=new_value, row_hash=row_hash)
    db.add(log)
    db.commit()

# ══════════════════════════════════════════════════════════════
#  SEED DATA
# ══════════════════════════════════════════════════════════════
def seed_database(db: Session):
    if db.query(User).count() > 0:
        # Migrate existing DB: add duty columns if missing (for upgrades)
        _migrate_employee_columns(db)
        return

    seed_users = [
        {"id": "u_admin",   "username": "admin",   "password": "Admin@123",   "role": "admin",   "name": "HR Admin",          "emp_id": None},
        {"id": "u_manager", "username": "manager", "password": "Manager@123", "role": "manager", "name": "Technical Manager", "emp_id": None},
    ]
    for u in seed_users:
        db.add(User(id=u["id"], username=u["username"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"], name=u["name"], employee_id=u["emp_id"]))
    db.commit()
    print("✅ Database seeded — admin and manager accounts ready.")

def _migrate_employee_columns(db: Session):
    """Add new v3 columns to existing employee table if upgrading from v2."""
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    cols = [c["name"] for c in inspector.get_columns("employees")]
    with engine.connect() as conn:
        if "duty_type" not in cols:
            conn.execute(text("ALTER TABLE employees ADD COLUMN duty_type VARCHAR DEFAULT 'OFFICE'"))
            conn.commit()
            print("✅ Migrated: added duty_type column.")
        if "assigned_lat" not in cols:
            conn.execute(text("ALTER TABLE employees ADD COLUMN assigned_lat FLOAT"))
            conn.commit()
            print("✅ Migrated: added assigned_lat column.")
        if "assigned_lng" not in cols:
            conn.execute(text("ALTER TABLE employees ADD COLUMN assigned_lng FLOAT"))
            conn.commit()
            print("✅ Migrated: added assigned_lng column.")
    # Seed manager user if not present
    mgr = db.query(User).filter(User.username == "manager").first()
    if not mgr:
        db.add(User(
            id="u_manager", username="manager",
            password_hash=hash_password("Manager@123"),
            role="manager", name="Technical Manager", employee_id=None,
        ))
        db.commit()
        print("✅ Seeded demo manager account.")

# ══════════════════════════════════════════════════════════════
#  PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════════════════
class LoginRequest(BaseModel):
    username: str
    password: str

class AttendanceRequest(BaseModel):
    employee_id: str
    status: str   # PRESENT | ABSENT_PL | ABSENT_EL | ABSENT_LOP

class SelfMarkRequest(BaseModel):
    current_lat: Optional[float] = None
    current_lng: Optional[float] = None

class DutyConfigRequest(BaseModel):
    duty_type: str              # OFFICE | ON_SITE | TRAVEL
    assigned_lat: Optional[float] = None
    assigned_lng: Optional[float] = None

class CandidateRequestBody(BaseModel):
    name: str
    email: str
    phone: str
    department: str
    position: str
    join_date: str
    address: Optional[str] = ""

class EditEmployeeBody(BaseModel):
    monthly_salary: int
    pl_balance: int
    el_balance: int
    username: str
    new_password: Optional[str] = None

class ChangeCredentialsBody(BaseModel):
    new_username: str
    new_password: str

# ══════════════════════════════════════════════════════════════
#  APP + CORS
# ══════════════════════════════════════════════════════════════
app = FastAPI(
    title="TrustAttend API",
    description="Secure Employee Attendance & Salary System — v3 with Multi-Role & GPS Check-In",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN] if ALLOWED_ORIGIN != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# ══════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════
@app.on_event("startup")
def startup():
    db = SessionLocal()
    seed_database(db)
    db.close()
    print(f"🚀 TrustAttend v3 backend running — port {PORT}")
    print(f"📂 Database : {_db_path}")
    print(f"🌐 CORS     : {ALLOWED_ORIGIN}")
    print(f"📖 API docs : http://localhost:{PORT}/docs")

# ══════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════
@app.post("/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username, User.is_active == True).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    token = create_token(user.id, user.role, user.employee_id)
    write_audit(db, user.id, user.employee_id or "N/A", "LOGIN", None, "SESSION_STARTED")

    return {
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "role": user.role,
            "username": user.username,
            "employee_id": user.employee_id,
        }
    }

@app.post("/auth/logout")
def logout(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    write_audit(db, payload["sub"], payload.get("employee_id", "N/A"), "LOGOUT", "SESSION_ACTIVE", None)
    return {"message": "Logged out."}

# ══════════════════════════════════════════════════════════════
#  EMPLOYEE ROUTES
# ══════════════════════════════════════════════════════════════
def _emp_to_dict(e: Employee, u=None) -> dict:
    return {
        "id": e.id, "user_id": e.user_id, "name": e.name,
        "department": e.department, "monthly_salary": e.monthly_salary,
        "pl_balance": e.pl_balance, "el_balance": e.el_balance,
        "join_date": e.join_date,
        "username": u.username if u else None,
        "duty_type": e.duty_type or "OFFICE",
        "assigned_lat": e.assigned_lat,
        "assigned_lng": e.assigned_lng,
    }

@app.get("/employees")
def list_employees(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    employees = db.query(Employee).all()
    users = {u.id: u for u in db.query(User).all()}
    return [_emp_to_dict(e, users.get(e.user_id)) for e in employees]

@app.get("/employees/{emp_id}")
def get_employee(emp_id: str, payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if payload["role"] == "employee" and payload.get("employee_id") != emp_id:
        raise HTTPException(status_code=403, detail="Access denied.")
    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")
    u = db.query(User).filter(User.id == emp.user_id).first()
    return _emp_to_dict(emp, u)

@app.put("/employees/{emp_id}")
def edit_employee(emp_id: str, body: EditEmployeeBody,
                  payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")
    user = db.query(User).filter(User.id == emp.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    conflict = db.query(User).filter(User.username == body.username, User.id != user.id).first()
    if conflict:
        raise HTTPException(status_code=400, detail="Username already taken.")

    old_val = f"salary:{emp.monthly_salary},pl:{emp.pl_balance},el:{emp.el_balance},user:{user.username}"
    emp.monthly_salary = body.monthly_salary
    emp.pl_balance = body.pl_balance
    emp.el_balance = body.el_balance
    user.username = body.username
    if body.new_password:
        user.password_hash = hash_password(body.new_password)

    new_val = f"salary:{body.monthly_salary},pl:{body.pl_balance},el:{body.el_balance},user:{body.username}"
    db.commit()
    write_audit(db, payload["sub"], emp_id, "EDIT_EMPLOYEE", old_val, new_val)
    return {"message": "Employee updated."}

@app.delete("/employees/{emp_id}")
def delete_employee(emp_id: str, payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")
    emp_name = emp.name
    db.query(AttendanceRecord).filter(AttendanceRecord.employee_id == emp_id).delete()
    db.query(User).filter(User.id == emp.user_id).delete()
    db.delete(emp)
    db.commit()
    write_audit(db, payload["sub"], emp_id, "DELETE_EMPLOYEE", f"name:{emp_name}", None)
    return {"message": f"{emp_name} deleted successfully."}

# ── NEW: Manager duty-config endpoint ─────────────────────────
@app.put("/employees/{emp_id}/duty-config")
def update_duty_config(emp_id: str, body: DutyConfigRequest,
                       payload: dict = Depends(require_manager),
                       db: Session = Depends(get_db)):
    """
    Technical Manager only: update duty_type, assigned_lat, assigned_lng.
    duty_type must be one of: OFFICE, ON_SITE, TRAVEL
    """
    valid_duty_types = {"OFFICE", "ON_SITE", "TRAVEL"}
    if body.duty_type not in valid_duty_types:
        raise HTTPException(status_code=400,
                            detail=f"Invalid duty_type. Must be one of: {valid_duty_types}")

    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")

    # Validate lat/lng required for ON_SITE
    if body.duty_type == "ON_SITE":
        if body.assigned_lat is None or body.assigned_lng is None:
            raise HTTPException(status_code=400,
                                detail="assigned_lat and assigned_lng are required for ON_SITE duty type.")

    old_val = f"duty:{emp.duty_type},lat:{emp.assigned_lat},lng:{emp.assigned_lng}"
    emp.duty_type    = body.duty_type
    emp.assigned_lat = body.assigned_lat if body.duty_type == "ON_SITE" else None
    emp.assigned_lng = body.assigned_lng if body.duty_type == "ON_SITE" else None
    db.commit()

    new_val = f"duty:{emp.duty_type},lat:{emp.assigned_lat},lng:{emp.assigned_lng}"
    write_audit(db, payload["sub"], emp_id, "UPDATE_DUTY_CONFIG", old_val, new_val)
    return {
        "message": "Duty configuration updated.",
        "employee_id": emp_id,
        "duty_type": emp.duty_type,
        "assigned_lat": emp.assigned_lat,
        "assigned_lng": emp.assigned_lng,
    }

# ══════════════════════════════════════════════════════════════
#  ATTENDANCE ROUTES
# ══════════════════════════════════════════════════════════════
@app.get("/attendance")
def get_attendance(month: Optional[str] = None, payload: dict = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    query = db.query(AttendanceRecord)
    if payload["role"] == "employee":
        query = query.filter(AttendanceRecord.employee_id == payload.get("employee_id"))
    if month:
        query = query.filter(AttendanceRecord.date.startswith(month))
    records = query.all()
    return [{"id": r.id, "employee_id": r.employee_id, "date": r.date,
             "status": r.status, "marked_by": r.marked_by,
             "marked_at": r.marked_at, "hash": r.row_hash} for r in records]

@app.get("/attendance/today")
def get_today_attendance(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    # Admin and manager can view today's attendance
    if payload.get("role") not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Admin or Manager access required.")
    today = today_iso()
    records = db.query(AttendanceRecord).filter(AttendanceRecord.date == today).all()
    return [{"id": r.id, "employee_id": r.employee_id, "date": r.date,
             "status": r.status, "marked_by": r.marked_by,
             "marked_at": r.marked_at, "hash": r.row_hash} for r in records]

@app.post("/attendance/mark")
def mark_attendance(body: AttendanceRequest, payload: dict = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """Admin/HR marks attendance manually — intended for OFFICE employees."""
    valid_statuses = {"PRESENT", "ABSENT_PL", "ABSENT_EL", "ABSENT_LOP"}
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    emp = db.query(Employee).filter(Employee.id == body.employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")

    today = today_iso()
    existing = db.query(AttendanceRecord).filter(
        AttendanceRecord.employee_id == body.employee_id,
        AttendanceRecord.date == today
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Attendance already marked for today.")

    record_id = gen_id("att")
    marked_at = now_iso()
    canonical = attendance_canonical(record_id, body.employee_id, today, body.status, payload["sub"], marked_at)
    row_hash = sha256_str(canonical)

    record = AttendanceRecord(
        id=record_id, employee_id=body.employee_id, date=today,
        status=body.status, marked_by=payload["sub"],
        marked_at=marked_at, row_hash=row_hash
    )
    db.add(record)

    if body.status == "ABSENT_PL" and emp.pl_balance > 0:
        emp.pl_balance -= 1
    elif body.status == "ABSENT_EL" and emp.el_balance > 0:
        emp.el_balance -= 1

    db.commit()
    write_audit(db, payload["sub"], body.employee_id, f"MARK_{body.status}", "NOT_MARKED", body.status)
    return {"message": "Attendance marked.", "record_id": record_id, "hash": row_hash}

# ── NEW: Employee Self-Mark endpoint ──────────────────────────
@app.post("/attendance/self-mark")
def self_mark_attendance(body: SelfMarkRequest,
                         payload: dict = Depends(require_employee),
                         db: Session = Depends(get_db)):
    """
    Employee self check-in based on their duty_type:

    OFFICE  → Blocked. HR/Admin must mark manually.
    TRAVEL  → Instant TRAVEL status logged, no GPS required.
    ON_SITE → Haversine GPS check against assigned_lat/lng.
              Blocked if distance > 100 metres.
              Logs as PRESENT if within 100 metres.
    """
    emp_id = payload.get("employee_id")
    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee profile not found.")

    duty = (emp.duty_type or "OFFICE").upper()

    # ── OFFICE: blocked ────────────────────────────────────────
    if duty == "OFFICE":
        raise HTTPException(
            status_code=403,
            detail="Office duty employees cannot self-mark. Your HR/Admin will log your attendance."
        )

    today = today_iso()
    existing = db.query(AttendanceRecord).filter(
        AttendanceRecord.employee_id == emp_id,
        AttendanceRecord.date == today
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Attendance already marked for today.")

    # ── TRAVEL: instant log, no GPS ──────────────────────────
    if duty == "TRAVEL":
        final_status = "TRAVEL"
        record_id = gen_id("att")
        marked_at = now_iso()
        canonical = attendance_canonical(record_id, emp_id, today, final_status, payload["sub"], marked_at)
        row_hash = sha256_str(canonical)
        db.add(AttendanceRecord(
            id=record_id, employee_id=emp_id, date=today,
            status=final_status, marked_by=payload["sub"],
            marked_at=marked_at, row_hash=row_hash
        ))
        db.commit()
        write_audit(db, payload["sub"], emp_id, "SELF_MARK_TRAVEL", "NOT_MARKED", "TRAVEL")
        return {
            "message": "Travel check-in recorded. Have a safe journey!",
            "status": "TRAVEL",
            "record_id": record_id,
            "hash": row_hash,
        }

    # ── ON_SITE: GPS Haversine check ─────────────────────────
    if duty == "ON_SITE":
        if body.current_lat is None or body.current_lng is None:
            raise HTTPException(status_code=400, detail="current_lat and current_lng are required for ON_SITE check-in.")

        if emp.assigned_lat is None or emp.assigned_lng is None:
            raise HTTPException(
                status_code=503,
                detail="Your site coordinates have not been configured yet. Please contact the Technical Manager."
            )

        distance = haversine_metres(
            body.current_lat, body.current_lng,
            emp.assigned_lat, emp.assigned_lng
        )

        if distance > 100:
            raise HTTPException(
                status_code=403,
                detail=f"Check-in denied. You are {distance:.0f}m from your assigned site. Must be within 100 metres."
            )

        final_status = "PRESENT"
        record_id = gen_id("att")
        marked_at = now_iso()
        canonical = attendance_canonical(record_id, emp_id, today, final_status, payload["sub"], marked_at)
        row_hash = sha256_str(canonical)
        db.add(AttendanceRecord(
            id=record_id, employee_id=emp_id, date=today,
            status=final_status, marked_by=payload["sub"],
            marked_at=marked_at, row_hash=row_hash
        ))
        db.commit()
        write_audit(db, payload["sub"], emp_id, "SELF_MARK_ON_SITE",
                    "NOT_MARKED", f"PRESENT (dist:{distance:.0f}m)")
        return {
            "message": f"GPS check-in successful! You are {distance:.0f}m from your site.",
            "status": "PRESENT",
            "distance_metres": round(distance, 1),
            "record_id": record_id,
            "hash": row_hash,
        }

    raise HTTPException(status_code=400, detail=f"Unknown duty_type: {duty}")

# ── Integrity verification ─────────────────────────────────────
@app.get("/attendance/integrity")
def verify_integrity(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if payload.get("role") not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Admin or Manager access required.")
    records = db.query(AttendanceRecord).all()
    results = []
    for r in records:
        canonical = attendance_canonical(r.id, r.employee_id, r.date, r.status, r.marked_by, r.marked_at)
        expected = sha256_str(canonical)
        results.append({
            "record": {"id": r.id, "employee_id": r.employee_id, "date": r.date,
                       "status": r.status, "marked_by": r.marked_by,
                       "marked_at": r.marked_at, "hash": r.row_hash},
            "tampered": expected != r.row_hash,
            "expected_hash": expected,
        })
    return results

# ══════════════════════════════════════════════════════════════
#  SALARY ROUTES
# ══════════════════════════════════════════════════════════════
@app.get("/salary")
def salary_summary(month: str, payload: dict = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    if payload["role"] == "employee":
        employees = db.query(Employee).filter(Employee.id == payload.get("employee_id")).all()
    else:
        employees = db.query(Employee).all()

    records = db.query(AttendanceRecord).filter(AttendanceRecord.date.startswith(month)).all()

    year, mon = map(int, month.split("-"))
    import calendar
    days_in_month = calendar.monthrange(year, mon)[1]

    result = []
    for emp in employees:
        emp_recs = [r for r in records if r.employee_id == emp.id]
        per_day  = emp.monthly_salary / days_in_month if days_in_month > 0 else 0
        lop_days = sum(1 for r in emp_recs if r.status == "ABSENT_LOP")
        pl_days  = sum(1 for r in emp_recs if r.status == "ABSENT_PL")
        el_days  = sum(1 for r in emp_recs if r.status == "ABSENT_EL")
        present  = sum(1 for r in emp_recs if r.status == "PRESENT")
        # TRAVEL counts as fully paid — same as PRESENT, no deduction
        travel   = sum(1 for r in emp_recs if r.status == "TRAVEL")
        deduction = round(lop_days * per_day, 2)
        result.append({
            "employee_id":    emp.id,
            "name":           emp.name,
            "department":     emp.department,
            "monthly_salary": emp.monthly_salary,
            "pl_balance":     emp.pl_balance,
            "el_balance":     emp.el_balance,
            "days_in_month":  days_in_month,
            "per_day_salary": round(per_day, 2),
            "present_days":   present,
            "travel_days":    travel,
            "lop_days":       lop_days,
            "pl_days":        pl_days,
            "el_days":        el_days,
            "deduction":      deduction,
            "payable":        round(emp.monthly_salary - deduction, 2),
            "duty_type":      emp.duty_type or "OFFICE",
        })
    return result

# ══════════════════════════════════════════════════════════════
#  CANDIDATE ROUTES
# ══════════════════════════════════════════════════════════════
@app.post("/candidates")
def submit_candidate(body: CandidateRequestBody, db: Session = Depends(get_db)):
    req = CandidateRequest(
        id=gen_id("req"),
        name=body.name, email=body.email, phone=body.phone,
        department=body.department, position=body.position,
        join_date=body.join_date, address=body.address or "",
        submitted_at=now_iso(), status="pending",
    )
    db.add(req)
    db.commit()
    return {"message": "Request submitted.", "id": req.id}

@app.get("/candidates")
def list_candidates(payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    reqs = db.query(CandidateRequest).order_by(CandidateRequest.submitted_at.desc()).all()
    return [{
        "id": r.id, "name": r.name, "email": r.email, "phone": r.phone,
        "department": r.department, "position": r.position,
        "join_date": r.join_date, "address": r.address,
        "submitted_at": r.submitted_at, "status": r.status,
        "temp_username": r.temp_username,
        "temp_password": r.temp_password if r.status == "approved" else None,
        "approved_at": r.approved_at,
    } for r in reqs]

@app.post("/candidates/{req_id}/approve")
def approve_candidate(req_id: str, payload: dict = Depends(require_admin),
                      db: Session = Depends(get_db)):
    req = db.query(CandidateRequest).filter(CandidateRequest.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found.")
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Request already processed.")

    temp_username = gen_temp_username(req.name)
    temp_password = gen_temp_password()
    new_emp_id = gen_employee_id(db)
    new_user_id = f"u_{new_emp_id.lower()}"

    db.add(User(
        id=new_user_id, username=temp_username,
        password_hash=hash_password(temp_password),
        role="employee", name=req.name, employee_id=new_emp_id,
    ))
    db.add(Employee(
        id=new_emp_id, user_id=new_user_id, name=req.name,
        department=req.department, monthly_salary=0,
        pl_balance=12, el_balance=15, join_date=req.join_date,
        duty_type="OFFICE",
    ))
    req.status = "approved"
    req.temp_username = temp_username
    req.temp_password = temp_password
    req.approved_at = now_iso()

    db.commit()
    write_audit(db, payload["sub"], new_emp_id, "APPROVE_CANDIDATE", f"req:{req.name}", f"user:{temp_username}")
    return {"message": "Candidate approved.", "employee_id": new_emp_id,
            "temp_username": temp_username, "temp_password": temp_password}

@app.post("/candidates/{req_id}/reject")
def reject_candidate(req_id: str, payload: dict = Depends(require_admin),
                     db: Session = Depends(get_db)):
    req = db.query(CandidateRequest).filter(CandidateRequest.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found.")
    req.status = "rejected"
    db.commit()
    write_audit(db, payload["sub"], "N/A", "REJECT_CANDIDATE", f"req:{req.name}", "rejected")
    return {"message": "Request rejected."}

# ══════════════════════════════════════════════════════════════
#  AUDIT LOG ROUTES
# ══════════════════════════════════════════════════════════════
@app.get("/audit")
def get_audit_logs(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if payload.get("role") not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Admin or Manager access required.")
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(500).all()
    users = {u.id: u.name for u in db.query(User).all()}
    return [{
        "id": l.id, "timestamp": l.timestamp,
        "user_id": l.user_id, "performed_by": users.get(l.user_id, l.user_id),
        "employee_id": l.employee_id, "action": l.action,
        "old_value": l.old_value, "new_value": l.new_value,
        "hash": l.row_hash,
    } for l in logs]

# ══════════════════════════════════════════════════════════════
#  CREDENTIALS CHANGE
# ══════════════════════════════════════════════════════════════
@app.post("/auth/change-credentials")
def change_credentials(body: ChangeCredentialsBody,
                       payload: dict = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    conflict = db.query(User).filter(User.username == body.new_username, User.id != user.id).first()
    if conflict:
        raise HTTPException(status_code=400, detail="Username already taken.")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    old_username = user.username
    user.username = body.new_username
    user.password_hash = hash_password(body.new_password)
    db.commit()
    write_audit(db, user.id, payload.get("employee_id", "N/A"),
                "CHANGE_CREDENTIALS", f"user:{old_username}", f"user:{body.new_username}")
    return {"message": "Credentials updated successfully."}

# ══════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════
@app.get("/health")
def health():
    import platform
    return {
        "status": "ok",
        "service": "TrustAttend API",
        "version": "3.0.0",
        "python": platform.python_version(),
        "db_path": _db_path,
        "cors_origin": ALLOWED_ORIGIN,
        "features": ["multi-role", "duty-types", "gps-checkin", "travel-status"],
    }

# ══════════════════════════════════════════════════════════════
#  BACKUP
# ══════════════════════════════════════════════════════════════
@app.get("/backup")
def backup_data(payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    users      = [{"id":u.id,"username":u.username,"password_hash":u.password_hash,
                   "role":u.role,"name":u.name,"employee_id":u.employee_id,
                   "is_active":u.is_active} for u in db.query(User).all()]
    employees  = [{"id":e.id,"user_id":e.user_id,"name":e.name,"department":e.department,
                   "monthly_salary":e.monthly_salary,"pl_balance":e.pl_balance,
                   "el_balance":e.el_balance,"join_date":e.join_date,
                   "duty_type":e.duty_type,"assigned_lat":e.assigned_lat,
                   "assigned_lng":e.assigned_lng} for e in db.query(Employee).all()]
    attendance = [{"id":r.id,"employee_id":r.employee_id,"date":r.date,"status":r.status,
                   "marked_by":r.marked_by,"marked_at":r.marked_at,"row_hash":r.row_hash}
                  for r in db.query(AttendanceRecord).all()]
    audit      = [{"id":l.id,"timestamp":l.timestamp,"user_id":l.user_id,
                   "employee_id":l.employee_id,"action":l.action,
                   "old_value":l.old_value,"new_value":l.new_value,"row_hash":l.row_hash}
                  for l in db.query(AuditLog).all()]
    candidates = [{"id":c.id,"name":c.name,"email":c.email,"phone":c.phone,
                   "department":c.department,"position":c.position,"join_date":c.join_date,
                   "address":c.address,"submitted_at":c.submitted_at,"status":c.status,
                   "temp_username":c.temp_username,"temp_password":c.temp_password,
                   "approved_at":c.approved_at} for c in db.query(CandidateRequest).all()]
    return {
        "backup_at": now_iso(), "version": "3.0.0",
        "users": users, "employees": employees,
        "attendance": attendance, "audit_logs": audit, "candidate_requests": candidates,
    }

# ══════════════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    is_local = os.environ.get("RENDER") is None
    uvicorn.run(
        "trustattend_backend:app",
        host="0.0.0.0",
        port=PORT,
        reload=is_local,
        workers=1,
    )
