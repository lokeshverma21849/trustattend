"""
TrustAttend — Cloud-Ready Production Backend  v2.1.0
FastAPI + SQLite + SQLAlchemy + bcrypt + SHA-256 Integrity
==========================================================
Local run (Pydroid / PC):
    pip install -r requirements.txt
    python trustattend_backend.py

Render.com deployment:
    Build Command : pip install -r requirements.txt
    Start Command : uvicorn trustattend_backend:app --host 0.0.0.0 --port $PORT

Environment variables to set on Render dashboard:
    SECRET_KEY   → any long random string  (REQUIRED — change default!)
    ALLOWED_ORIGIN → https://your-frontend-domain.com  (or * for open)

Database note:
    Render free tier does NOT persist disk between deploys.
    SQLite is fine for testing / small teams on a paid Render plan with a Disk mount.
    For the free tier, data resets on each deploy — use the /backup endpoint
    to download a JSON dump before redeploying.
    Upgrade path: swap DATABASE_URL to a PostgreSQL URL from Render's free Postgres add-on.
"""

import hashlib
import json
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
from sqlalchemy import (Boolean, Column, DateTime, Integer, String, Text,
                        create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ══════════════════════════════════════════════════════════════
#  CONFIG  — all values can be overridden via environment vars
# ══════════════════════════════════════════════════════════════
SECRET_KEY     = os.environ.get("SECRET_KEY", "trustattend-super-secret-change-in-production-2024")
ALGORITHM      = "HS256"
TOKEN_EXPIRE   = 24   # hours
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")   # set to your frontend URL in prod

# ── Render.com PORT binding ──────────────────────────────────
# Render injects PORT automatically. Falls back to 8000 locally.
PORT = int(os.environ.get("PORT", 8000))

# ── Database path ────────────────────────────────────────────
# On Render free tier: ephemeral disk — data is lost on redeploy.
# On Render paid tier: mount a persistent disk at /data and set:
#   DB_PATH=/data/trustattend.db
# Locally (Pydroid / PC): defaults to ./trustattend.db
_db_path   = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustattend.db"))
DATABASE_URL = f"sqlite:///{_db_path}"

# Ensure the directory for the DB file exists (important for /data mounts)
os.makedirs(os.path.dirname(_db_path), exist_ok=True)

# ══════════════════════════════════════════════════════════════
#  DATABASE SETUP
# ══════════════════════════════════════════════════════════════
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Enable WAL mode for concurrent reads
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
    id          = Column(String, primary_key=True)
    username    = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role        = Column(String, nullable=False)          # 'admin' | 'employee'
    name        = Column(String, nullable=False)
    employee_id = Column(String, nullable=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active   = Column(Boolean, default=True)

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

class AttendanceRecord(Base):
    __tablename__ = "attendance"
    id          = Column(String, primary_key=True)
    employee_id = Column(String, nullable=False)
    date        = Column(String, nullable=False)          # ISO YYYY-MM-DD
    status      = Column(String, nullable=False)          # PRESENT | ABSENT_PL | ABSENT_EL | ABSENT_LOP
    marked_by   = Column(String, nullable=False)          # user_id of HR
    marked_at   = Column(String, nullable=False)          # ISO datetime string
    row_hash    = Column(String, nullable=False)          # SHA-256 tamper seal

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id          = Column(String, primary_key=True)
    timestamp   = Column(String, nullable=False)
    user_id     = Column(String, nullable=False)
    employee_id = Column(String, nullable=True)
    action      = Column(String, nullable=False)
    old_value   = Column(Text, nullable=True)
    new_value   = Column(Text, nullable=True)
    row_hash    = Column(String, nullable=False)          # SHA-256 tamper seal

class CandidateRequest(Base):
    __tablename__ = "candidate_requests"
    id           = Column(String, primary_key=True)
    name         = Column(String, nullable=False)
    email        = Column(String, nullable=False)
    phone        = Column(String, nullable=False)
    department   = Column(String, nullable=False)
    position     = Column(String, nullable=False)
    join_date    = Column(String, nullable=False)
    address      = Column(String, nullable=True)
    submitted_at = Column(String, nullable=False)
    status       = Column(String, default="pending")      # pending | approved | rejected
    temp_username = Column(String, nullable=True)
    temp_password = Column(String, nullable=True)         # stored plain for one-time display only
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
    suffix = random.randint(100, 999)
    return f"{base}{suffix}"

def gen_temp_password() -> str:
    chars = string.ascii_letters + string.digits
    return "Tmp@" + ''.join(random.choices(chars, k=8))

# ── Password ──────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ── SHA-256 row integrity ─────────────────────────────────────
def sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def attendance_canonical(record_id, emp_id, rec_date, status, marked_by, marked_at) -> str:
    return "|".join([record_id, emp_id, rec_date, status, marked_by, marked_at])

def audit_canonical(entry: dict) -> str:
    payload = {k: entry[k] for k in ["id", "timestamp", "user_id", "employee_id", "action", "old_value", "new_value"]}
    return json.dumps(payload, sort_keys=True)

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

# ── DB Dependency ─────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ── Auth dependency helpers ───────────────────────────────────
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return decode_token(credentials.credentials)

def require_admin(payload: dict = Depends(get_current_user)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return payload

def require_employee(payload: dict = Depends(get_current_user)):
    if payload.get("role") != "employee":
        raise HTTPException(status_code=403, detail="Employee access required.")
    return payload

# ── Audit log writer ──────────────────────────────────────────
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
#  SEED DATA (runs once on first startup)
# ══════════════════════════════════════════════════════════════
def seed_database(db: Session):
    if db.query(User).count() > 0:
        return  # Already seeded

    seed_users = [
        {"id": "u_admin", "username": "admin",  "password": "Admin@123", "role": "admin",    "name": "HR Admin",       "emp_id": None},
        {"id": "u_e001",  "username": "alice",  "password": "Alice@123", "role": "employee", "name": "Alice Johnson",  "emp_id": "E001"},
        {"id": "u_e002",  "username": "bob",    "password": "Bob@123",   "role": "employee", "name": "Bob Martinez",   "emp_id": "E002"},
        {"id": "u_e003",  "username": "carol",  "password": "Carol@123", "role": "employee", "name": "Carol Singh",    "emp_id": "E003"},
        {"id": "u_e004",  "username": "david",  "password": "David@123", "role": "employee", "name": "David Chen",     "emp_id": "E004"},
    ]
    for u in seed_users:
        db.add(User(id=u["id"], username=u["username"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"], name=u["name"], employee_id=u["emp_id"]))

    seed_employees = [
        {"id": "E001", "user_id": "u_e001", "name": "Alice Johnson", "dept": "Engineering", "salary": 85000, "pl": 12, "el": 15, "join": "2022-01-15"},
        {"id": "E002", "user_id": "u_e002", "name": "Bob Martinez",  "dept": "Marketing",   "salary": 72000, "pl": 10, "el": 15, "join": "2021-06-01"},
        {"id": "E003", "user_id": "u_e003", "name": "Carol Singh",   "dept": "Engineering", "salary": 95000, "pl": 8,  "el": 15, "join": "2020-03-20"},
        {"id": "E004", "user_id": "u_e004", "name": "David Chen",    "dept": "Finance",     "salary": 68000, "pl": 14, "el": 15, "join": "2023-02-10"},
    ]
    for e in seed_employees:
        db.add(Employee(id=e["id"], user_id=e["user_id"], name=e["name"],
                        department=e["dept"], monthly_salary=e["salary"],
                        pl_balance=e["pl"], el_balance=e["el"], join_date=e["join"]))
    db.commit()
    print("✅ Database seeded with demo data.")

# ══════════════════════════════════════════════════════════════
#  PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════════════════
class LoginRequest(BaseModel):
    username: str
    password: str

class AttendanceRequest(BaseModel):
    employee_id: str
    status: str   # PRESENT | ABSENT_PL | ABSENT_EL | ABSENT_LOP

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
    description="Secure Employee Attendance & Salary System",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    # In production set ALLOWED_ORIGIN env var to your exact frontend URL, e.g.:
    #   https://trustattend.onrender.com
    #   https://yourcompany.github.io
    # "*" is fine during development / testing.
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
    print(f"🚀 TrustAttend backend running — port {PORT}")
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
#  EMPLOYEE ROUTES (read-only for employees, managed by admin)
# ══════════════════════════════════════════════════════════════
@app.get("/employees")
def list_employees(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    employees = db.query(Employee).all()
    users = {u.id: u for u in db.query(User).all()}
    result = []
    for e in employees:
        u = users.get(e.user_id)
        result.append({
            "id": e.id, "user_id": e.user_id, "name": e.name,
            "department": e.department, "monthly_salary": e.monthly_salary,
            "pl_balance": e.pl_balance, "el_balance": e.el_balance,
            "join_date": e.join_date, "username": u.username if u else None,
        })
    return result

@app.get("/employees/{emp_id}")
def get_employee(emp_id: str, payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    # Employees can only see their own profile
    if payload["role"] == "employee" and payload.get("employee_id") != emp_id:
        raise HTTPException(status_code=403, detail="Access denied.")
    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")
    u = db.query(User).filter(User.id == emp.user_id).first()
    return {
        "id": emp.id, "user_id": emp.user_id, "name": emp.name,
        "department": emp.department, "monthly_salary": emp.monthly_salary,
        "pl_balance": emp.pl_balance, "el_balance": emp.el_balance,
        "join_date": emp.join_date, "username": u.username if u else None,
    }

@app.put("/employees/{emp_id}")
def edit_employee(emp_id: str, body: EditEmployeeBody,
                  payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    emp = db.query(Employee).filter(Employee.id == emp_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")

    user = db.query(User).filter(User.id == emp.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    # Check username conflict
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
    if emp_id == payload.get("employee_id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account.")

    emp_name = emp.name
    # Delete attendance records
    db.query(AttendanceRecord).filter(AttendanceRecord.employee_id == emp_id).delete()
    # Delete user account
    db.query(User).filter(User.id == emp.user_id).delete()
    # Delete employee
    db.delete(emp)
    db.commit()
    write_audit(db, payload["sub"], emp_id, "DELETE_EMPLOYEE", f"name:{emp_name}", None)
    return {"message": f"{emp_name} deleted successfully."}

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
def get_today_attendance(payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    today = today_iso()
    records = db.query(AttendanceRecord).filter(AttendanceRecord.date == today).all()
    return [{"id": r.id, "employee_id": r.employee_id, "date": r.date,
             "status": r.status, "marked_by": r.marked_by,
             "marked_at": r.marked_at, "hash": r.row_hash} for r in records]

@app.post("/attendance/mark")
def mark_attendance(body: AttendanceRequest, payload: dict = Depends(require_admin),
                    db: Session = Depends(get_db)):
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

    # Compute tamper-proof hash BEFORE saving
    canonical = attendance_canonical(record_id, body.employee_id, today, body.status, payload["sub"], marked_at)
    row_hash = sha256_str(canonical)

    record = AttendanceRecord(
        id=record_id, employee_id=body.employee_id, date=today,
        status=body.status, marked_by=payload["sub"],
        marked_at=marked_at, row_hash=row_hash
    )
    db.add(record)

    # Deduct leave balance
    if body.status == "ABSENT_PL" and emp.pl_balance > 0:
        emp.pl_balance -= 1
    elif body.status == "ABSENT_EL" and emp.el_balance > 0:
        emp.el_balance -= 1

    db.commit()
    write_audit(db, payload["sub"], body.employee_id, f"MARK_{body.status}", "NOT_MARKED", body.status)
    return {"message": "Attendance marked.", "record_id": record_id, "hash": row_hash}

# ── Integrity verification ─────────────────────────────────────
@app.get("/attendance/integrity")
def verify_integrity(payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
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
        per_day = emp.monthly_salary / days_in_month if days_in_month > 0 else 0
        lop_days = sum(1 for r in emp_recs if r.status == "ABSENT_LOP")
        pl_days  = sum(1 for r in emp_recs if r.status == "ABSENT_PL")
        el_days  = sum(1 for r in emp_recs if r.status == "ABSENT_EL")
        present  = sum(1 for r in emp_recs if r.status == "PRESENT")
        deduction = round(lop_days * per_day, 2)
        result.append({
            "employee_id": emp.id,
            "name": emp.name,
            "department": emp.department,
            "monthly_salary": emp.monthly_salary,
            "pl_balance": emp.pl_balance,
            "el_balance": emp.el_balance,
            "days_in_month": days_in_month,
            "per_day_salary": round(per_day, 2),
            "present_days": present,
            "lop_days": lop_days,
            "pl_days": pl_days,
            "el_days": el_days,
            "deduction": deduction,
            "payable": round(emp.monthly_salary - deduction, 2),
        })
    return result

# ══════════════════════════════════════════════════════════════
#  CANDIDATE REQUEST ROUTES
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

    # Create user (password stored hashed in DB)
    db.add(User(
        id=new_user_id, username=temp_username,
        password_hash=hash_password(temp_password),
        role="employee", name=req.name, employee_id=new_emp_id,
    ))
    # Create employee
    db.add(Employee(
        id=new_emp_id, user_id=new_user_id, name=req.name,
        department=req.department, monthly_salary=0,
        pl_balance=12, el_balance=15, join_date=req.join_date,
    ))
    # Update request
    req.status = "approved"
    req.temp_username = temp_username
    req.temp_password = temp_password  # plain shown once to HR
    req.approved_at = now_iso()

    db.commit()
    write_audit(db, payload["sub"], new_emp_id, "APPROVE_CANDIDATE", f"req:{req.name}", f"user:{temp_username}")

    return {
        "message": "Candidate approved.",
        "employee_id": new_emp_id,
        "temp_username": temp_username,
        "temp_password": temp_password,
    }

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
def get_audit_logs(payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
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
#  CREDENTIALS CHANGE (Employee only — own account)
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
        "version": "2.1.0",
        "python": platform.python_version(),
        "db_path": _db_path,
        "cors_origin": ALLOWED_ORIGIN,
    }

# ══════════════════════════════════════════════════════════════
#  BACKUP ENDPOINT — download all data as JSON before redeploying
#  (important on Render free tier where disk is ephemeral)
# ══════════════════════════════════════════════════════════════
from fastapi.responses import JSONResponse as _JSONResponse

@app.get("/backup")
def backup_data(payload: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Download a full JSON snapshot of all data. Use before redeploying on free Render tier."""
    users      = [{"id":u.id,"username":u.username,"password_hash":u.password_hash,
                   "role":u.role,"name":u.name,"employee_id":u.employee_id,
                   "is_active":u.is_active} for u in db.query(User).all()]
    employees  = [{"id":e.id,"user_id":e.user_id,"name":e.name,"department":e.department,
                   "monthly_salary":e.monthly_salary,"pl_balance":e.pl_balance,
                   "el_balance":e.el_balance,"join_date":e.join_date} for e in db.query(Employee).all()]
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
        "backup_at": now_iso(),
        "users": users, "employees": employees,
        "attendance": attendance, "audit_logs": audit, "candidate_requests": candidates,
    }

# ══════════════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # reload=True only locally; Render uses the Start Command directly via uvicorn CLI
    is_local = os.environ.get("RENDER") is None
    uvicorn.run(
        "trustattend_backend:app",
        host="0.0.0.0",
        port=PORT,
        reload=is_local,   # auto-reload in local dev, off on Render
        workers=1,         # SQLite supports only 1 writer; use Postgres for multi-worker
    )
