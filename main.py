"""Brightloop Subscription Management System - FastAPI + SQLModel."""
import calendar, hashlib, hmac, logging, os, re, secrets, smtplib, time
from datetime import date, timedelta
from email.message import EmailMessage
from typing import Optional
from urllib.parse import quote

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import JSON, Column, UniqueConstraint, func
from sqlalchemy.exc import IntegrityError
from sqlmodel import Field, Session, SQLModel, create_engine, select

SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
logger = logging.getLogger(__name__)
engine = create_engine(os.getenv("DB_URL", "sqlite:///brightloop.db"),
                       connect_args={"check_same_thread": False})

# ----------------------------------------------------------------- models
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    name: str = ""
    password_hash: str
    role: str = "customer"  # admin | staff | customer

class Product(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    type: str = "service"
    sales_price: float
    cost_price: float = 0
    notes: str = ""

class Variant(SQLModel, table=True):  # e.g. attribute=brand, value=Odoo, extra_price=560
    id: Optional[int] = Field(default=None, primary_key=True)
    product_id: int = Field(foreign_key="product.id", index=True)
    attribute: str
    value: str
    extra_price: float = 0

class Plan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    price: float
    billing_period: str  # daily|weekly|monthly|yearly
    min_quantity: int = 1
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    auto_close: bool = False
    closable: bool = True
    pausable: bool = True
    renewable: bool = True

class Tax(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    rate_pct: float

class Discount(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    kind: str  # fixed | percent
    value: float
    min_purchase: float = 0
    min_quantity: int = 0
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    usage_limit: Optional[int] = None
    used_count: int = 0
    product_id: Optional[int] = None  # set -> product discount, else whole-subscription

class QuoteTemplate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    validity_days: int = 30
    plan_id: int = Field(foreign_key="plan.id")
    lines: list = Field(default_factory=list, sa_column=Column(JSON))  # [{product_id, variant_id, quantity, tax_id}]

class Subscription(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    number: str = Field(unique=True, index=True)
    customer_id: int = Field(foreign_key="user.id", index=True)
    plan_id: int = Field(foreign_key="plan.id")
    start_date: date
    expiry_date: Optional[date] = None
    payment_terms_days: int = 15
    status: str = Field(default="draft", index=True)
    paused: bool = False
    next_invoice_date: Optional[date] = Field(default=None, index=True)

class SubLine(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    subscription_id: int = Field(foreign_key="subscription.id", index=True)
    product_id: int = Field(foreign_key="product.id")
    variant_id: Optional[int] = None
    quantity: int = 1
    unit_price: float = 0
    tax_id: Optional[int] = None

class Invoice(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("subscription_id", "period_start"),)  # never billed twice
    id: Optional[int] = Field(default=None, primary_key=True)
    number: str = Field(unique=True, index=True)
    subscription_id: int = Field(foreign_key="subscription.id", index=True)
    customer_id: int = Field(index=True)
    period_start: date
    period_end: date
    status: str = Field(default="draft", index=True)  # draft|confirmed|paid|cancelled
    subtotal: float = 0
    discount_total: float = 0
    tax_total: float = 0
    total: float = 0
    paid_amount: float = 0
    due_date: date = Field(index=True)

class InvoiceLine(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    invoice_id: int = Field(foreign_key="invoice.id", index=True)
    description: str
    quantity: int
    unit_price: float
    discount: float = 0
    tax_rate: float = 0
    amount: float

class Payment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    invoice_id: int = Field(foreign_key="invoice.id", index=True)
    method: str
    amount: float
    paid_on: date
    note: str = ""

# ----------------------------------------------------------------- auth
def hash_pw(pw: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

def check_pw(pw: str, stored: str) -> bool:
    return hmac.compare_digest(hash_pw(pw, stored.split("$")[0]), stored)

def validate_password(pw: str):
    if not (len(pw) > 8 and re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw)
            and re.search(r"[^A-Za-z0-9]", pw)):
        raise HTTPException(422, "Password must be >8 chars with uppercase, lowercase and a special character")

def normalized_email(email: str) -> str:
    value = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise HTTPException(422, "A valid email address is required")
    return value

def token_for(u: User, minutes=720, purpose="access") -> str:
    return jwt.encode({"sub": str(u.id), "purpose": purpose, "exp": int(time.time()) + minutes * 60}, SECRET, "HS256")

bearer = HTTPBearer()
def get_session():
    with Session(engine) as s:
        yield s

def current_user(c: HTTPAuthorizationCredentials = Depends(bearer), s: Session = Depends(get_session)) -> User:
    try:
        data = jwt.decode(c.credentials, SECRET, ["HS256"])
        assert data["purpose"] == "access"
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    u = s.get(User, int(data["sub"]))
    if not u:
        raise HTTPException(401, "Unknown user")
    return u

def role(*roles):
    def dep(u: User = Depends(current_user)):
        if u.role not in roles:
            raise HTTPException(403, "Not allowed")
        return u
    return dep

ADMIN, STAFF = role("admin"), role("admin", "staff")

# ----------------------------------------------------------------- helpers
def add_period(d: date, period: str) -> date:
    if period == "daily": return d + timedelta(days=1)
    if period == "weekly": return d + timedelta(days=7)
    months = 1 if period == "monthly" else 12
    m = d.month - 1 + months
    y, m = d.year + m // 12, m % 12 + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))

def r2(x): return round(x + 1e-9, 2)

def discount_ok(d: Discount, today: date) -> bool:
    return ((d.start_date is None or d.start_date <= today) and (d.end_date is None or today <= d.end_date)
            and (d.usage_limit is None or d.used_count < d.usage_limit))

def disc_amount(d: Discount, base: float) -> float:
    return min(base, base * d.value / 100 if d.kind == "percent" else d.value)

# ----------------------------------------------------------------- billing engine
def build_invoice(s: Session, sub: Subscription, today: date) -> Invoice:
    plan = s.get(Plan, sub.plan_id)
    p_start = sub.next_invoice_date
    p_end = add_period(p_start, plan.billing_period) - timedelta(days=1)
    inv = Invoice(number=f"INV-{sub.id:05d}-{p_start:%Y%m%d}", subscription_id=sub.id, customer_id=sub.customer_id,
                  period_start=p_start, period_end=p_end, due_date=today + timedelta(days=sub.payment_terms_days))
    s.add(inv); s.flush()
    lines = s.exec(select(SubLine).where(SubLine.subscription_id == sub.id)).all()
    discounts = [d for d in s.exec(select(Discount)).all() if discount_ok(d, today)]
    rows, total_qty, subtotal = [], 0, 0.0
    if plan.price:
        rows.append({"l": None, "product_id": None, "name": plan.name, "quantity": 1,
                     "unit_price": plan.price, "amt": plan.price, "disc": 0.0, "rate": 0})
        subtotal += plan.price
        total_qty += 1
    for l in lines:
        prod = s.get(Product, l.product_id)
        tax = s.get(Tax, l.tax_id) if l.tax_id else None
        amt = l.quantity * l.unit_price
        rows.append({"l": l, "product_id": l.product_id, "name": prod.name, "quantity": l.quantity,
                     "unit_price": l.unit_price, "amt": amt, "disc": 0.0, "rate": tax.rate_pct if tax else 0})
        subtotal += amt; total_qty += l.quantity
    used = set()
    for d in (x for x in discounts if x.product_id):  # product-level
        for r in rows:
            if r["product_id"] == d.product_id and r["amt"] >= d.min_purchase and r["quantity"] >= d.min_quantity:
                r["disc"] += disc_amount(d, r["amt"] - r["disc"]); used.add(d.id)
    net = sum(r["amt"] - r["disc"] for r in rows)
    sub_disc = 0.0
    for d in (x for x in discounts if not x.product_id):  # subscription-level
        if net >= d.min_purchase and total_qty >= d.min_quantity:
            sub_disc += disc_amount(d, net - sub_disc); used.add(d.id)
    factor = (net - sub_disc) / net if net else 1
    tax_total = sum((r["amt"] - r["disc"]) * r["rate"] / 100 for r in rows) * factor
    for r in rows:
        s.add(InvoiceLine(invoice_id=inv.id, description=r["name"], quantity=r["quantity"], unit_price=r["unit_price"],
                          discount=r2(r["disc"]), tax_rate=r["rate"], amount=r2(r["amt"] - r["disc"])))
    for did in used:
        s.get(Discount, did).used_count += 1
    inv.subtotal = r2(subtotal)
    inv.discount_total = r2(subtotal - net + sub_disc)
    inv.tax_total = r2(tax_total)
    inv.total = r2(net - sub_disc + tax_total)
    sub.next_invoice_date = add_period(p_start, plan.billing_period)
    if sub.expiry_date and sub.next_invoice_date > sub.expiry_date:
        sub.next_invoice_date = None
        if plan.auto_close: sub.status = "closed"
    return inv

# ----------------------------------------------------------------- app
app = FastAPI(title="Brightloop Subscription Management")

@app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        if not s.exec(select(User).where(User.role == "admin")).first():
            s.add(User(email=os.getenv("ADMIN_EMAIL", "admin@brightloop.io"), name="Admin", role="admin",
                       password_hash=hash_pw(os.getenv("ADMIN_PASSWORD", "Admin@12345"))))
            s.commit()

class Signup(BaseModel):
    email: str; password: str; name: str = ""

@app.post("/auth/signup", status_code=201)
def signup(b: Signup, s: Session = Depends(get_session)):
    validate_password(b.password)
    email = normalized_email(b.email)
    if s.exec(select(User).where(User.email == email)).first():
        raise HTTPException(409, "Email already registered")
    u = User(email=email, name=b.name.strip(), password_hash=hash_pw(b.password)); s.add(u)
    try:
        s.commit()
    except IntegrityError:
        s.rollback()
        raise HTTPException(409, "Email already registered")
    return {"id": u.id, "email": u.email, "role": u.role}

class Login(BaseModel):
    email: str; password: str

@app.post("/auth/login")
def login(b: Login, s: Session = Depends(get_session)):
    u = s.exec(select(User).where(User.email == normalized_email(b.email))).first()
    if not u or not check_pw(b.password, u.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": token_for(u), "role": u.role}

class ForgotPassword(BaseModel):
    email: str

class ResetPassword(BaseModel):
    token: str
    password: str

def send_password_reset(email: str, token: str):
    host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    if not host or not sender:
        raise HTTPException(503, "Password reset email is not configured")
    base_url = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
    reset_url = f"{base_url}/?reset_token={quote(token)}"
    message = EmailMessage()
    message["Subject"] = "Reset your Brightloop password"
    message["From"] = sender
    message["To"] = email
    message.set_content(f"Use this link within 30 minutes to reset your password:\n\n{reset_url}\n")
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
        if not 1 <= port <= 65535:
            raise ValueError("SMTP_PORT must be between 1 and 65535")
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
                smtp.starttls()
            username = os.getenv("SMTP_USERNAME")
            password = os.getenv("SMTP_PASSWORD")
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        raise HTTPException(502, "Password reset email could not be sent") from exc

@app.post("/auth/forgot")
def forgot(b: ForgotPassword, s: Session = Depends(get_session)):
    email = normalized_email(b.email)
    if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_FROM"):
        raise HTTPException(503, "Password reset email is not configured")
    u = s.exec(select(User).where(User.email == email)).first()
    if u:
        try:
            send_password_reset(u.email, token_for(u, 30, "reset"))
        except HTTPException:
            logger.exception("Password reset email could not be delivered")
    return {"detail": "If the email is registered, a reset link has been sent"}

@app.post("/auth/reset")
def reset(b: ResetPassword, s: Session = Depends(get_session)):
    try:
        data = jwt.decode(b.token, SECRET, algorithms=["HS256"])
        if data.get("purpose") != "reset":
            raise jwt.InvalidTokenError("Unexpected token purpose")
        user_id = int(data["sub"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise HTTPException(400, "Invalid or expired token")
    validate_password(b.password)
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(400, "Invalid or expired token")
    u.password_hash = hash_pw(b.password)
    s.commit()
    return {"detail": "Password updated"}

@app.get("/auth/me")
def auth_me(u: User = Depends(current_user)):
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role}

@app.post("/staff", status_code=201)
def add_staff(b: Signup, _: User = Depends(ADMIN), s: Session = Depends(get_session)):
    validate_password(b.password)
    email = normalized_email(b.email)
    if s.exec(select(User).where(User.email == email)).first():
        raise HTTPException(409, "Email already registered")
    u = User(email=email, name=b.name.strip(), role="staff", password_hash=hash_pw(b.password)); s.add(u)
    try:
        s.commit()
    except IntegrityError:
        s.rollback()
        raise HTTPException(409, "Email already registered")
    return {"id": u.id, "email": u.email, "role": u.role}

@app.get("/customers")
def list_customers(skip: int = 0, limit: int = 50, _: User = Depends(STAFF), s: Session = Depends(get_session)):
    customers = s.exec(select(User).where(User.role == "customer").order_by(User.id)
                       .offset(skip).limit(min(limit, 200))).all()
    return [{"id": customer.id, "email": customer.email, "name": customer.name} for customer in customers]

# ---- generic admin-managed catalogue CRUD (products, variants, plans, taxes, discounts, templates)
def crud(path, model, write=ADMIN, read=STAFF):
    @app.post(f"/{path}", status_code=201, name=f"create_{path}")
    def create(b: model, _: User = Depends(write), s: Session = Depends(get_session)):
        b.id = None; s.add(b); s.commit(); s.refresh(b); return b
    @app.get(f"/{path}", name=f"list_{path}")
    def list_(skip: int = 0, limit: int = 50, u: User = Depends(current_user), s: Session = Depends(get_session)):
        if u.role == "customer" and model not in (Product, Plan, Variant):
            raise HTTPException(403, "Not allowed")
        records = s.exec(select(model).offset(skip).limit(min(limit, 200))).all()
        if u.role == "customer" and model is Product:
            return [{"id": item.id, "name": item.name, "type": item.type, "sales_price": item.sales_price}
                    for item in records]
        return records
    @app.put(f"/{path}/{{item_id}}", name=f"update_{path}")
    def update(item_id: int, b: model, _: User = Depends(write), s: Session = Depends(get_session)):
        o = s.get(model, item_id)
        if not o: raise HTTPException(404)
        for k, v in b.dict(exclude={"id"}).items(): setattr(o, k, v)
        s.commit(); return o
    @app.delete(f"/{path}/{{item_id}}", name=f"delete_{path}")
    def delete(item_id: int, _: User = Depends(write), s: Session = Depends(get_session)):
        o = s.get(model, item_id)
        if not o: raise HTTPException(404)
        s.delete(o); s.commit(); return {"deleted": item_id}

for p, m in [("products", Product), ("variants", Variant), ("plans", Plan), ("taxes", Tax),
             ("discounts", Discount), ("templates", QuoteTemplate)]:
    crud(p, m)

@app.get("/products/{pid}/price")
def price(pid: int, variant_id: Optional[int] = None, s: Session = Depends(get_session), _: User = Depends(current_user)):
    p = s.get(Product, pid); v = s.get(Variant, variant_id) if variant_id else None
    return {"unit_price": p.sales_price + (v.extra_price if v else 0)}

# ---- subscriptions
class LineIn(BaseModel):
    product_id: int; variant_id: Optional[int] = None; quantity: int = 1; tax_id: Optional[int] = None

class AddOnIn(BaseModel):
    product_id: int
    variant_id: Optional[int] = None
    quantity: int = 1

class SubIn(BaseModel):
    customer_id: int
    plan_id: Optional[int] = None
    template_id: Optional[int] = None
    start_date: date
    expiry_date: Optional[date] = None
    payment_terms_days: int = 15
    lines: list[LineIn] = []

@app.post("/subscriptions", status_code=201)
def create_sub(b: SubIn, u: User = Depends(current_user), s: Session = Depends(get_session)):
    if u.role == "customer" and b.customer_id != u.id:
        raise HTTPException(403, "Customers may only create their own subscriptions")
    if u.role not in ("admin", "staff", "customer"):
        raise HTTPException(403, "Not allowed")
    customer = s.get(User, b.customer_id)
    if not customer or customer.role != "customer":
        raise HTTPException(422, "A valid customer account is required")
    plan_id, lines, expiry = b.plan_id, b.lines, b.expiry_date
    if b.template_id:  # start from quotation template
        t = s.get(QuoteTemplate, b.template_id)
        if not t: raise HTTPException(404, "Template not found")
        plan_id = plan_id or t.plan_id
        lines = lines or [LineIn(**x) for x in t.lines]
        expiry = expiry or b.start_date + timedelta(days=t.validity_days)
    plan = s.get(Plan, plan_id) if plan_id else None
    if not plan: raise HTTPException(422, "A plan or template is required")
    if plan.start_date and b.start_date < plan.start_date:
        raise HTTPException(422, "The plan is not available yet")
    if plan.end_date and b.start_date > plan.end_date:
        raise HTTPException(422, "The plan is no longer available")
    count = s.exec(select(func.count()).select_from(Subscription)).one()
    sub = Subscription(number=f"SUB-{count + 1:06d}", customer_id=b.customer_id, plan_id=plan.id, start_date=b.start_date,
                       expiry_date=expiry, payment_terms_days=b.payment_terms_days)
    s.add(sub); s.flush()
    for l in lines:
        if l.quantity <= 0 or l.quantity < plan.min_quantity:
            raise HTTPException(422, f"Minimum quantity for this plan is {plan.min_quantity}")
        prod = s.get(Product, l.product_id)
        if not prod:
            raise HTTPException(422, "Product not found")
        v = s.get(Variant, l.variant_id) if l.variant_id else None
        if l.variant_id and (not v or v.product_id != prod.id):
            raise HTTPException(422, "Variant does not belong to this product")
        if l.tax_id and not s.get(Tax, l.tax_id):
            raise HTTPException(422, "Tax not found")
        s.add(SubLine(subscription_id=sub.id, product_id=l.product_id, variant_id=l.variant_id, quantity=l.quantity,
                      tax_id=l.tax_id, unit_price=prod.sales_price + (v.extra_price if v else 0)))
    s.commit(); s.refresh(sub); return sub

FLOW = {"draft": ["quotation"], "quotation": ["confirmed", "draft"], "confirmed": ["active"], "active": ["closed"]}

@app.post("/subscriptions/{sid}/transition")
def transition(sid: int, b: dict, u: User = Depends(current_user), s: Session = Depends(get_session)):
    sub = s.get(Subscription, sid)
    if not sub or (u.role == "customer" and sub.customer_id != u.id):
        raise HTTPException(404, "Subscription not found")
    to = b.get("to")
    if u.role == "customer" and to not in ("pause", "resume", "renew"):
        raise HTTPException(403, "Customers may pause, resume, or renew their own subscriptions")
    if u.role not in ("admin", "staff", "customer"):
        raise HTTPException(403, "Not allowed")
    plan = s.get(Plan, sub.plan_id)
    if to == "pause":
        if sub.status != "active" or sub.paused:
            raise HTTPException(409, "Only active subscriptions can be paused")
        if not plan.pausable: raise HTTPException(409, "Plan cannot be paused")
        sub.paused = True
    elif to == "resume":
        if sub.status != "active" or not sub.paused:
            raise HTTPException(409, "Only paused active subscriptions can be resumed")
        sub.paused = False
    elif to == "renew":
        if sub.status not in ("active", "closed"):
            raise HTTPException(409, "Only active or closed subscriptions can be renewed")
        if not plan.renewable: raise HTTPException(409, "Plan cannot be renewed")
        base = sub.expiry_date or date.today()
        sub.expiry_date = add_period(base, plan.billing_period)
        sub.status = "active"; sub.next_invoice_date = sub.next_invoice_date or base + timedelta(days=1)
    else:
        if to not in FLOW.get(sub.status, []): raise HTTPException(409, f"Cannot go from {sub.status} to {to}")
        if to == "closed" and not plan.closable: raise HTTPException(409, "Plan cannot be closed early")
        sub.status = to
        if to == "active": sub.next_invoice_date = sub.next_invoice_date or sub.start_date
    s.commit(); return sub

@app.get("/subscriptions/{sid}")
def subscription_details(sid: int, u: User = Depends(current_user), s: Session = Depends(get_session)):
    sub = s.get(Subscription, sid)
    if not sub or (u.role == "customer" and sub.customer_id != u.id):
        raise HTTPException(404, "Subscription not found")
    lines = s.exec(select(SubLine).where(SubLine.subscription_id == sid)).all()
    return {"subscription": sub, "lines": lines}

@app.post("/subscriptions/{sid}/addons", status_code=201)
def add_subscription_addon(sid: int, b: AddOnIn, u: User = Depends(current_user), s: Session = Depends(get_session)):
    sub = s.get(Subscription, sid)
    if not sub or (u.role == "customer" and sub.customer_id != u.id):
        raise HTTPException(404, "Subscription not found")
    if sub.status != "active":
        raise HTTPException(409, "Add-ons can only be changed on active subscriptions")
    product = s.get(Product, b.product_id)
    if not product or product.type.lower() != "addon":
        raise HTTPException(422, "Choose a product configured as an add-on")
    if b.quantity <= 0:
        raise HTTPException(422, "Add-on quantity must be greater than zero")
    variant = s.get(Variant, b.variant_id) if b.variant_id else None
    if b.variant_id and (not variant or variant.product_id != product.id):
        raise HTTPException(422, "Variant does not belong to this product")
    tax_line = s.exec(select(SubLine).where(SubLine.subscription_id == sub.id,
                                            SubLine.tax_id.is_not(None))).first()
    line = SubLine(subscription_id=sub.id, product_id=product.id, variant_id=b.variant_id,
                   quantity=b.quantity, tax_id=tax_line.tax_id if tax_line else None,
                   unit_price=product.sales_price + (variant.extra_price if variant else 0))
    s.add(line)
    s.commit()
    s.refresh(line)
    return line

@app.delete("/subscriptions/{sid}/addons/{line_id}")
def remove_subscription_addon(sid: int, line_id: int, u: User = Depends(current_user), s: Session = Depends(get_session)):
    sub = s.get(Subscription, sid)
    if not sub or (u.role == "customer" and sub.customer_id != u.id):
        raise HTTPException(404, "Subscription not found")
    if sub.status != "active":
        raise HTTPException(409, "Add-ons can only be changed on active subscriptions")
    line = s.get(SubLine, line_id)
    if not line or line.subscription_id != sub.id:
        raise HTTPException(404, "Add-on not found")
    product = s.get(Product, line.product_id)
    if not product or product.type.lower() != "addon":
        raise HTTPException(409, "Only add-on products can be removed here")
    s.delete(line)
    s.commit()
    return {"deleted": line_id, "effective": "next_invoice"}

@app.get("/subscriptions")
def list_subs(status: Optional[str] = None, skip: int = 0, limit: int = 50,
              u: User = Depends(current_user), s: Session = Depends(get_session)):
    q = select(Subscription)
    if u.role == "customer": q = q.where(Subscription.customer_id == u.id)
    if status: q = q.where(Subscription.status == status)
    return s.exec(q.order_by(Subscription.id.desc()).offset(skip).limit(min(limit, 200))).all()

# ---- invoices
@app.post("/billing/run")
def run_billing(today: Optional[date] = None, _: User = Depends(STAFF), s: Session = Depends(get_session)):
    """Create invoices for every due active subscription. Idempotent."""
    today = today or date.today()
    due = s.exec(select(Subscription).where(Subscription.status == "active", Subscription.paused == False,  # noqa
                                            Subscription.next_invoice_date <= today)).all()
    created = skipped = 0
    for sub in due:
        while sub.next_invoice_date and sub.next_invoice_date <= today and sub.status == "active":  # catch up missed periods
            try:
                build_invoice(s, sub, today); s.commit(); created += 1
            except IntegrityError:
                s.rollback(); skipped += 1; break
    return {"created": created, "skipped_duplicates": skipped}

@app.get("/invoices")
def list_invoices(status: Optional[str] = None, overdue: bool = False, skip: int = 0, limit: int = 50,
                  u: User = Depends(current_user), s: Session = Depends(get_session)):
    q = select(Invoice)
    if u.role == "customer": q = q.where(Invoice.customer_id == u.id)
    if status: q = q.where(Invoice.status == status)
    if overdue: q = q.where(Invoice.status == "confirmed", Invoice.due_date < date.today())
    return s.exec(q.order_by(Invoice.id.desc()).offset(skip).limit(min(limit, 200))).all()

def get_invoice(s, iid, u):
    inv = s.get(Invoice, iid)
    if not inv or (u.role == "customer" and inv.customer_id != u.id): raise HTTPException(404)
    return inv

@app.post("/invoices/{iid}/{action}")
def invoice_action(iid: int, action: str, u: User = Depends(STAFF), s: Session = Depends(get_session)):
    inv = get_invoice(s, iid, u)
    rules = {"confirm": ("draft", "confirmed"), "cancel": (("draft", "confirmed"), "cancelled")}
    if action in rules:
        frm, to = rules[action]
        if inv.status not in (frm if isinstance(frm, tuple) else (frm,)): raise HTTPException(409, f"Invoice is {inv.status}")
        inv.status = to; s.commit()
    elif action == "send":
        print(f"[EMAIL] invoice {inv.number} sent to customer {inv.customer_id}")
    else:
        raise HTTPException(404, "Unknown action")
    return inv

@app.get("/invoices/{iid}/print", response_class=HTMLResponse)
def print_invoice(iid: int, u: User = Depends(current_user), s: Session = Depends(get_session)):
    inv = get_invoice(s, iid, u)
    from html import escape
    rows = "".join(f"<tr><td>{escape(l.description)}</td><td>{l.quantity}</td><td>{l.unit_price}</td><td>{l.discount}</td>"
                   f"<td>{l.tax_rate}%</td><td>{l.amount}</td></tr>"
                   for l in s.exec(select(InvoiceLine).where(InvoiceLine.invoice_id == iid)))
    return (f"<h2>{inv.number}</h2><p>Status: {inv.status} | Due: {inv.due_date}</p><table border=1 cellpadding=6>"
            f"<tr><th>Item</th><th>Qty</th><th>Price</th><th>Disc</th><th>Tax</th><th>Amount</th></tr>{rows}</table>"
            f"<p>Subtotal {inv.subtotal} | Discount {inv.discount_total} | Tax {inv.tax_total} | <b>Total {inv.total}</b></p>")

# ---- payments
class PayIn(BaseModel):
    invoice_id: int; method: str; amount: float; paid_on: date = Field(default_factory=date.today); note: str = ""

@app.post("/payments", status_code=201)
def pay(b: PayIn, _: User = Depends(STAFF), s: Session = Depends(get_session)):
    inv = s.get(Invoice, b.invoice_id)
    if not inv: raise HTTPException(404, "Invoice not found")
    if inv.status != "confirmed": raise HTTPException(409, "Only confirmed invoices accept payments")
    if b.amount <= 0 or r2(inv.paid_amount + b.amount) > inv.total: raise HTTPException(422, "Invalid amount")
    p = Payment(**b.dict()); s.add(p)
    inv.paid_amount = r2(inv.paid_amount + b.amount)
    if inv.paid_amount >= inv.total: inv.status = "paid"
    s.commit(); return p

@app.get("/payments")
def list_payments(skip: int = 0, limit: int = 50, _: User = Depends(STAFF), s: Session = Depends(get_session)):
    return s.exec(select(Payment).order_by(Payment.id.desc()).offset(skip).limit(min(limit, 200))).all()

# ---- reports (aggregate in SQL so it stays fast with thousands of rows)
@app.get("/reports/summary")
def summary(_: User = Depends(STAFF), s: Session = Depends(get_session)):
    today = date.today()
    active = s.exec(select(func.count()).select_from(Subscription).where(Subscription.status == "active")).one()
    revenue = s.exec(select(func.coalesce(func.sum(Payment.amount), 0))).one()
    owed = s.exec(select(func.coalesce(func.sum(Invoice.total - Invoice.paid_amount), 0)).where(Invoice.status == "confirmed")).one()
    od = s.exec(select(func.count(), func.coalesce(func.sum(Invoice.total - Invoice.paid_amount), 0))
                .where(Invoice.status == "confirmed", Invoice.due_date < today)).one()
    plan_revenue = s.exec(select(Plan.billing_period, func.sum(Plan.price))
                          .join(Subscription, Subscription.plan_id == Plan.id)
                          .where(Subscription.status == "active")
                          .group_by(Plan.billing_period)).all()
    line_revenue = s.exec(select(Plan.billing_period, func.sum(SubLine.quantity * SubLine.unit_price))
                          .join(Subscription, Subscription.id == SubLine.subscription_id)
                          .join(Plan, Plan.id == Subscription.plan_id)
                          .where(Subscription.status == "active")
                          .group_by(Plan.billing_period)).all()
    period_factor = {"daily": 365.2425 / 12, "weekly": 52 / 12, "monthly": 1, "yearly": 1 / 12}
    mrr = sum(float(amount or 0) * period_factor.get(period, 0)
              for period, amount in [*plan_revenue, *line_revenue])
    return {"active_subscriptions": active, "revenue_collected": r2(revenue), "outstanding": r2(owed),
            "overdue_count": od[0], "overdue_amount": r2(od[1]), "monthly_recurring_revenue": r2(mrr)}

base_dir = os.path.dirname(__file__)
static_dir = os.path.join(base_dir, "static") if os.path.isdir(os.path.join(base_dir, "static")) else base_dir
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
