"""
HealthTag prototype 

A working demo of the three-tier emergency access flow:
  Tier 0  anyone scanning the QR      -> "call 108" + emergency contact number only
  Tier 1  verified doctor/paramedic   -> emergency card, instantly, logged against their credential
  Tier 2  full medical history        -> unlocks only after the emergency contact approves (link or OTP)

Every access is written to an audit log and the owner is notified.
SMS/WhatsApp delivery is SIMULATED: messages appear on the /inbox page.
"""
import os
import re
import secrets
import socket
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from reportlab.graphics.barcode import qrencoder
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "healthtag.db")
KEY_PATH = os.path.join(APP_DIR, ".healthtag.key")
SECRET_PATH = os.path.join(APP_DIR, ".secret_key")
PORT = int(os.environ.get("PORT", 5000))

IST = timezone(timedelta(hours=5, minutes=30))
REQUEST_TTL_MIN = 15      # how long a pending approval request stays valid
ACCESS_TTL_MIN = 30       # how long full-history access lasts once approved
MAX_OTP_ATTEMPTS = 3

BLOOD_GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-", "Not sure"]
TEXT_FIELDS = ["name", "age", "blood_group", "allergies", "conditions", "medications",
               "contact_name", "contact_relation", "contact_phone", "history"]

DEMO_OWNER_KEY = "demo-owner-key"   # fixed so the home page can link the demo patient
DEMO_PROFILE_ID = "LBNAPH0"


# --------------------------------------------------------------------------- setup
def _load_or_create(path, factory):
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    value = factory()
    with open(path, "w") as fh:
        fh.write(value)
    return value


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# The QR code must point at an address the *phone* can reach, so we use the laptop's
# LAN IP by default. Override with HEALTHTAG_BASE_URL (e.g. an ngrok URL).
BASE_URL = os.environ.get("HEALTHTAG_BASE_URL", f"http://{lan_ip()}:{PORT}").rstrip("/")

app = Flask(__name__)
app.secret_key = _load_or_create(SECRET_PATH, lambda: secrets.token_hex(32))

# Field-level encryption at rest. Optional: falls back to plain text if the
# 'cryptography' package is not installed.
try:
    from cryptography.fernet import Fernet
    _key = os.environ.get("HEALTHTAG_ENC_KEY") or _load_or_create(KEY_PATH, lambda: Fernet.generate_key().decode())
    _fernet = Fernet(_key.encode())
    ENCRYPTED = True
except ImportError:
    _fernet = None
    ENCRYPTED = False


def enc(text):
    text = text or ""
    if not text or _fernet is None:
        return text
    return "enc:" + _fernet.encrypt(text.encode()).decode()


def dec(text):
    if text and text.startswith("enc:") and _fernet is not None:
        try:
            return _fernet.decrypt(text[4:].encode()).decode()
        except Exception:
            return "(unreadable)"
    return text or ""


# --------------------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY, owner_key TEXT NOT NULL, created_at TEXT NOT NULL,
    name TEXT, age TEXT, blood_group TEXT, allergies TEXT, conditions TEXT, medications TEXT,
    contact_name TEXT, contact_relation TEXT, contact_phone TEXT, history TEXT
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT, ts TEXT,
    author TEXT, org TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT, ts TEXT,
    tier INTEGER, actor TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, profile_id TEXT,
    kind TEXT, to_label TEXT, body TEXT, link TEXT
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, profile_id TEXT, ts TEXT, status TEXT, otp TEXT,
    attempts INTEGER DEFAULT 0, requester_cred TEXT, requester_name TEXT, requester_org TEXT,
    decided_at TEXT, decided_by TEXT, decided_via TEXT
);
CREATE TABLE IF NOT EXISTS professionals (
    cred_id TEXT PRIMARY KEY, name TEXT, org TEXT, pin_hash TEXT
);
"""


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or utcnow()).isoformat(timespec="seconds")


def parse(value):
    return datetime.fromisoformat(value)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    if not conn.execute("SELECT 1 FROM professionals LIMIT 1").fetchone():
        demo_pros = [
            ("H-1001", "Dr. Anita Verma", "Apollo Hospital", "1234"),
            ("A-2002", "Ravi Kumar (paramedic)", "108 Ambulance Service", "1234"),
        ]
        for cred, name, org, pin in demo_pros:
            conn.execute("INSERT INTO professionals VALUES (?,?,?,?)",
                         (cred, name, org, generate_password_hash(pin)))

    if not conn.execute("SELECT 1 FROM profiles LIMIT 1").fetchone():
        demo = {
            "name": "Aarav Sharma", "age": "21", "blood_group": "O+",
            "allergies": "Penicillin, Peanuts",
            "conditions": "Type 1 diabetes",
            "medications": "Insulin (daily)",
            "contact_name": "Neha Sharma", "contact_relation": "Mother",
            "contact_phone": "+919800000001",
            "history": "Appendectomy (2021). Fully vaccinated. Uses an insulin pump; "
                       "carries glucose tablets. No known heart conditions.",
        }
        conn.execute(
            "INSERT INTO profiles (id, owner_key, created_at, " + ", ".join(TEXT_FIELDS) + ") "
            "VALUES (?,?,?," + ",".join("?" * len(TEXT_FIELDS)) + ")",
            (DEMO_PROFILE_ID, DEMO_OWNER_KEY, iso(), *[enc(demo[f]) for f in TEXT_FIELDS]),
        )
    conn.commit()
    conn.close()


init_db()


# --------------------------------------------------------------------------- helpers
@app.template_filter("ist")
def ist_filter(value):
    try:
        return parse(value).astimezone(IST).strftime("%d %b, %I:%M %p")
    except (TypeError, ValueError):
        return value or ""


@app.template_filter("chips")
def chips_filter(value):
    return [part.strip() for part in re.split(r"[,\n]", value or "") if part.strip()]


@app.context_processor
def inject_globals():
    return {"ENCRYPTED": ENCRYPTED, "BASE_URL": BASE_URL, "pro": current_pro()}


@app.after_request
def no_store(resp):
    if not request.path.startswith("/static"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def load_profile(pid):
    row = db().execute("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
    if not row:
        return None
    p = {"id": row["id"], "owner_key": row["owner_key"], "created_at": row["created_at"]}
    for field in TEXT_FIELDS:
        p[field] = dec(row[field])
    return p


def owner_profile(pid):
    """Load a profile and check the owner key from ?k= (or the form)."""
    p = load_profile(pid)
    if p is None:
        abort(404)
    supplied = request.values.get("k", "")
    if not secrets.compare_digest(supplied.encode(), p["owner_key"].encode()):
        abort(403)
    return p


def log_event(pid, tier, actor, action, detail=""):
    db().execute("INSERT INTO events (profile_id, ts, tier, actor, action, detail) VALUES (?,?,?,?,?,?)",
                 (pid, iso(), tier, actor, action, detail))
    db().commit()


def log_once(pid, tier, actor, action, detail="", minutes=5):
    """Log an event unless the same actor did the same thing very recently (avoids refresh spam)."""
    cutoff = iso(utcnow() - timedelta(minutes=minutes))
    seen = db().execute(
        "SELECT 1 FROM events WHERE profile_id=? AND actor=? AND action=? AND ts>=?",
        (pid, actor, action, cutoff)).fetchone()
    if seen:
        return False
    log_event(pid, tier, actor, action, detail)
    return True


def send_message(pid, kind, to_label, body, link=""):
    """Simulated SMS / app notification. Shown on /inbox."""
    db().execute("INSERT INTO messages (ts, profile_id, kind, to_label, body, link) VALUES (?,?,?,?,?,?)",
                 (iso(), pid, kind, to_label, body, link))
    db().commit()


def notify_owner(pid, body):
    send_message(pid, "owner", "Owner (HealthTag app)", body)


def current_pro():
    return session.get("pro")


def require_pro():
    pro = current_pro()
    if not pro:
        abort(403)
    return pro


def actor_label(pro):
    return f"{pro['name']}, {pro['org']}"


# ---- access requests
def refresh_request(row):
    """Expire a pending request that has waited too long."""
    if row and row["status"] == "pending" and utcnow() - parse(row["ts"]) > timedelta(minutes=REQUEST_TTL_MIN):
        db().execute("UPDATE requests SET status='expired' WHERE id=?", (row["id"],))
        db().commit()
        row = db().execute("SELECT * FROM requests WHERE id=?", (row["id"],)).fetchone()
    return row


def get_request(rid):
    row = db().execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    return refresh_request(row)


def latest_pending(pid, cred):
    row = db().execute(
        "SELECT * FROM requests WHERE profile_id=? AND requester_cred=? AND status='pending' "
        "ORDER BY ts DESC LIMIT 1", (pid, cred)).fetchone()
    return refresh_request(row)


def full_access_until(pid):
    """Return when the current professional's full-history access ends, or None."""
    pro = current_pro()
    if not pro:
        return None
    row = db().execute(
        "SELECT decided_at FROM requests WHERE profile_id=? AND requester_cred=? AND status='approved' "
        "ORDER BY decided_at DESC LIMIT 1", (pid, pro["cred"])).fetchone()
    if not row:
        return None
    until = parse(row["decided_at"]) + timedelta(minutes=ACCESS_TTL_MIN)
    return iso(until) if until > utcnow() else None


def decide_request(r, approved, by, via):
    status = "approved" if approved else "denied"
    db().execute("UPDATE requests SET status=?, decided_at=?, decided_by=?, decided_via=? WHERE id=?",
                 (status, iso(), by, via, r["id"]))
    db().commit()
    p = load_profile(r["profile_id"])
    who = f"{r['requester_name']}, {r['requester_org']}"
    how = "using the one-time code" if via == "otp" else "from the approval link"
    if approved:
        log_event(p["id"], 2, by, "approved full history access", f"For {who} ({how})")
        notify_owner(p["id"], f"{by} approved full history access for {who} {how}. "
                              f"Access lasts {ACCESS_TTL_MIN} minutes.")
        send_message(p["id"], "contact", f"{p['contact_name']} ({p['contact_phone']})",
                     f"HealthTag: you approved {who}. They can see {p['name']}'s medical history "
                     f"(past conditions, notes and hospital records) for {ACCESS_TTL_MIN} minutes.")
    else:
        log_event(p["id"], 2, by, "denied full history access", f"Request from {who}")
        notify_owner(p["id"], f"Full history access for {who} was denied ({by}).")


# --------------------------------------------------------------------------- QR
def qr_svg(data):
    qr = qrencoder.QRCode(None, qrencoder.QRErrorCorrectLevel.M)
    qr.addData(data)
    qr.make()
    n, quiet = qr.getModuleCount(), 3
    path = []
    for row in range(n):
        col = 0
        while col < n:
            if qr.isDark(row, col):
                start = col
                while col < n and qr.isDark(row, col):
                    col += 1
                path.append(f"M{start + quiet} {row + quiet}h{col - start}v1h-{col - start}z")
            else:
                col += 1
    size = n + 2 * quiet
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
            f'shape-rendering="crispEdges" role="img" aria-label="HealthTag QR code">'
            f'<rect width="{size}" height="{size}" fill="#fff"/>'
            f'<path d="{"".join(path)}" fill="#0B2545"/></svg>')


@app.route("/qr/<pid>.svg")
def qr_image(pid):
    if load_profile(pid) is None:
        abort(404)
    return Response(qr_svg(f"{BASE_URL}/scan/{pid}"), mimetype="image/svg+xml")


# --------------------------------------------------------------------------- pages: home, register, card
@app.route("/")
def home():
    return render_template("home.html", demo_id=DEMO_PROFILE_ID, demo_key=DEMO_OWNER_KEY)


def read_profile_form():
    limits = {"history": 2000}
    data = {f: request.form.get(f, "").strip()[:limits.get(f, 300)] for f in TEXT_FIELDS}
    errors = []
    if not data["name"]:
        errors.append("Enter the person's name.")
    if data["blood_group"] not in BLOOD_GROUPS:
        errors.append("Choose a blood group, or 'Not sure'.")
    if not data["contact_name"]:
        errors.append("Enter the emergency contact's name.")
    phone = re.sub(r"[^\d+]", "", data["contact_phone"])
    if len(re.sub(r"\D", "", phone)) < 10:
        errors.append("Enter a valid emergency contact phone number (at least 10 digits).")
    data["contact_phone"] = phone
    return data, errors


@app.route("/register", methods=["GET", "POST"])
def register():
    form = {f: "" for f in TEXT_FIELDS}
    if request.method == "POST":
        form, errors = read_profile_form()
        if errors:
            for e in errors:
                flash(e)
        else:
            pid = secrets.token_urlsafe(5).replace("-", "x").replace("_", "y").upper()
            key = secrets.token_urlsafe(12)
            db().execute(
                "INSERT INTO profiles (id, owner_key, created_at, " + ", ".join(TEXT_FIELDS) + ") "
                "VALUES (?,?,?," + ",".join("?" * len(TEXT_FIELDS)) + ")",
                (pid, key, iso(), *[enc(form[f]) for f in TEXT_FIELDS]))
            db().commit()
            log_event(pid, 0, "Owner", "created this HealthTag")
            return redirect(url_for("card", pid=pid, k=key))
    return render_template("profile_form.html", form=form, editing=False, blood_groups=BLOOD_GROUPS)


@app.route("/card/<pid>")
def card(pid):
    p = owner_profile(pid)
    return render_template("card.html", p=p, k=p["owner_key"])


@app.route("/owner/<pid>")
def owner(pid):
    p = owner_profile(pid)
    events = db().execute("SELECT * FROM events WHERE profile_id=? ORDER BY id DESC LIMIT 60", (pid,)).fetchall()
    notes = db().execute("SELECT * FROM messages WHERE profile_id=? AND kind='owner' ORDER BY id DESC LIMIT 30",
                         (pid,)).fetchall()
    records = db().execute("SELECT * FROM records WHERE profile_id=? ORDER BY id DESC", (pid,)).fetchall()
    records = [dict(r, note=dec(r["note"])) for r in records]
    return render_template("owner.html", p=p, k=p["owner_key"], events=events, notes=notes, records=records)


@app.route("/owner/<pid>/edit", methods=["GET", "POST"])
def owner_edit(pid):
    p = owner_profile(pid)
    form = {f: p[f] for f in TEXT_FIELDS}
    if request.method == "POST":
        form, errors = read_profile_form()
        if errors:
            for e in errors:
                flash(e)
        else:
            sets = ", ".join(f"{f}=?" for f in TEXT_FIELDS)
            db().execute(f"UPDATE profiles SET {sets} WHERE id=?", (*[enc(form[f]) for f in TEXT_FIELDS], pid))
            db().commit()
            log_event(pid, 0, "Owner", "updated the profile")
            return redirect(url_for("owner", pid=pid, k=p["owner_key"]))
    return render_template("profile_form.html", form=form, editing=True, p=p, k=p["owner_key"],
                           blood_groups=BLOOD_GROUPS)


# --------------------------------------------------------------------------- scanning
@app.route("/scan/<pid>")
def scan(pid):
    p = load_profile(pid)
    if p is None:
        abort(404)
    pro = current_pro()

    # Tier 0: anyone without a verified professional login
    if not pro:
        log_once(pid, 0, "Unverified scanner", "scanned the QR code",
                 "Saw only the emergency alert and contact number", minutes=2)
        return render_template("scan_public.html", p=p)

    # Tier 1: verified professional
    actor = actor_label(pro)
    if log_once(pid, 1, actor, "viewed the emergency card", f"Credential {pro['cred']}"):
        notify_owner(pid, f"{actor} viewed your emergency card.")

    until = full_access_until(pid)
    records = []
    if until:
        rows = db().execute("SELECT * FROM records WHERE profile_id=? ORDER BY id DESC", (pid,)).fetchall()
        records = [dict(r, note=dec(r["note"])) for r in rows]
        log_once(pid, 2, actor, "viewed the full history", f"Credential {pro['cred']}", minutes=5)
    pending = latest_pending(pid, pro["cred"]) if not until else None
    return render_template("scan_pro.html", p=p, until=until, records=records, pending=pending,
                           added=request.args.get("added"))


@app.post("/scan/<pid>/request")
def request_full_history(pid):
    pro = require_pro()
    p = load_profile(pid) or abort(404)
    existing = latest_pending(pid, pro["cred"])
    if existing:
        return redirect(url_for("request_wait", rid=existing["id"]))

    rid = secrets.token_urlsafe(8)
    otp = f"{secrets.randbelow(10 ** 6):06d}"
    db().execute("INSERT INTO requests (id, profile_id, ts, status, otp, requester_cred, requester_name, requester_org) "
                 "VALUES (?,?,?,?,?,?,?,?)",
                 (rid, pid, iso(), "pending", otp, pro["cred"], pro["name"], pro["org"]))
    db().commit()

    actor = actor_label(pro)
    log_event(pid, 2, actor, "requested the full history", f"Waiting for {p['contact_name']} to approve")
    send_message(pid, "contact", f"{p['contact_name']} ({p['contact_phone']})",
                 f"HealthTag: {actor} is asking to see {p['name']}'s full medical history. "
                 f"Your one-time code is {otp}. Tap the link to approve or deny.",
                 link=f"{BASE_URL}/approve/{rid}")
    notify_owner(pid, f"{actor} requested your full history. Waiting for {p['contact_name']} to approve.")
    return redirect(url_for("request_wait", rid=rid))


@app.post("/scan/<pid>/record")
def add_record(pid):
    pro = require_pro()
    load_profile(pid) or abort(404)
    note = request.form.get("note", "").strip()[:1000]
    if note:
        db().execute("INSERT INTO records (profile_id, ts, author, org, note) VALUES (?,?,?,?,?)",
                     (pid, iso(), pro["name"], pro["org"], enc(note)))
        db().commit()
        log_event(pid, 1, actor_label(pro), "added a record", "Visible in the full history")
        notify_owner(pid, f"{actor_label(pro)} added a note to your record.")
    return redirect(url_for("scan", pid=pid, added=1))


# --------------------------------------------------------------------------- request waiting (professional side)
def own_request_or_403(rid):
    pro = require_pro()
    r = get_request(rid)
    if r is None:
        abort(404)
    if r["requester_cred"] != pro["cred"]:
        abort(403)
    return r


@app.route("/request/<rid>")
def request_wait(rid):
    r = own_request_or_403(rid)
    if r["status"] == "approved":
        return redirect(url_for("scan", pid=r["profile_id"]))
    p = load_profile(r["profile_id"])
    return render_template("request_wait.html", r=r, p=p, error=request.args.get("err"),
                           ttl=REQUEST_TTL_MIN, max_attempts=MAX_OTP_ATTEMPTS)


@app.route("/request/<rid>/status")
def request_status(rid):
    r = own_request_or_403(rid)
    return jsonify(status=r["status"], next=url_for("scan", pid=r["profile_id"]))


@app.post("/request/<rid>/otp")
def request_otp(rid):
    r = own_request_or_403(rid)
    if r["status"] != "pending":
        return redirect(url_for("request_wait", rid=rid))
    p = load_profile(r["profile_id"])
    code = re.sub(r"\D", "", request.form.get("otp", ""))
    if secrets.compare_digest(code.encode(), r["otp"].encode()):
        decide_request(r, True, f"{p['contact_name']} (code read out)", "otp")
        return redirect(url_for("scan", pid=r["profile_id"]))
    attempts = r["attempts"] + 1
    db().execute("UPDATE requests SET attempts=? WHERE id=?", (attempts, rid))
    db().commit()
    if attempts >= MAX_OTP_ATTEMPTS:
        decide_request(r, False, "Locked after 3 wrong codes", "otp")
        return redirect(url_for("request_wait", rid=rid))
    return redirect(url_for("request_wait", rid=rid, err=MAX_OTP_ATTEMPTS - attempts))


# --------------------------------------------------------------------------- emergency contact approval
@app.route("/approve/<rid>", methods=["GET", "POST"])
def approve(rid):
    r = get_request(rid)
    if r is None:
        abort(404)
    p = load_profile(r["profile_id"])
    if request.method == "POST" and r["status"] == "pending":
        approved = request.form.get("decision") == "approve"
        decide_request(r, approved, p["contact_name"], "link")
        r = get_request(rid)
    return render_template("contact_approve.html", r=r, p=p)


# --------------------------------------------------------------------------- professional sign-in
def safe_next(value):
    return value if value and value.startswith("/") and not value.startswith("//") else url_for("home")


@app.route("/pro/login", methods=["GET", "POST"])
def pro_login():
    nxt = safe_next(request.values.get("next", ""))
    if request.method == "POST":
        cred = request.form.get("cred", "").strip().upper()
        pin = request.form.get("pin", "")
        row = db().execute("SELECT * FROM professionals WHERE cred_id=?", (cred,)).fetchone()
        if row and check_password_hash(row["pin_hash"], pin):
            session["pro"] = {"cred": row["cred_id"], "name": row["name"], "org": row["org"]}
            return redirect(nxt)
        flash("That ID and PIN don't match a verified professional.")
    return render_template("pro_login.html", nxt=nxt)


@app.route("/pro/logout")
def pro_logout():
    session.pop("pro", None)
    return redirect(safe_next(request.args.get("next", "")))


# --------------------------------------------------------------------------- demo inbox
@app.route("/inbox")
def inbox():
    messages = db().execute("SELECT * FROM messages ORDER BY id DESC LIMIT 40").fetchall()
    return render_template("inbox.html", messages=messages)


# --------------------------------------------------------------------------- errors
@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", title="Access denied",
                           text="This page needs a verified sign-in or the owner's private link."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", title="Not found",
                           text="This HealthTag or page doesn't exist."), 404


if __name__ == "__main__":
    print("\n  HealthTag prototype")
    print(f"  Open on this laptop : http://localhost:{PORT}")
    print(f"  Phones (same Wi-Fi) : {BASE_URL}   <- QR codes point here")
    print(f"  Field encryption    : {'on' if ENCRYPTED else 'OFF (pip install cryptography to enable)'}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
