import hmac
import math
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import date, timedelta
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "expenses.db")
SECRET_PATH = os.path.join(BASE_DIR, "secret_key.txt")

EXPENSE_CATEGORIES = ["Food", "Transport", "Shopping", "Bills", "Entertainment", "Health", "Education", "Other"]
INCOME_CATEGORIES = ["Salary", "Freelance", "Business", "Interest", "Gifts", "Other"]
CURRENCY = "₹"
MAX_AMOUNT = 1_000_000_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
ATTEMPT_WINDOW = 15 * 60  # seconds

# Turn these on with environment variables when the site is online (see the guide).
SECURE_COOKIES = os.environ.get("COOKIE_SECURE") == "1"
ALLOW_REGISTRATION = os.environ.get("ALLOW_REGISTRATION", "1") == "1"


def load_secret_key():
    """Use FLASK_SECRET_KEY if set, else a random key saved once in secret_key.txt."""
    from_env = os.environ.get("FLASK_SECRET_KEY")
    if from_env:
        return from_env
    if not os.path.exists(SECRET_PATH):
        try:
            fd = os.open(SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    with open(SECRET_PATH) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)

DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------- database ----------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def columns_of(conn, table):
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            amount REAL NOT NULL CHECK(amount > 0),
            type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
            category TEXT NOT NULL DEFAULT 'Other',
            source TEXT NOT NULL DEFAULT '',
            date TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            month TEXT NOT NULL,
            category TEXT NOT NULL,
            amount REAL NOT NULL CHECK(amount > 0),
            UNIQUE(user_id, month, category)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            ts REAL NOT NULL
        )""")

        first_user = conn.execute("SELECT MIN(id) FROM users").fetchone()[0]

        # Upgrade an older database: transactions get an owner
        if "user_id" not in columns_of(conn, "transactions"):
            conn.execute("ALTER TABLE transactions ADD COLUMN user_id INTEGER")
        if first_user:
            conn.execute("UPDATE transactions SET user_id = ? WHERE user_id IS NULL", (first_user,))

        # Upgrade an older database: budgets get an owner (needs a table rebuild)
        if "user_id" not in columns_of(conn, "budgets"):
            conn.execute("ALTER TABLE budgets RENAME TO budgets_old")
            conn.execute("""CREATE TABLE budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                month TEXT NOT NULL,
                category TEXT NOT NULL,
                amount REAL NOT NULL CHECK(amount > 0),
                UNIQUE(user_id, month, category)
            )""")
            if first_user:
                conn.execute("INSERT INTO budgets (user_id, month, category, amount) "
                             "SELECT ?, month, category, amount FROM budgets_old", (first_user,))
            conn.execute("DROP TABLE budgets_old")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_user_date ON transactions(user_id, date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attempts_key ON login_attempts(key)")


# ---------- security: CSRF, headers ----------
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


@app.before_request
def protect_forms():
    g.csp_nonce = secrets.token_urlsafe(16)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "").encode()
        expected = session.get("csrf_token", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


@app.context_processor
def inject_security_helpers():
    return {"csrf_token": csrf_token, "csp_nonce": lambda: g.get("csp_nonce", "")}


@app.after_request
def add_security_headers(resp):
    nonce = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if SECURE_COOKIES:
        resp.headers["Strict-Transport-Security"] = "max-age=15552000"
    if not request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(400)
def bad_request(_error):
    return ('<p>This form expired or was not valid. Go back, refresh the page and try again.</p>'
            f'<p><a href="{url_for("login")}">Back to the app</a></p>'), 400


@app.errorhandler(404)
def not_found(_error):
    return f'<p>Page not found.</p><p><a href="{url_for("login")}">Back to the app</a></p>', 404


# ---------- login helpers ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def too_many_attempts(conn, key, limit):
    conn.execute("DELETE FROM login_attempts WHERE ts < ?", (time.time() - ATTEMPT_WINDOW,))
    count = conn.execute("SELECT COUNT(*) FROM login_attempts WHERE key = ?", (key,)).fetchone()[0]
    return count >= limit


def record_attempt(conn, key):
    conn.execute("INSERT INTO login_attempts (key, ts) VALUES (?, ?)", (key, time.time()))


def start_session(user_id, username):
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["username"] = username


def month_bounds(month):
    start = date.fromisoformat(month + "-01")
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start.isoformat(), end.isoformat()


# ---------- routes: accounts ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:50]
        password = request.form.get("password", "")[:200]
        ip = request.remote_addr or "unknown"
        user_key = f"login:{ip}:{username.lower()}"
        ip_key = f"loginip:{ip}"
        with db() as conn:
            if too_many_attempts(conn, user_key, 5) or too_many_attempts(conn, ip_key, 20):
                flash("Too many failed attempts. Please wait 15 minutes and try again.", "error")
                return render_template("login.html", mode="login", allow_registration=ALLOW_REGISTRATION), 429
            user = conn.execute("SELECT * FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
            # Always check a hash, so a wrong username takes as long as a wrong password
            password_ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
            if user and password_ok:
                conn.execute("DELETE FROM login_attempts WHERE key = ?", (user_key,))
                start_session(user["id"], user["username"])
                return redirect(url_for("home"))
            record_attempt(conn, user_key)
            record_attempt(conn, ip_key)
        flash("Username or password is incorrect.", "error")
    return render_template("login.html", mode="login", allow_registration=ALLOW_REGISTRATION)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))
    if not ALLOW_REGISTRATION:
        abort(404)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"
        with db() as conn:
            if too_many_attempts(conn, f"reg:{ip}", 5):
                flash("Too many sign-up attempts. Please try again later.", "error")
                return render_template("login.html", mode="register", allow_registration=True), 429
            record_attempt(conn, f"reg:{ip}")
            if not USERNAME_RE.match(username):
                flash("Username: 3 to 30 letters, numbers, dots, dashes or underscores.", "error")
            elif not 8 <= len(password) <= 128:
                flash("Password must be between 8 and 128 characters.", "error")
            elif conn.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)).fetchone():
                flash("That username is already taken.", "error")
            else:
                cursor = conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                                      (username, generate_password_hash(password)))
                user_id = cursor.lastrowid
                if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1:
                    conn.execute("UPDATE transactions SET user_id = ? WHERE user_id IS NULL", (user_id,))
                start_session(user_id, username)
                return redirect(url_for("home"))
    return render_template("login.html", mode="register", allow_registration=True)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- routes: the app ----------
@app.get("/home")
@login_required
def home():
    uid = session["user_id"]
    month = date.today().strftime("%Y-%m")
    start, end = month_bounds(month)
    with db() as conn:
        totals = conn.execute("""SELECT
            COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END), 0) AS income,
            COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END), 0) AS expenses,
            COUNT(*) AS count FROM transactions WHERE user_id = ? AND date >= ? AND date < ?""",
            (uid, start, end)).fetchone()
        budget_total = conn.execute("SELECT COALESCE(SUM(amount), 0) FROM budgets WHERE user_id = ? AND month = ?",
                                    (uid, month)).fetchone()[0]
    return render_template("home.html", income=totals["income"], expenses=totals["expenses"],
                           net=totals["income"] - totals["expenses"], count=totals["count"],
                           budget_total=budget_total, month=month, currency=CURRENCY)


@app.get("/graphs")
@login_required
def graphs():
    uid = session["user_id"]
    period = request.args.get("period", "month")
    if period not in ("week", "month", "year"):
        period = "month"
    today = date.today()
    if period == "week":
        start_day = today - timedelta(days=today.weekday())
    elif period == "year":
        start_day = date(today.year, 1, 1)
    else:
        start_day = date(today.year, today.month, 1)
    start, end = start_day.isoformat(), today.isoformat()
    with db() as conn:
        categories = conn.execute("""SELECT category, SUM(amount) AS total FROM transactions
            WHERE user_id = ? AND type='expense' AND date >= ? AND date <= ?
            GROUP BY category ORDER BY total DESC""", (uid, start, end)).fetchall()
        daily = conn.execute("""SELECT date,
            SUM(CASE WHEN type='income' THEN amount ELSE 0 END) AS income,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expenses
            FROM transactions WHERE user_id = ? AND date >= ? AND date <= ?
            GROUP BY date ORDER BY date""", (uid, start, end)).fetchall()
    return render_template("graphs.html", period=period,
        category_labels=[r["category"] for r in categories],
        category_values=[round(r["total"], 2) for r in categories],
        daily_labels=[r["date"] for r in daily],
        daily_income=[round(r["income"], 2) for r in daily],
        daily_expenses=[round(r["expenses"], 2) for r in daily], currency=CURRENCY)


@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    uid = session["user_id"]
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        tx_type = request.form.get("type", "expense")
        category = request.form.get("category", "Other")
        source = request.form.get("source", "").strip()
        try:
            amount = float(request.form.get("amount", ""))
            tx_date = date.fromisoformat(request.form.get("date", ""))
        except (ValueError, TypeError):
            flash("Enter a valid amount and date.", "error")
            return redirect(url_for("transactions"))
        allowed = {"income": INCOME_CATEGORIES, "expense": EXPENSE_CATEGORIES}
        if (tx_type not in allowed or not name or len(name) > 150 or len(source) > 150
                or not math.isfinite(amount) or not 0 < amount <= MAX_AMOUNT
                or not 1970 <= tx_date.year <= 2100):
            flash("Please enter a valid transaction.", "error")
            return redirect(url_for("transactions"))
        if category not in allowed[tx_type]:
            category = "Other"
        with db() as conn:
            conn.execute("INSERT INTO transactions (user_id, name, amount, type, category, source, date) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (uid, name, amount, tx_type, category, source, tx_date.isoformat()))
        flash("Transaction added.", "success")
        return redirect(url_for("transactions"))
    with db() as conn:
        rows = conn.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC, id DESC LIMIT 1000",
                            (uid,)).fetchall()
    return render_template("transactions.html", transactions=rows, today=date.today().isoformat(),
                           income_categories=INCOME_CATEGORIES, expense_categories=EXPENSE_CATEGORIES,
                           currency=CURRENCY)


@app.post("/transactions/delete/<int:transaction_id>")
@login_required
def delete_transaction(transaction_id):
    with db() as conn:
        conn.execute("DELETE FROM transactions WHERE id = ? AND user_id = ?",
                     (transaction_id, session["user_id"]))
    return redirect(url_for("transactions"))


@app.route("/budgets", methods=["GET", "POST"])
@login_required
def budgets():
    uid = session["user_id"]
    month = request.values.get("month", date.today().strftime("%Y-%m"))
    try:
        start, end = month_bounds(month)
    except ValueError:
        month = date.today().strftime("%Y-%m")
        start, end = month_bounds(month)
    if request.method == "POST":
        with db() as conn:
            for category in EXPENSE_CATEGORIES:
                raw = request.form.get("budget_" + category, "").strip()
                if not raw:
                    conn.execute("DELETE FROM budgets WHERE user_id = ? AND month = ? AND category = ?",
                                 (uid, month, category))
                    continue
                try:
                    amount = float(raw)
                except ValueError:
                    continue
                if not math.isfinite(amount) or not 0 < amount <= MAX_AMOUNT:
                    continue
                conn.execute("""INSERT INTO budgets (user_id, month, category, amount) VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, month, category) DO UPDATE SET amount=excluded.amount""",
                             (uid, month, category, amount))
        return redirect(url_for("budgets", month=month))
    with db() as conn:
        spend_rows = conn.execute("""SELECT category, SUM(amount) AS spent FROM transactions
            WHERE user_id = ? AND type='expense' AND date >= ? AND date < ? GROUP BY category""",
                                  (uid, start, end)).fetchall()
        budget_rows = conn.execute("SELECT category, amount FROM budgets WHERE user_id = ? AND month = ?",
                                   (uid, month)).fetchall()
    spent_map = {r["category"]: r["spent"] for r in spend_rows}
    budget_map = {r["category"]: r["amount"] for r in budget_rows}
    progress = []
    for category in EXPENSE_CATEGORIES:
        limit = budget_map.get(category, 0)
        spent = spent_map.get(category, 0)
        pct = spent / limit * 100 if limit else 0
        status = "no-budget" if not limit else "overspent" if spent > limit else "near-limit" if pct >= 80 else "on-track"
        alert = ("Set a limit to track this category." if not limit
                 else f"Over budget by {CURRENCY}{spent-limit:,.2f}." if spent > limit
                 else f"{pct:.0f}% used — getting close." if pct >= 80 else "On track.")
        progress.append({"category": category, "budget": limit, "spent": spent,
                         "remaining": max(limit - spent, 0), "percentage": pct,
                         "bar_percentage": min(pct, 100), "status": status, "alert": alert})
    return render_template("budgets.html", month=month, progress=progress, currency=CURRENCY)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
