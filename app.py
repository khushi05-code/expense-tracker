import os
import sqlite3
from datetime import date

from flask import Flask, render_template, request, redirect

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expenses.db")
CATEGORIES = ["Food", "Transport", "Shopping", "Bills",
              "Entertainment", "Health", "Education", "Other"]
CURRENCY = ""  # put a symbol here if you like, for example "₹" or "$"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT NOT NULL DEFAULT 'Other',
        date TEXT NOT NULL DEFAULT ''
    )
    """)
    # Upgrade an older table that doesn't have the new columns yet
    columns = [row["name"] for row in conn.execute("PRAGMA table_info(expenses)")]
    if "category" not in columns:
        conn.execute("ALTER TABLE expenses ADD COLUMN category TEXT NOT NULL DEFAULT 'Other'")
    if "date" not in columns:
        conn.execute("ALTER TABLE expenses ADD COLUMN date TEXT NOT NULL DEFAULT ''")
    conn.commit()
    conn.close()


@app.route("/")
def home():
    conn = get_db()
    expenses = conn.execute(
        "SELECT id, name, amount, category, date FROM expenses "
        "ORDER BY date DESC, id DESC"
    ).fetchall()
    conn.close()

    total = sum(e["amount"] for e in expenses)
    this_month = date.today().strftime("%Y-%m")
    month_total = sum(e["amount"] for e in expenses if e["date"].startswith(this_month))

    totals_by_category = {}
    for e in expenses:
        totals_by_category[e["category"]] = totals_by_category.get(e["category"], 0) + e["amount"]
    by_category = sorted(totals_by_category.items(), key=lambda pair: pair[1], reverse=True)

    return render_template(
        "index.html",
        expenses=expenses,
        total=total,
        month_total=month_total,
        by_category=by_category,
        categories=CATEGORIES,
        today=date.today().isoformat(),
        currency=CURRENCY,
    )


@app.route("/add", methods=["POST"])
def add():
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "Other")
    if category not in CATEGORIES:
        category = "Other"
    try:
        amount = float(request.form.get("amount", ""))
        expense_date = date.fromisoformat(request.form.get("date", ""))
    except ValueError:
        return redirect("/")

    if name and amount > 0:
        conn = get_db()
        conn.execute(
            "INSERT INTO expenses (name, amount, category, date) VALUES (?, ?, ?, ?)",
            (name, amount, category, expense_date.isoformat()),
        )
        conn.commit()
        conn.close()
    return redirect("/")


@app.route("/delete/<int:expense_id>", methods=["POST"])
def delete(expense_id):
    conn = get_db()
    conn.execute("DELETE FROM expenses WHERE id = ?", (expense_id,))
    conn.commit()
    conn.close()
    return redirect("/")


init_db()

if __name__ == "__main__":
    app.run(debug=True)