import sqlite3
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect("expenses.db")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        amount REAL NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def get_expenses():
    conn = sqlite3.connect("expenses.db")
    rows = conn.execute("SELECT name, amount FROM expenses").fetchall()
    conn.close()
    return rows

@app.route("/")
def home():
    expenses = get_expenses()
    total = sum(amount for name, amount in expenses)
    return render_template("index.html", expenses=expenses, total=total)

@app.route("/add", methods=["POST"])
def add():
    name = request.form["name"].strip()
    try:
        amount = float(request.form["amount"])
    except ValueError:
        return redirect("/")
    if name and amount > 0:
        conn = sqlite3.connect("expenses.db")
        conn.execute(
            "INSERT INTO expenses (name, amount) VALUES (?, ?)",
            (name, amount),
        )
        conn.commit()
        conn.close()
    return redirect("/")

init_db()

if __name__ == "__main__":
    app.run(debug=True)