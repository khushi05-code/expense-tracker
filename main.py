import sqlite3

conn = sqlite3.connect("expenses.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    amount REAL NOT NULL
)
""")
conn.commit()

def add_expense():
    while True:
        name = input("What did you spend on? ").strip()
        if name:
            break
        print("Name cannot be empty.")
    while True:
        try:
            amount = float(input("How much? "))
            if amount <= 0:
                print("Amount must be more than zero.")
                continue
            break
        except ValueError:
            print("Please enter a number, like 50 or 12.5.")
    cursor.execute(
        "INSERT INTO expenses (name, amount) VALUES (?, ?)",
        (name, amount),
    )
    conn.commit()
    print("Saved!")

def show_expenses():
    cursor.execute("SELECT name, amount FROM expenses")
    rows = cursor.fetchall()
    if not rows:
        print("No expenses yet.")
        return
    total = 0
    for name, amount in rows:
        print(name, "-", amount)
        total = total + amount
    print("Total:", total)

while True:
    print("\n1. Add expense")
    print("2. Show expenses")
    print("3. Quit")
    choice = input("Choose: ")

    if choice == "1":
        add_expense()
    elif choice == "2":
        show_expenses()
    elif choice == "3":
        break
    else:
        print("Please choose 1, 2 or 3.")

conn.close()