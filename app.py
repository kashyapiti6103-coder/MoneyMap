import os
import sqlite3
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "replace_this_secret")

# ---------------- DATABASE ----------------
DB_FILE = "expenses.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_sqlite():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            joined_date TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            amount REAL,
            category TEXT,
            date TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS budgets (
            user_id INTEGER PRIMARY KEY,
            amount REAL
        )
    """)

    conn.commit()
    conn.close()

init_sqlite()

# ---------------- HELPERS ----------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    user = cur.fetchone()
    conn.close()

    if user:
        return dict(user)
    return None

# ---------------- ROUTES ----------------

# ✅ FIXED ROOT (IMPORTANT)
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login")
def login():
    if "user_id" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=get_current_user())

@app.route("/expenses")
@login_required
def expenses_page():
    return render_template("expenses.html", user=get_current_user())

@app.route("/analytics")
@login_required
def analytics_page():
    return render_template("analytics.html", user=get_current_user())

@app.route("/budget")
@login_required
def budget_page():
    return render_template("budget.html", user=get_current_user())

@app.route("/profile")
@login_required
def profile_page():
    return render_template("profile.html", user=get_current_user())

# ---------------- AUTH API ----------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.json or {}

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    if cur.fetchone():
        return jsonify({"error": "Username exists"}), 400

    pwd_hash = generate_password_hash(password)
    joined = datetime.utcnow().strftime("%Y-%m-%d")

    cur.execute("INSERT INTO users (username,email,password_hash,joined_date) VALUES (?,?,?,?)",
                (username, email, pwd_hash, joined))
    conn.commit()

    session["user_id"] = cur.lastrowid
    conn.close()

    return jsonify({"message": "Created"})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id,password_hash FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid"}), 401

    session["user_id"] = user["id"]
    return jsonify({"message": "Success"})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out"})

# ---------------- EXPENSE ----------------
@app.route("/api/expenses", methods=["GET", "POST"])
@login_required
def api_expenses():
    user = get_current_user()

    if request.method == "GET":
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM expenses WHERE user_id=?", (user["id"],))
        data = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(data)

    data = request.json or {}

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO expenses (user_id,title,amount,category,date) VALUES (?,?,?,?,?)",
                (user["id"], data["title"], data["amount"], data["category"], data["date"]))
    conn.commit()
    conn.close()

    return jsonify({"message": "Saved"})

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
