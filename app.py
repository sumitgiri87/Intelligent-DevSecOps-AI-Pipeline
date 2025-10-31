from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

DB = "demo.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, pwd TEXT);")
    c.execute("INSERT OR IGNORE INTO users (id, username, pwd) VALUES (1, 'alice', 'password123');")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return "Intelligent DevSecOps demo"

# INSECURE: constructs SQL via concatenation (SQL injection demo)
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # unsafe query -> intentional vulnerability
    query = f"SELECT id FROM users WHERE username = '{username}' AND pwd = '{password}';"
    print("DEBUG QUERY:", query)
    c.execute(query)  # vulnerable to SQL injection
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"status": "ok", "id": row[0]})
    return jsonify({"status": "fail"}), 401

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
