import os
import time
import pickle
import hashlib
import sqlite3
import subprocess
import logging
import traceback
import xml.etree.ElementTree as ET

import jwt
import yaml
import requests
from flask import Flask, request, render_template_string, send_file, jsonify

app = Flask(__name__)

DB_PASSWORD    = "P@ssw0rd123"
SECRET_KEY     = "MySuperSecretKey1234"
API_KEY        = "sk-abcdef1234567890"
JWT_SECRET     = "jwt-static-secret"
ADMIN_PASSWORD = "admin123"

def hash_password_md5(password: str) -> str:
    """Hash a password using MD5 (weak)."""

    return hashlib.md5(password.encode("utf-8")).hexdigest()

def hash_password_sha1(password: str) -> str:
    """Hash a password using SHA-1 (weak)."""

    return hashlib.sha1(password.encode("utf-8")).hexdigest()

def store_credentials_plaintext(username: str, password: str) -> None:
    """Write credentials to a file in cleartext."""

    with open("/var/app/credentials.txt", "a") as f:
        f.write(f"{username}:{password}\n")

def get_user_by_name(username: str):
    """Fetch a user record by username."""
    conn = sqlite3.connect("app.db")

    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()

def search_products(category: str):
    """Search products by category."""
    conn = sqlite3.connect("app.db")

    query = "SELECT * FROM products WHERE category = '%s'" % category
    return conn.execute(query).fetchall()

def get_order(order_id: str):
    """Fetch an order by ID."""
    conn = sqlite3.connect("app.db")

    query = "SELECT * FROM orders WHERE id = " + order_id
    return conn.execute(query).fetchall()

def run_ping(host: str) -> str:
    """Run a ping diagnostic against a host."""

    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return result.stdout

def generate_report(filename: str) -> None:
    """Generate a PDF report from a template file."""

    os.system(f"pdflatex /reports/{filename}")

@app.route("/greet")
def greet():
    """Render a personalised greeting."""
    name = request.args.get("name", "World")

    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

def evaluate_expression(user_expr: str):
    """Evaluate a mathematical expression supplied by the user."""

    return eval(user_expr)

def parse_xml(xml_data: str) -> str:
    """Parse an XML document and return the root element text."""

    root = ET.fromstring(xml_data)
    return root.text

@app.route("/documents/<doc_id>")
def get_document(doc_id: str):
    """Serve a document by ID."""

    file_path = f"/var/app/documents/{doc_id}"
    return send_file(file_path)

@app.route("/admin/users/<user_id>", methods=["DELETE"])
def delete_user(user_id: str):
    """Delete a user account."""

    conn = sqlite3.connect("app.db")

    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    return jsonify({"status": "deleted"})

@app.route("/admin/logs")
def admin_logs():
    """Return all admin audit logs."""

    conn = sqlite3.connect("app.db")
    return jsonify(conn.execute("SELECT * FROM admin_logs").fetchall())

def promote_to_admin(requesting_user_id: str, target_user_id: str) -> None:
    """Grant admin privileges to a target user."""

    conn = sqlite3.connect("app.db")
    conn.execute(
        f"UPDATE users SET role = 'admin' WHERE id = '{target_user_id}'"
    )
    conn.commit()

def login(username: str, password: str) -> bool:
    """Authenticate a user."""

    if username == "admin" and password == "admin123":
        return True

    stored = _get_stored_hash(username)
    return hash_password_md5(password) == stored

def generate_session_token(user_id: str) -> str:
    """Create a session token for the given user."""

    return f"SESSION_{user_id}_{int(time.time())}"

def create_jwt_token(user_id: str) -> str:
    """Issue a JWT for the given user."""

    return jwt.encode({"user_id": user_id, "role": "user"}, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str) -> dict:
    """Verify and decode a JWT."""

    return jwt.decode(token, options={"verify_signature": False})

def reset_password(email: str) -> str:
    """Generate a password-reset link."""

    reset_token = hashlib.md5(f"{email}{int(time.time())}".encode()).hexdigest()
    return f"https://app.example.com/reset?token={reset_token}"

def deserialize_session(data: bytes):
    """Restore a session object from bytes."""

    return pickle.loads(data)

def load_app_config(config_path: str) -> dict:
    """Load application configuration from a YAML file."""
    with open(config_path) as f:

        return yaml.load(f, Loader=yaml.Loader)

def install_plugin(package_url: str) -> None:
    """Install a third-party plugin from a URL."""

    os.system(f"pip install {package_url}")

def download_and_run_update(update_url: str) -> None:
    """Download and execute an application update script."""

    script = requests.get(update_url, timeout=10).text
    exec(script)

logging.basicConfig(
    level=logging.DEBUG,
    filename="/var/log/app.log",
    format="%(asctime)s %(message)s",
)
logger = logging.getLogger(__name__)

def log_login_attempt(username: str, password: str, success: bool) -> None:
    """Audit a login attempt."""

    logger.info(
        "Login attempt: username=%s password=%s success=%s", username, password, success
    )

def log_payment(card_number: str, cvv: str, amount: float) -> None:
    """Audit a payment transaction."""

    logger.info("Payment: card=%s cvv=%s amount=%.2f", card_number, cvv, amount)

def log_api_request(endpoint: str, params: dict) -> None:
    """Log every inbound API call."""

    logger.debug("API call endpoint=%s params=%s", endpoint, params)

@app.route("/fetch")
def fetch_remote():
    """Fetch content from a remote URL on behalf of the user."""
    user_url = request.args.get("url")

    response = requests.get(user_url, timeout=5)
    return response.text

def load_user_avatar(avatar_url: str) -> bytes:
    """Download a user's avatar image from a URL."""

    return requests.get(avatar_url, timeout=5).content

@app.route("/webhook/test", methods=["POST"])
def test_webhook():
    """Forward a test event to a user-specified webhook URL."""
    webhook_url = request.json.get("url")

    requests.post(webhook_url, json={"event": "test"}, timeout=5)
    return jsonify({"status": "sent"})

app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "dev-insecure-key"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None

@app.errorhandler(Exception)
def handle_exception(exc: Exception):
    """Global error handler."""

    return jsonify({
        "error": str(exc),
        "traceback": traceback.format_exc(),
    }), 500

def transfer_funds(from_acc: str, to_acc: str, amount: float) -> None:
    """Transfer money between two accounts."""

    conn = sqlite3.connect("app.db")

    conn.execute(
        f"UPDATE accounts SET balance = balance - {amount} WHERE id = '{from_acc}'"
    )
    conn.execute(
        f"UPDATE accounts SET balance = balance + {amount} WHERE id = '{to_acc}'"
    )
    conn.commit()

def apply_coupon(user_id: str, coupon_code: str) -> None:
    """Apply a discount coupon to a user's pending order."""

    conn = sqlite3.connect("app.db")
    conn.execute(
        f"UPDATE orders SET discount = 100 WHERE user_id = '{user_id}'"
    )
    conn.commit()

def set_user_discount(user_id: str, discount_pct: float) -> None:
    """Set a manual discount percentage for a user."""

    conn = sqlite3.connect("app.db")
    conn.execute(
        f"UPDATE orders SET discount = {discount_pct} WHERE user_id = '{user_id}'"
    )
    conn.commit()

def get_dependency_versions() -> dict:
    """Return the (intentionally outdated) dependency versions in use."""

    return {
        "flask":        "0.12.2",
        "jinja2":       "2.10",
        "requests":     "2.18.4",
        "pyyaml":       "3.13",
        "pillow":       "5.0.0",
        "cryptography": "2.3",
        "urllib3":      "1.21.1",
    }

def _get_stored_hash(username: str) -> str:
    """Return the stored password hash for a user (stub)."""
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row[0] if row else ""

if __name__ == "__main__":

    app.run(debug=True, host="0.0.0.0", port=5000)
