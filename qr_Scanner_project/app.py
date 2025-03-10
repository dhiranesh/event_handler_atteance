from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import bcrypt
import requests
import pandas as pd
import os
import logging
import time

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your_secret_key")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TIMEOUT"] = 1800  # Auto logout after 30 minutes

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Google Sheets Web App URL
GOOGLE_SHEET_URL = "https://script.google.com/macros/s/AKfycbym298Z8r4FqjMLHvpByW1Z9h0BydTTrMsFRykHoI3aokYParxIZykjDfHcRjWkLPAz/exec"

# Excel File for saving scanned data
EXCEL_FILE = "scanned_data.xlsx"

# User Database (JSON-based, no SQL)
USER_DB_FILE = "users.json"

scanned_qr_codes = set()

# Function to load users
def load_users():
    try:
        if os.path.exists(USER_DB_FILE):
            with open(USER_DB_FILE, "r") as file:
                return json.load(file)
        return {}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error loading user database: {e}")
        return {}

# Function to save users
def save_users(users):
    try:
        with open(USER_DB_FILE, "w") as file:
            json.dump(users, file, indent=4)
    except Exception as e:
        logging.error(f"Error saving user database: {e}")

# Initialize admin account if not exists
users = load_users()
if "admin" not in users:
    hashed_password = bcrypt.hashpw("admin@ksrct".encode(), bcrypt.gensalt()).decode()
    users["admin"] = hashed_password
    save_users(users)

# Function to authenticate users
def authenticate_user(username, password):
    users = load_users()
    if username in users:
        stored_hashed_pw = users[username].encode()  # Convert stored hash back to bytes
        return bcrypt.checkpw(password.encode(), stored_hashed_pw)
    return False

# Function to send data to Google Sheets
def send_to_google_sheets(data):
    try:
        response = requests.post(GOOGLE_SHEET_URL, json={"data": data}, timeout=5)
        response_json = response.json()  # Parse response
        logging.info(f"Google Sheets Response: {response_json}")  # Log response

        return response_json.get("status") == "success"
    except requests.RequestException as e:
        logging.error(f"Error sending data to Google Sheets: {e}")
        return False

# Function to save data to Excel
def save_to_excel(data):
    df_new = pd.DataFrame([[data]], columns=["Scanned Data"])
    try:
        if os.path.exists(EXCEL_FILE):
            try:
                existing_df = pd.read_excel(EXCEL_FILE)
                df_new = pd.concat([existing_df, df_new], ignore_index=True)
            except Exception:
                logging.warning("Excel file corrupted or unreadable. Creating a new one.")
        df_new.to_excel(EXCEL_FILE, index=False)
        logging.info(f"✅ Data saved to Excel: {data}")
    except Exception as e:
        logging.warning(f"⚠️ Error updating Excel file: {e}")

# Function to check session timeout
def is_session_expired():
    if "last_activity" in session:
        elapsed_time = time.time() - session["last_activity"]
        return elapsed_time > app.config["SESSION_TIMEOUT"]
    return True

@app.before_request
def check_session_timeout():
    if "logged_in" in session and is_session_expired():
        session.clear()
        return redirect(url_for("login_page"))

# Route: Login Page
@app.route("/")
def login_page():
    return render_template("login.html")

# Route: Authentication
@app.route("/authenticate", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if authenticate_user(username, password):
        session["logged_in"] = True
        session["last_activity"] = time.time()
        return redirect(url_for("scan_qr_page"))

    return jsonify({"success": False, "message": "Invalid username or password"}), 401

# Route: Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# Route: QR Scan Page
@app.route("/scan_qr")
def scan_qr_page():
    if not session.get("logged_in"):
        return redirect(url_for("login_page"))
    return render_template("scan_qr.html")

# Route: Submit Scanned QR Code
@app.route("/submit_qr", methods=["POST"])
def submit_qr():
    data = request.json.get("qr_data")

    if not data:
        return jsonify({"success": False, "message": "No QR data received"})

    if data in scanned_qr_codes:
        return jsonify({"success": False, "message": "Duplicate QR code"})

    scanned_qr_codes.add(data)

    success = send_to_google_sheets(data)
    save_to_excel(data)

    return jsonify({"success": success, "message": "QR scanned successfully"})

# Route: Retrieve Scanned QR Codes
@app.route("/get_scanned_data", methods=["GET"])
def get_scanned_data():
    return jsonify(list(scanned_qr_codes))

# Run Flask Application
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
