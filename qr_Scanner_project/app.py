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

# Google Apps Script Web App URL
GOOGLE_APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbw56PD0KHSu_KlZcv7l9GgmHaXLOPwcw5GSTygOoBRZMnDazXjgYU9x4vCVRYU6Bubq/exec"

# User Database (JSON-based)
USER_DB_FILE = "users.json"

# Excel File for storing scanned QR codes
EXCEL_FILE = "scanned_data.xlsx"

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

# Initialize default users if they do not exist
users = load_users()

# List of default users with unique passwords
default_users = {
    "admin": "admin@ksrct",
    "user123": "admin123@123"
}

# Generate unique passwords for user1 to user9
for i in range(1, 10):
    default_users[f"user{i}"] = f"user{i}_pass{i*111}"  # Example: user1_pass111, user2_pass222, ...

# Create users if they don't exist
for username, password in default_users.items():
    if username not in users:
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        users[username] = hashed_password
        logging.info(f"✅ Default user '{username}' added with password: {password}")

# Save updated user list
save_users(users)

# Function to authenticate users
def authenticate_user(username, password):
    users = load_users()
    if username in users:
        stored_hashed_pw = users[username].encode()  # Convert stored hash back to bytes
        return bcrypt.checkpw(password.encode(), stored_hashed_pw)
    return False

# Function to send QR data to Google Apps Script
def send_to_google_script(qr_data):
    try:
        response = requests.post(GOOGLE_APPS_SCRIPT_URL, json={"qr_data": qr_data}, timeout=5)
        response_json = response.json()
        logging.info(f"Google Script Response: {response_json}")

        return response_json
    except requests.RequestException as e:
        logging.error(f"Error sending data to Google Apps Script: {e}")
        return {"success": False, "message": "Error sending data to Google Script"}

# Function to clear and save scanned QR code to Excel
def save_to_excel(qr_data):
    try:
        # # Clear old data
        # df = pd.DataFrame(columns=["Timestamp", "Scanned Data"])
        # df.to_excel(EXCEL_FILE, index=False)

        # Add new QR data with timestamp
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")  # Format: YYYY-MM-DD HH:MM:SS
        df_new = pd.DataFrame([[timestamp, qr_data]], columns=["Timestamp", "Scanned Data"])
        df_new.to_excel(EXCEL_FILE, index=False)

        logging.info(f"✅ Data saved to Excel: {qr_data} at {timestamp}")
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

    # Send QR data to Google Apps Script
    response = send_to_google_script(data)

    # Save QR code to Excel
    save_to_excel(data)

    return jsonify(response)

# Route: Retrieve Scanned QR Codes
@app.route("/get_scanned_data", methods=["GET"])
def get_scanned_data():
    return jsonify(list(scanned_qr_codes))

# Run Flask Application
if __name__ == "__main__":    
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
