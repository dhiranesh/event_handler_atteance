from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import bcrypt
import requests
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config["SESSION_PERMANENT"] = False  # Ensures session expires after logout

# Google Sheets Web App URL
GOOGLE_SHEET_URL = "https://script.google.com/macros/s/AKfycbwzUh8Ob83S9B5N0M0gc8ONSfS6Y0l9D22KMMxAJoL3fLWyICnUyAZKUDpCLMMnz64k/exec"

# Excel File for saving scanned data
EXCEL_FILE = "scanned_data.xlsx"
scanned_qr_codes = []  # Store scanned QR codes

# User Database (JSON-based, no SQL)
USER_DB_FILE = "users.json"

def load_users():
    """Load users from a JSON file."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    try:
        with open(USER_DB_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}

def save_users(users):
    """Save users to a JSON file."""
    try:
        with open(USER_DB_FILE, "w") as file:
            json.dump(users, file, indent=4)
    except Exception as e:
        print(f"Error saving users: {e}")

# Initialize admin account
users = load_users()
if "admin" not in users:
    hashed_password = bcrypt.hashpw("admin@ksrct".encode(), bcrypt.gensalt()).decode()
    users["admin"] = hashed_password
    save_users(users)

def authenticate_user(username, password):
    """Verify user credentials."""
    users = load_users()
    return username in users and bcrypt.checkpw(password.encode(), users[username].encode())

def send_to_google_sheets(data):
    """Send scanned QR data to Google Sheets."""
    try:
        response = requests.get(GOOGLE_SHEET_URL, params={"data": data}, timeout=5)
        return response.status_code == 200
    except requests.RequestException as e:
        print(f"Error sending data to Google Sheets: {e}")
        return False

def save_to_excel(data):
    """Save scanned QR data to an Excel file."""
    df = pd.DataFrame([[data]], columns=["Scanned Data"])
    try:
        if os.path.exists(EXCEL_FILE):
            existing_df = pd.read_excel(EXCEL_FILE)
            df = pd.concat([existing_df, df], ignore_index=True)
    except Exception as e:
        print(f"Error reading Excel file: {e}")
    df.to_excel(EXCEL_FILE, index=False)

def login_required(f):
    """Decorator to restrict access to logged-in users."""
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return wrapper

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')

    if authenticate_user(username, password):
        session['logged_in'] = True
        return redirect(url_for('scan_qr_page'))
    return "Invalid Credentials", 401

@app.route('/logout')
def logout():
    """Log out the user."""
    session.pop('logged_in', None)
    return redirect(url_for('login_page'))

@app.route('/scan_qr')
@login_required
def scan_qr_page():
    return render_template('scan_qr.html')

@app.route('/submit_qr', methods=['POST'])
@login_required
def submit_qr():
    data = request.json.get("qr_data")
    if data and data not in scanned_qr_codes:
        scanned_qr_codes.append(data)
        success = send_to_google_sheets(data)
        save_to_excel(data)
        return jsonify({"success": success, "message": "QR scanned successfully"})
    return jsonify({"success": False, "message": "Invalid or duplicate QR"})

@app.route('/get_scanned_data', methods=['GET'])
@login_required
def get_scanned_data():
    return jsonify(scanned_qr_codes)

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))  # Get PORT from environment, default to 5000
    app.run(host="0.0.0.0", port=port, debug=True)

