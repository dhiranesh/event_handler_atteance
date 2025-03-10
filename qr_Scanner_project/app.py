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
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TIMEOUT"] = 1800  # Auto logout after 30 minutes (1800 sec)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Google Sheets Web App URL
GOOGLE_SHEET_URL = "https://script.google.com/macros/s/AKfycbwzUh8Ob83S9B5N0M0gc8ONSfS6Y0l9D22KMMxAJoL3fLWyICnUyAZKUDpCLMMnz64k/exec"

# Excel File for saving scanned data
EXCEL_FILE = "scanned_data.xlsx"
scanned_qr_codes = set()  # Store scanned QR codes to prevent duplicates

# User Database (JSON-based, no SQL)
USER_DB_FILE = "users.json"

def load_users():
    try:
        if os.path.exists(USER_DB_FILE):
            with open(USER_DB_FILE, "r") as file:
                return json.load(file)
        return {}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error loading user database: {e}")
        return {}

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

def authenticate_user(username, password):
    users = load_users()
    return username in users and bcrypt.checkpw(password.encode(), users[username].encode())

def send_to_google_sheets(data):
    try:
        params = {"data": data}
        response = requests.get(GOOGLE_SHEET_URL, params=params, timeout=5)
        return response.status_code == 200
    except requests.RequestException as e:
        logging.error(f"Error sending data to Google Sheets: {e}")
        return False

def save_to_excel(data):
    df = pd.DataFrame([[data]], columns=["Scanned Data"])
    try:
        if os.path.exists(EXCEL_FILE):
            existing_df = pd.read_excel(EXCEL_FILE)
            df = pd.concat([existing_df, df], ignore_index=True)
    except Exception as e:
        logging.warning(f"Error reading Excel file: {e}")
    df.to_excel(EXCEL_FILE, index=False)

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/authenticate', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if authenticate_user(username, password):
        session['logged_in'] = True
        session['last_activity'] = time.time()
        return redirect(url_for('scan_qr_page'))
    return "Invalid Credentials", 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/scan_qr')
def scan_qr_page():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    return render_template('scan_qr.html')

@app.route('/submit_qr', methods=['POST'])
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

@app.route('/get_scanned_data', methods=['GET'])
def get_scanned_data():
    return jsonify(list(scanned_qr_codes))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Dynamic port for deployment
    app.run(host="0.0.0.0", port=port, debug=True)
