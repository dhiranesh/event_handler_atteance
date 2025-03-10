from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import json
import bcrypt
import requests
import pandas as pd
import time

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config["SESSION_PERMANENT"] = True

# Google Sheets Web App URL
GOOGLE_SHEET_URL = "https://script.google.com/macros/s/AKfycbwzUh8Ob83S9B5N0M0gc8ONSfS6Y0l9D22KMMxAJoL3fLWyICnUyAZKUDpCLMMnz64k/exec"

# Excel File for saving scanned data
EXCEL_FILE = "scanned_data.xlsx"
scanned_qr_codes = []  # Store scanned QR codes

# User Database (JSON-based, no SQL)
USER_DB_FILE = "users.json"

def load_users():
    try:
        with open(USER_DB_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USER_DB_FILE, "w") as file:
        json.dump(users, file)

# Initialize admin account
users = load_users()
if "admin" not in users:
    hashed_password = bcrypt.hashpw("admin@ksrct".encode(), bcrypt.gensalt()).decode()
    users["admin"] = hashed_password
    save_users(users)

def authenticate_user(username, password):
    users = load_users()
    if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
        return True
    return False

def send_to_google_sheets(data):
    try:
        params = {"data": data}
        response = requests.get(GOOGLE_SHEET_URL, params=params, timeout=5)
        return response.status_code == 200
    except requests.RequestException as e:
        print(f"Error sending data to Google Sheets: {e}")
        return False

def save_to_excel(data):
    df = pd.DataFrame([[data]], columns=["Scanned Data"])
    try:
        existing_df = pd.read_excel(EXCEL_FILE)
        df = pd.concat([existing_df, df], ignore_index=True)
    except FileNotFoundError:
        pass
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
        return redirect(url_for('scan_qr_page'))
    else:
        return "Invalid Credentials", 401

@app.route('/scan_qr')
def scan_qr_page():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    return render_template('scan_qr.html')

@app.route('/submit_qr', methods=['POST'])
def submit_qr():
    data = request.json.get("qr_data")
    if data and data not in scanned_qr_codes:
        scanned_qr_codes.append(data)
        success = send_to_google_sheets(data)
        save_to_excel(data)
        return jsonify({"success": success, "message": "QR scanned successfully"})
    return jsonify({"success": False, "message": "Invalid or duplicate QR"})

@app.route('/get_scanned_data', methods=['GET'])
def get_scanned_data():
    return jsonify(scanned_qr_codes)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
