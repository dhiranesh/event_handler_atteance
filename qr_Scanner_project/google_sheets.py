import gspread
from oauth2client.service_account import ServiceAccountCredentials

# Google Sheets API Setup
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
client = gspread.authorize(creds)
sheet = client.open("QR_Scanned_Data").sheet1  # Change to your actual Google Sheet name

def update_google_sheets(data):
    """Updates Google Sheets with scanned QR code data."""
    sheet.append_row([data])
    print(f"Updated Google Sheets with data: {data}")

if __name__ == "__main__":
    test_data = "Sample QR Data"
    update_google_sheets(test_data)
