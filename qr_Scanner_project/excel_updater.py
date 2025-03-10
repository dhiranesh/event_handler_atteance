import pandas as pd
import threading

# Excel file path
EXCEL_FILE = "scanned_data.xlsx"

# Lock to prevent concurrent write issues
lock = threading.Lock()

def update_excel(data):
    """Updates the Excel file with the scanned QR code data."""
    with lock:
        df = pd.DataFrame([[data]], columns=["Scanned Data"])
        try:
            existing_df = pd.read_excel(EXCEL_FILE)
            df = pd.concat([existing_df, df], ignore_index=True)
        except FileNotFoundError:
            pass
        df.to_excel(EXCEL_FILE, index=False)
        print(f"Updated Excel with data: {data}")

if __name__ == "__main__":
    test_data = "Sample QR Data"
    update_excel(test_data)
