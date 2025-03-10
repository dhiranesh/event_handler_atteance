import cv2

def scan_qr():
    """Scans a QR code using the webcam and returns the scanned data."""
    cap = cv2.VideoCapture(0)  # Open webcam
    detector = cv2.QRCodeDetector()

    print("Scanning... Please show the QR code to the camera.")

    while True:
        _, frame = cap.read()
        data, _, _ = detector.detectAndDecode(frame)

        if data:
            print(f"QR Code detected: {data}")
            cap.release()
            cv2.destroyAllWindows()
            return data

if __name__ == "__main__":
    result = scan_qr()
    if result:
        print(f"Scanned QR Code Data: {result}")
