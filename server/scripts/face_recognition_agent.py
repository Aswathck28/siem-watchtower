import cv2
import face_recognition
import pyautogui
import smtplib
from email.message import EmailMessage
import requests
import time
import os
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables (ensure .env exists in this folder or parent)
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'server', '.env'))

# CONFIGURATION
OWNER_FACE_IMAGE = "registered_face.jpg"  # Provide a clear image of the owner here
EMAIL_SENDER = os.getenv("EMAIL_USER", "your_email@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASS", "your_app_password")
EMAIL_RECEIVER = os.getenv("SUPER_ADMIN_EMAIL", "admin@yourdomain.com")
SIEM_API_LOG = "http://localhost:5000/api/log"

def send_security_alert(intruder_img_path, screenshot_path):
    print("[ALERT] Sending unauthorized access email...")
    msg = EmailMessage()
    msg['Subject'] = f"🚨 SIEM-Watchtower: Unauthorized Laptop Access Detected!"
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg.set_content(f"Unauthorized physical access was detected at {timestamp}.\n\n"
                    f"The facial recognition mismatch policy triggered. Attached are the webcam feed and screen capture.")
    
    # Attach Webcam Image
    with open(intruder_img_path, 'rb') as f:
        img_data = f.read()
        msg.add_attachment(img_data, maintype='image', subtype='jpeg', filename="intruder_webcam.jpg")
    
    # Attach Screenshot
    with open(screenshot_path, 'rb') as f:
        img_data = f.read()
        msg.add_attachment(img_data, maintype='image', subtype='jpeg', filename="desktop_screenshot.jpg")
        
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("[ALERT] Email alert sent successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def log_to_siem():
    """Send telemetry to SIEM Backend"""
    print("[SIEM] Logging Unauthorized Access Incident...")
    payload = {
        "uid": "SYSTEM_AGENT",
        "sessionId": "OS_UNLOCK_EVENT",
        "action": "unauthorized_face_detected",
        "details": {
            "severity": "CRITICAL",
            "message": "Physical intrusion detected via facial recognition mismatch."
        }
    }
    try:
        requests.post(SIEM_API_LOG, json=payload, timeout=5)
    except Exception as e:
        print(f"[ERROR] SIEM Backend unreachable: {e}")

def verify_face():
    print("[INFO] Initializing Facial Recognition Protocol...")
    
    if not os.path.exists(OWNER_FACE_IMAGE):
        print(f"[FATAL] Registered face image '{OWNER_FACE_IMAGE}' not found. Exiting.")
        return

    # Load known face
    owner_image = face_recognition.load_image_file(OWNER_FACE_IMAGE)
    owner_encodings = face_recognition.face_encodings(owner_image)
    if not owner_encodings:
        print("[FATAL] Could not find a face in the registered image.")
        return
    owner_encoding = owner_encodings[0]

    # Initialize Webcam
    video_capture = cv2.VideoCapture(0)
    print("[INFO] Analysing lock-screen user...")
    
    # Give the camera a second to adjust to light
    time.sleep(1)
    
    match_found = False
    captured_frame = None
    
    # Check up to 5 consecutive frames
    for _ in range(5):
        ret, frame = video_capture.read()
        if not ret:
            continue
            
        captured_frame = frame
        rgb_frame = frame[:, :, ::-1] # Convert BGR to RGB
        face_locations = face_recognition.face_locations(rgb_frame)
        current_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        
        for enc in current_encodings:
            matches = face_recognition.compare_faces([owner_encoding], enc, tolerance=0.5)
            if matches[0]:
                match_found = True
                break
                
        if match_found:
            break
            
    video_capture.release()
    cv2.destroyAllWindows()
    
    if match_found:
        print("[SUCCESS] Face Verified. Normal Operation Authorized.")
    else:
        print("[WARNING] UNKNOWN FACE DETECTED!")
        intruder_path = "intruder_capture.jpg"
        screenshot_path = "desktop_capture.jpg"
        
        # Save webcam frame
        if captured_frame is not None:
            cv2.imwrite(intruder_path, captured_frame)
            
        # Take Screenshot
        screenshot = pyautogui.screenshot()
        screenshot.save(screenshot_path)
        
        # Execute Defense Protocol
        log_to_siem()
        send_security_alert(intruder_path, screenshot_path)

if __name__ == "__main__":
    verify_face()
