import os
import cv2
import sqlite3
import face_recognition
import numpy as np
import smtplib
from email.message import EmailMessage
from datetime import datetime
from flask import Flask, render_template, Response, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# EMAIL CONFIG
# -----------------------
EMAIL_SENDER = "srisaisasanksadineni@gmail.com"
EMAIL_PASSWORD = "ehlyshxyeyspsucc"
EMAIL_RECEIVER = "srisaisasanksadineni@gmail.com"

def send_email_with_image(image_path):
    try:
        msg = EmailMessage()
        msg["Subject"] = "🚨 Intruder Alert!"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg.set_content("Unknown person detected! Image attached.")

        with open(image_path, "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype="image",
                subtype="jpeg",
                filename=os.path.basename(image_path)
            )

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)

        print("📧 Email sent!")

    except Exception as e:
        print("❌ Email failed:", e)

# -----------------------
# FLASK SETUP
# -----------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security.db")
KNOWN_DIR = os.path.join(BASE_DIR, "known_faces")
INTRUDER_DIR = os.path.join(BASE_DIR, "intruders")

os.makedirs(KNOWN_DIR, exist_ok=True)
os.makedirs(INTRUDER_DIR, exist_ok=True)

# -----------------------
# DATABASE
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    time TEXT)''')

    if not c.execute("SELECT * FROM admin WHERE username='admin'").fetchone():
        c.execute("INSERT INTO admin VALUES (1, ?, ?)",
                  ("admin", generate_password_hash("admin123")))

    conn.commit()
    conn.close()

init_db()

# -----------------------
# LOAD FACES
# -----------------------
def load_faces():
    encodings = []
    names = []

    for file in os.listdir(KNOWN_DIR):
        if file.lower().endswith((".jpg", ".png", ".jpeg")):
            path = os.path.join(KNOWN_DIR, file)
            img = face_recognition.load_image_file(path)
            enc = face_recognition.face_encodings(img)

            if enc:
                encodings.append(enc[0])
                names.append(os.path.splitext(file)[0])

    return encodings, names

known_encodings, known_names = load_faces()

# -----------------------
# LOGIN REQUIRED
# -----------------------
def login_required(func):
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# -----------------------
# CAMERA SETUP
# -----------------------
camera = cv2.VideoCapture(0) 
camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

last_alert_time = None
last_logged_name = None

# -----------------------
# CAMERA STREAM (SMOOTH)
# -----------------------
def generate_frames():
    global last_alert_time, last_logged_name
    process_this_frame = True
    last_faces = []

    while True:
        success, frame = camera.read()
        if not success:
            continue  # Keep trying if frame not captured

        # Reduce size for faster processing
        small_frame = cv2.resize(frame, (0, 0), fx=0.4, fy=0.4)
        rgb_small = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)

        names = []
        boxes = []

        if process_this_frame:
            face_locations = face_recognition.face_locations(rgb_small)
            face_encodings = face_recognition.face_encodings(rgb_small, face_locations)

            for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
                matches = face_recognition.compare_faces(known_encodings, face_encoding, tolerance=0.5)
                distances = face_recognition.face_distance(known_encodings, face_encoding)

                name = "Unknown"
                if len(distances) > 0:
                    best_index = np.argmin(distances)
                    if matches[best_index] and distances[best_index] < 0.45:
                        name = known_names[best_index]

                names.append(name)
                boxes.append((top, right, bottom, left))

                # ALERT
                if name == "Unknown":
                    now = datetime.now()
                    if not last_alert_time or (now - last_alert_time).seconds > 15:
                        filename = f"intruder_{now.strftime('%Y%m%d_%H%M%S')}.jpg"
                        filepath = os.path.join(INTRUDER_DIR, filename)
                        cv2.imwrite(filepath, frame)
                        send_email_with_image(filepath)
                        last_alert_time = now

                # LOGGING
                if name != last_logged_name:
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO logs (name, time) VALUES (?, ?)",
                        (name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    )
                    conn.commit()
                    conn.close()
                    last_logged_name = name

            last_faces = list(zip(boxes, names))

        process_this_frame = not process_this_frame

        # Draw boxes
        for (top, right, bottom, left), name in last_faces:
            top = int(top * 2.5)
            right = int(right * 2.5)
            bottom = int(bottom * 2.5)
            left = int(left * 2.5)

            color = (0, 255, 0) if name != "Unknown" else (0, 0, 255)
            cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
            cv2.putText(frame, name, (left, top - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.8, color, 2)

        ret, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

# -----------------------
# ROUTES
# -----------------------
@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM admin WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["user"] = username
            return redirect("/")
        else:
            error = "❌ Invalid Username or Password"

    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
@login_required
def home():
    return render_template("index.html")

@app.route('/register', methods=["GET", "POST"])
@login_required
def register():
    global known_encodings, known_names
    if request.method == "POST":
        name = request.form["name"]
        photo = request.files["photo"]
        if name and photo:
            photo.save(os.path.join(KNOWN_DIR, f"{name}.jpg"))
            known_encodings, known_names = load_faces()
    return render_template("register.html")

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, time FROM logs ORDER BY id DESC")
    logs = c.fetchall()
    conn.close()
    return render_template("dashboard.html", logs=logs)

@app.route('/camera')
@login_required
def camera_page():
    return render_template("camera.html")

@app.route('/video')
@login_required
def video():
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# -----------------------
# RUN APP
# -----------------------
if __name__ == "__main__":
    app.run(debug=True)