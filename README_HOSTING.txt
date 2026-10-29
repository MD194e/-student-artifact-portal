STUDENT ARTIFACT PORTAL - HOSTING NOTES

This version stores the SQLite database and uploaded files in WEENY_DATA_DIR when the host provides it.
Install dependencies with: pip install -r requirements.txt
Run locally with: python app.py
Production start command: gunicorn --bind 0.0.0.0:${PORT:-5000} app:app

DEMO TEACHER LOGIN (change before real use):
Email: teacher@portal.local
Password: Teacher@123

IMPORTANT: Change the default teacher password and set a strong SECRET_KEY before sharing the app.
This is an educational prototype; do not use real student data until security hardening, backups, and access controls are reviewed.
