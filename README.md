# Colab version - Student Artifact Portal

## In Google Colab
1. Upload this ZIP or upload `app.py` to Colab.
2. Run `%pip install flask`.
3. Change directory to this folder, then launch `app.py` as a subprocess.
4. A tunnel is needed to reach the app from your browser. Follow the tunnel provider's current official setup; keep the URL private.
5. Demo teacher login: `teacher@portal.local` / `Teacher@123`.
6. Create an assignment as teacher, register a student, submit an allowed file, then grade it as teacher.

## Limitations
This is an educational prototype. SQLite database and uploads may disappear when the Colab runtime resets. Plagiarism detection and automatic rubric scoring are not included yet. Do not use real student data or expose this prototype publicly. Add CSRF protection, security testing, audit logs, malware scanning, and production hosting before deployment.
