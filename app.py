import os, sqlite3, re, time, uuid
from datetime import datetime
from flask import Flask, request, redirect, session, render_template_string, send_from_directory, abort, flash
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("WEENY_DATA_DIR", os.path.join(ROOT, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB = os.path.join(DATA_DIR, "portal.db")
UPLOADS = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOADS, exist_ok=True)
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable must be configured.")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
csrf = CSRFProtect(app)
ALLOWED = {"pdf","docx","txt","zip","png","jpg","jpeg","py","java","cpp","html","css","js"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Security token missing or invalid. Please reload the page and try again.")
    return redirect(request.referrer or "/")

@app.after_request
def add_security_headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://cdn.jsdelivr.net; font-src 'self'; connect-src 'self'; script-src 'self'")
    return resp

def connect():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, enrollment TEXT UNIQUE,
          email TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS assignments(id INTEGER PRIMARY KEY, title TEXT, description TEXT,
          due_at TEXT, max_marks REAL, allowed_ext TEXT, created_by INTEGER);
        CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, assignment_id INTEGER,
          student_id INTEGER, stored TEXT, original TEXT, submitted_at TEXT, marks REAL, feedback TEXT,
          UNIQUE(assignment_id,student_id));
        """)
        if not c.execute("SELECT id FROM users WHERE email='teacher@portal.local'").fetchone():
            teacher_password = os.environ.get("TEACHER_PASSWORD")
            if teacher_password:
                c.execute(
                    "INSERT INTO users(name,enrollment,email,password,role) VALUES(?,?,?,?,?)",
                    (
                        "Demo Teacher",
                        "TEACHER001",
                        "teacher@portal.local",
                        generate_password_hash(teacher_password),
                        "teacher",
                    ),
                )

def page(body, **kw):
    template = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Artifact Portal</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{background:#f3f6fb}.navbar{background:#102746}.card{border:0;border-radius:14px;box-shadow:0 4px 18px #10274612}.hero{background:linear-gradient(120deg,#102746,#176b87);color:white;border-radius:18px;padding:30px}</style>
    </head><body><nav class="navbar navbar-dark p-3"><div class="container"><a class="navbar-brand" href="/">Artifact Portal</a>
    <span class="text-white">{% if session.get('name') %}{{session.get('name')}} · {{session.get('role')}} · <a href="/logout">Logout</a>{% endif %}</span></div></nav>
    <main class="container py-4">{% for m in get_flashed_messages() %}<div class="alert alert-info">{{m}}</div>{% endfor %}""" + body + """</main></body></html>"""
    return render_template_string(template, **kw)

@app.route("/")
def home():
    if session.get("role") == "teacher": return redirect("/teacher")
    if session.get("role") == "student": return redirect("/student")
    return page("""<div class="hero mb-4"><h1>Automated Student Artifact Submission & Grading Portal</h1>
    <p>Upload work, track submissions, and receive grades and feedback.</p><a class="btn btn-light" href="/login">Login</a>
    <a class="btn btn-outline-light" href="/register">Student registration</a></div>""")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        vals = [request.form.get(k,"").strip() for k in ("name","enrollment","email")]
        pw = request.form.get("password","")
        if not all(vals) or not EMAIL_RE.match(vals[2]) or len(pw)<8: flash("Fill all fields with a valid email; password must be at least 8 characters.")
        else:
            try:
                with connect() as c:
                    c.execute("INSERT INTO users(name,enrollment,email,password,role) VALUES(?,?,?,?,?)",
                    (*vals, generate_password_hash(pw), "student"))
                flash("Account created. Log in now."); return redirect("/login")
            except sqlite3.IntegrityError: flash("Email or enrollment number already exists.")
    return page("""<div class="card p-4 mx-auto" style="max-width:600px"><h2>Student registration</h2>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input class="form-control my-2" name="name" placeholder="Full name" required>
    <input class="form-control my-2" name="enrollment" placeholder="Enrollment number" required>
    <input class="form-control my-2" type="email" name="email" placeholder="Email" required>
    <input class="form-control my-2" type="password" name="password" placeholder="Password (8+ characters)" minlength="8" required>
    <button class="btn btn-primary mt-2">Register</button></form></div>""")

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900
login_attempts = {}

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        key = request.form.get("email","").lower().strip() or "_unknown_"
        now_ts = time.time()
        count, first_ts = login_attempts.get(key, (0, 0))
        if now_ts - first_ts > LOGIN_WINDOW_SECONDS:
            count, first_ts = 0, now_ts
        count += 1
        login_attempts[key] = (count, first_ts)
        locked = count >= LOGIN_MAX_ATTEMPTS
        with connect() as c: u = c.execute("SELECT * FROM users WHERE email=?", (key,)).fetchone()
        if u and check_password_hash(u["password"], request.form.get("password","")) and not locked:
            login_attempts.pop(key, None)
            session.clear(); session.update(user_id=u["id"], name=u["name"], role=u["role"])
            return redirect("/teacher" if u["role"]=="teacher" else "/student")
        if locked:
            flash("Too many failed login attempts. Please wait before trying again.")
            return redirect("/login")
        flash("Invalid email or password.")
    return page("""<div class="card p-4 mx-auto" style="max-width:600px"><h2>Login</h2><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input class="form-control my-2" type="email" name="email" placeholder="Email" required>
    <input class="form-control my-2" type="password" name="password" placeholder="Password" required>
    <button class="btn btn-primary mt-2">Login</button></form></div>""")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")

@app.route("/teacher")
def teacher():
    if session.get("role") != "teacher": return redirect("/login")
    with connect() as c: rows=c.execute("""SELECT a.*,COUNT(s.id) n FROM assignments a LEFT JOIN submissions s
      ON a.id=s.assignment_id GROUP BY a.id ORDER BY a.id DESC""").fetchall()
    return page("""<h2>Teacher dashboard</h2><a class="btn btn-primary mb-3" href="/new">Create assignment</a>
    {% for a in rows %}<div class="card p-3 mb-3"><h5>{{a['title']}}</h5><p>Due {{a['due_at']}} · {{a['n']}} submissions · {{a['max_marks']}} marks</p>
    <a href="/review/{{a['id']}}">Review submissions</a></div>{% else %}<p>No assignments created.</p>{% endfor %}""", rows=rows)

@app.route("/new", methods=["GET","POST"])
def new_assignment():
    if session.get("role") != "teacher": return redirect("/login")
    if request.method == "POST":
        try:
            due=datetime.fromisoformat(request.form["due_at"]).isoformat(timespec="minutes")
            marks=float(request.form.get("max_marks","100"))
            with connect() as c: c.execute("INSERT INTO assignments(title,description,due_at,max_marks,allowed_ext,created_by) VALUES(?,?,?,?,?,?)",
              (request.form["title"].strip(),request.form.get("description","").strip(),due,marks,
               request.form.get("allowed_ext","pdf,docx,txt,zip").replace(" ","").lower(),session["user_id"]))
            flash("Assignment created."); return redirect("/teacher")
        except Exception: flash("Check the assignment details.")
    return page("""<div class="card p-4"><h2>Create assignment</h2><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label>Title</label><input class="form-control mb-3" name="title" required>
    <label>Description</label><textarea class="form-control mb-3" name="description"></textarea>
    <label>Deadline</label><input class="form-control mb-3" type="datetime-local" name="due_at" required>
    <label>Maximum marks</label><input class="form-control mb-3" type="number" name="max_marks" value="100" min="1" required>
    <label>Allowed extensions</label><input class="form-control mb-3" name="allowed_ext" value="pdf,docx,txt,zip,py,java">
    <button class="btn btn-primary">Publish</button></form></div>""")

@app.route("/student")
def student():
    if session.get("role") != "student": return redirect("/login")
    with connect() as c: rows=c.execute("""SELECT a.*,s.id sid,s.original,s.marks,s.feedback FROM assignments a
      LEFT JOIN submissions s ON a.id=s.assignment_id AND s.student_id=? ORDER BY a.due_at""",(session["user_id"],)).fetchall()
    now=datetime.now()
    return page("""<h2>Student dashboard</h2><div class="row g-3">{% for a in rows %}<div class="col-md-6"><div class="card p-4">
    <h5>{{a['title']}}</h5><p>{{a['description'] or ''}}</p><p>Deadline: {{a['due_at']}} · Max marks: {{a['max_marks']}}</p>
    {% if a['sid'] %}<p>Submitted file: {{a['original']}}</p>{% if a['marks'] is not none %}<b>Grade: {{a['marks']}} / {{a['max_marks']}}</b><p>Feedback: {{a['feedback'] or 'No feedback'}}</p>{% endif %}
    {% elif now < a['due_at'] %}<form method="post" enctype="multipart/form-data" action="/submit/{{a['id']}}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input class="form-control mb-2" type="file" name="artifact" required><button class="btn btn-primary">Submit</button></form>
    {% else %}<span class="text-danger">Deadline passed</span>{% endif %}</div></div>{% else %}<p>No assignments available.</p>{% endfor %}</div>""", rows=rows, now=now.isoformat(timespec="minutes"))

@app.route("/submit/<int:aid>", methods=["POST"])
def submit(aid):
    if session.get("role") != "student": return redirect("/login")
    with connect() as c: a=c.execute("SELECT * FROM assignments WHERE id=?",(aid,)).fetchone()
    if not a: abort(404)
    f=request.files.get("artifact")
    if not f or not f.filename: flash("Choose a file."); return redirect("/student")
    name=secure_filename(f.filename); ext=name.rsplit(".",1)[-1].lower() if "." in name else ""
    allowed={x.strip().lower().lstrip(".") for x in a["allowed_ext"].split(",")}
    if ext not in ALLOWED or ext not in allowed: flash("File type is not allowed."); return redirect("/student")
    if datetime.now() > datetime.fromisoformat(a["due_at"]): flash("Deadline passed."); return redirect("/student")
    stored=uuid.uuid4().hex+"_"+name; f.save(os.path.join(UPLOADS,stored))
    with connect() as c:
        old=c.execute("SELECT stored FROM submissions WHERE assignment_id=? AND student_id=?",(aid,session["user_id"])).fetchone()
        c.execute("""INSERT INTO submissions(assignment_id,student_id,stored,original,submitted_at) VALUES(?,?,?,?,?)
        ON CONFLICT(assignment_id,student_id) DO UPDATE SET stored=excluded.stored,original=excluded.original,
        submitted_at=excluded.submitted_at,marks=NULL,feedback=NULL""",
        (aid,session["user_id"],stored,name,datetime.now().isoformat(timespec="minutes")))
        if old:
            try: os.remove(os.path.join(UPLOADS,old["stored"]))
            except OSError: pass
    flash("Artifact submitted."); return redirect("/student")

@app.route("/review/<int:aid>")
def review(aid):
    if session.get("role") != "teacher": return redirect("/login")
    with connect() as c:
        a=c.execute("SELECT * FROM assignments WHERE id=?",(aid,)).fetchone()
        rows=c.execute("""SELECT s.*,u.name,u.enrollment FROM submissions s JOIN users u ON u.id=s.student_id
        WHERE s.assignment_id=? ORDER BY s.submitted_at DESC""",(aid,)).fetchall()
    if not a: abort(404)
    return page("""<h2>{{a['title']}} submissions</h2>{% for s in rows %}<div class="card p-4 mb-3">
    <h5>{{s['name']}} ({{s['enrollment']}})</h5><p>{{s['original']}} · {{s['submitted_at']}}</p><a href="/download/{{s['id']}}">Download artifact</a>
    <form method="post" action="/grade/{{s['id']}}" class="row g-2 mt-2"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><div class="col-md-3"><input class="form-control" type="number" name="marks" min="0" max="{{a['max_marks']}}" step="0.5" value="{{s['marks'] if s['marks'] is not none else ''}}" required></div>
    <div class="col-md-7"><input class="form-control" name="feedback" value="{{s['feedback'] or ''}}" placeholder="Feedback"></div><div class="col-md-2"><button class="btn btn-primary">Save grade</button></div></form></div>
    {% else %}<p>No submissions yet.</p>{% endfor %}""", a=a, rows=rows)

@app.route("/grade/<int:sid>", methods=["POST"])
def grade(sid):
    if session.get("role") != "teacher": return redirect("/login")
    with connect() as c:
        s=c.execute("SELECT s.*,a.max_marks FROM submissions s JOIN assignments a ON a.id=s.assignment_id WHERE s.id=?",(sid,)).fetchone()
        if not s: abort(404)
        try: marks=float(request.form.get("marks",""))
        except ValueError: marks=-1
        if not 0 <= marks <= s["max_marks"]: flash("Marks out of range.")
        else:
            c.execute("UPDATE submissions SET marks=?,feedback=? WHERE id=?",(marks,request.form.get("feedback","").strip(),sid))
            flash("Grade saved.")
        aid=s["assignment_id"]
    return redirect(f"/review/{aid}")

@app.route("/download/<int:sid>")
def download(sid):
    if not session.get("user_id"): return redirect("/login")
    with connect() as c: s=c.execute("SELECT * FROM submissions WHERE id=?",(sid,)).fetchone()
    if not s: abort(404)
    if session.get("role")=="student" and s["student_id"] != session["user_id"]: abort(403)
    return send_from_directory(UPLOADS,s["stored"],as_attachment=True,download_name=s["original"])

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False, use_reloader=False)
