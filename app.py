import os, io, time, sqlite3, secrets, uuid, re
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, send_filefrom itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import qrcode

APP_SECRET = os.environ.get("APP_SECRET", "CAMBIA-ESTA-CLAVE-ANTES-DE-USAR-EN-PRODUCCION")
DB_PATH = os.environ.get("DATABASE_PATH", "attendance.db")
app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")
signer = URLSafeTimedSerializer(APP_SECRET, salt="attendance-qr-v1")
QR_MAX_AGE = 25
QR_REFRESH_SECONDS = 15

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('teacher','student')),
          full_name TEXT NOT NULL,
          student_code TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS classes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          teacher_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sections (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          UNIQUE(class_id, name)
        );
        CREATE TABLE IF NOT EXISTS enrollments (
          class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
          student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          section_id INTEGER REFERENCES sections(id),
          PRIMARY KEY(class_id, student_id)
        );
        CREATE TABLE IF NOT EXISTS attendance_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          class_id INTEGER NOT NULL REFERENCES classes(id),
          started_at TEXT NOT NULL,
          ended_at TEXT
        );
        CREATE TABLE IF NOT EXISTS attendance (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          session_id INTEGER NOT NULL REFERENCES attendance_sessions(id),
          student_id INTEGER NOT NULL REFERENCES users(id),
          marked_at TEXT NOT NULL,
          ip_address TEXT,
          user_agent TEXT,
          section_id INTEGER REFERENCES sections(id),
          UNIQUE(session_id, student_id)
        );
        """)
        # Migration for databases created by earlier versions.
        columns = [r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if "student_code" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN student_code TEXT")
        enrollment_columns = [r["name"] for r in c.execute("PRAGMA table_info(enrollments)").fetchall()]
        if "section_id" not in enrollment_columns:
            c.execute("ALTER TABLE enrollments ADD COLUMN section_id INTEGER REFERENCES sections(id)")
        attendance_columns = [r["name"] for r in c.execute("PRAGMA table_info(attendance)").fetchall()]
        if "section_id" not in attendance_columns:
            c.execute("ALTER TABLE attendance ADD COLUMN section_id INTEGER REFERENCES sections(id)")
        for cl in c.execute("SELECT id FROM classes").fetchall():
            c.execute("INSERT OR IGNORE INTO sections(class_id,name) VALUES(?,?)", (cl["id"], "General"))
            general_id = c.execute("SELECT id FROM sections WHERE class_id=? AND name='General'", (cl["id"],)).fetchone()["id"]
            c.execute("UPDATE enrollments SET section_id=? WHERE class_id=? AND section_id IS NULL", (general_id, cl["id"]))
        c.execute("""UPDATE attendance SET section_id=(SELECT e.section_id FROM attendance_sessions ss
          JOIN enrollments e ON e.class_id=ss.class_id AND e.student_id=attendance.student_id
          WHERE ss.id=attendance.session_id) WHERE section_id IS NULL""")
init_db()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

@app.route("/")
def home():
    if session.get("role") == "teacher": return redirect(url_for("teacher"))
    if session.get("role") == "student": return redirect(url_for("student"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with db() as c:
            user = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(user_id=user["id"], username=user["username"],
                           full_name=user["full_name"], role=user["role"])
            return redirect(url_for("home"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")

@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    setup_token = os.environ.get("ADMIN_SETUP_TOKEN", "")

    if not setup_token:
        abort(404)

    if request.method == "POST":
        supplied_token = request.form.get("token", "")

        if not secrets.compare_digest(supplied_token, setup_token):
            abort(403)

        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")

        if not username or not full_name or len(password) < 8:
            return "Completa todos los campos. La contraseña debe tener al menos 8 caracteres.", 400

        with db() as c:
            c.execute("BEGIN IMMEDIATE")
            exists = c.execute(
                "SELECT 1 FROM users WHERE role='teacher' LIMIT 1"
            ).fetchone()

            if exists:
                return "Ya existe un profesor registrado.", 409

            c.execute(
                """INSERT INTO users(username, password_hash, role, full_name)
                   VALUES(?, ?, 'teacher', ?)""",
                (username, generate_password_hash(password), full_name)
            )

        return "¡Usuario de profesor creado! Ya puedes iniciar sesión."

    return render_template_string("""
    <h2>Crear cuenta de profesor</h2>
    <form method="POST">
      <label>Clave de configuración:</label>
      <input name="token" required>
      <br><br>
      <label>Usuario:</label>
      <input name="username" required>
      <br><br>
      <label>Nombre completo:</label>
      <input name="full_name" required>
      <br><br>
      <label>Contraseña (mínimo 8 caracteres):</label>
      <input name="password" type="password" minlength="8" required>
      <br><br>
      <button type="submit">Crear profesor</button>
    </form>
    """)

@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/teacher")
@login_required("teacher")
def teacher():
    with db() as c:
        classes = c.execute("""
          SELECT cl.*, (SELECT id FROM attendance_sessions s
            WHERE s.class_id=cl.id AND s.ended_at IS NULL ORDER BY id DESC LIMIT 1) active_session
          FROM classes cl WHERE teacher_id=? ORDER BY cl.id DESC
        """, (session["user_id"],)).fetchall()
    return render_template("teacher.html", classes=classes)

@app.route("/classes", methods=["POST"])
@login_required("teacher")
def create_class():
    name = request.form.get("name","").strip()
    if not name:
        flash("Escribe el nombre de la clase.", "error")
        return redirect(url_for("teacher"))
    with db() as c:
        c.execute("INSERT INTO classes(name,teacher_id,created_at) VALUES(?,?,?)",
                  (name, session["user_id"], now()))
        class_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
        c.execute("INSERT INTO sections(class_id,name) VALUES(?,?)", (class_id, "General"))
    flash("Clase creada.", "success")
    return redirect(url_for("teacher"))

def owned_class(class_id):
    with db() as c:
        row = c.execute("SELECT * FROM classes WHERE id=? AND teacher_id=?",
                        (class_id, session["user_id"])).fetchone()
    if not row: abort(404)
    return row

@app.route("/classes/<int:class_id>/students", methods=["GET","POST"])
@login_required("teacher")
def manage_students(class_id):
    cl = owned_class(class_id)
    if request.method == "POST" and request.form.get("action") == "create_section":
        section_name = request.form.get("section_name", "").strip()
        if not section_name:
            flash("Escribe el nombre de la sección.", "error")
        else:
            try:
                with db() as c:
                    c.execute("INSERT INTO sections(class_id,name) VALUES(?,?)", (class_id, section_name))
                flash("Sección creada.", "success")
            except sqlite3.IntegrityError:
                flash("Esa sección ya existe en esta clase.", "error")
        return redirect(url_for("manage_students", class_id=class_id))
    if request.method == "POST" and request.form.get("action") == "bulk_import":
        raw_text = request.form.get("bulk_students", "")
        current_section = None
        parsed = []
        errors = []
        seen_codes = set()
        for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            heading = re.match(r"^(?:SECCI[ÓO]N|SECTION)\s*[:#-]?\s*(.+)$", line, re.IGNORECASE)
            if heading:
                current_section = heading.group(1).strip()
                continue
            # Also accept a section name by itself in brackets, e.g. [0901].
            bracket = re.match(r"^\[(.+)\]$", line)
            if bracket:
                current_section = bracket.group(1).strip()
                continue
            if current_section is None:
                errors.append(f"Línea {line_no}: primero indica una sección (ej. SECCIÓN: 0901).")
                continue
            # Accepted student formats: Name - account, Name, account, or tab-separated.
            parts = re.split(r"\s+-\s+|\t+|\s*;\s*|\s*,\s*", line)
            if len(parts) < 2:
                errors.append(f"Línea {line_no}: usa Nombre - número de cuenta.")
                continue
            full_name = parts[0].strip()
            student_code = parts[1].strip()
            if not full_name or not student_code:
                errors.append(f"Línea {line_no}: falta el nombre o número de cuenta.")
                continue
            if student_code in seen_codes:
                errors.append(f"Línea {line_no}: número repetido en el texto ({student_code}).")
                continue
            seen_codes.add(student_code)
            parsed.append((full_name, student_code, current_section))
        if not parsed:
            flash("No se encontraron estudiantes válidos. Revisa el formato de la lista.", "error")
        elif errors:
            flash("No se importó nada. Corrige estos problemas: " + " ".join(errors[:8]), "error")
        else:
            added = 0
            updated = 0
            try:
                with db() as c:
                    for full_name, student_code, section_name in parsed:
                        c.execute("INSERT OR IGNORE INTO sections(class_id,name) VALUES(?,?)",
                                  (class_id, section_name))
                        section_id = c.execute("SELECT id FROM sections WHERE class_id=? AND name=?",
                                               (class_id, section_name)).fetchone()["id"]
                        existing = c.execute("SELECT id,role FROM users WHERE student_code=?",
                                             (student_code,)).fetchone()
                        if existing:
                            if existing["role"] != "student":
                                raise ValueError(f"El número {student_code} ya pertenece a un usuario docente.")
                            student_id = existing["id"]
                            c.execute("UPDATE users SET full_name=? WHERE id=?", (full_name, student_id))
                            already = c.execute("SELECT 1 FROM enrollments WHERE class_id=? AND student_id=?",
                                                (class_id, student_id)).fetchone()
                            c.execute("""INSERT INTO enrollments(class_id,student_id,section_id) VALUES(?,?,?)
                                      ON CONFLICT(class_id,student_id) DO UPDATE SET section_id=excluded.section_id""",
                                      (class_id, student_id, section_id))
                            if already:
                                updated += 1
                            else:
                                added += 1
                        else:
                            username = "qr_" + uuid.uuid4().hex
                            c.execute("""INSERT INTO users(username,password_hash,role,full_name,student_code)
                                      VALUES(?,?,?,?,?)""",
                                      (username, generate_password_hash(secrets.token_urlsafe(32)),
                                       "student", full_name, student_code))
                            student_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                            c.execute("INSERT INTO enrollments(class_id,student_id,section_id) VALUES(?,?,?)",
                                      (class_id, student_id, section_id))
                            added += 1
                flash(f"Importación completada: {added} estudiantes agregados y {updated} actualizados.", "success")
            except (sqlite3.IntegrityError, ValueError) as exc:
                flash(f"No se completó la importación: {exc}", "error")
        return redirect(url_for("manage_students", class_id=class_id))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        student_code = request.form.get("student_code", "").strip()
        section_id = request.form.get("section_id", type=int)
        with db() as c:
            valid_section = c.execute("SELECT id FROM sections WHERE id=? AND class_id=?", (section_id, class_id)).fetchone()
        if not valid_section:
            flash("Selecciona una sección válida.", "error")
        elif not full_name or not student_code:
            flash("Escribe el nombre y el código estudiantil.", "error")
        else:
            with db() as c:
                existing = c.execute("SELECT id,role FROM users WHERE student_code=?", (student_code,)).fetchone()
                if existing:
                    if existing["role"] != "student":
                        flash("Ese código ya está asignado a otro tipo de usuario.", "error")
                    else:
                        c.execute("INSERT INTO enrollments(class_id,student_id,section_id) VALUES(?,?,?) ON CONFLICT(class_id,student_id) DO UPDATE SET section_id=excluded.section_id", (class_id, existing["id"], section_id))
                        c.execute("UPDATE users SET full_name=? WHERE id=?", (full_name, existing["id"]))
                        flash("Estudiante inscrito en la clase.", "success")
                else:
                    username = "qr_" + uuid.uuid4().hex
                    c.execute("INSERT INTO users(username,password_hash,role,full_name,student_code) VALUES(?,?,?,?,?)",
                              (username, generate_password_hash(secrets.token_urlsafe(32)), "student", full_name, student_code))
                    student_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                    c.execute("INSERT INTO enrollments(class_id,student_id,section_id) VALUES(?,?,?)", (class_id, student_id, section_id))
                    flash("Estudiante agregado. No necesita crear una cuenta ni contraseña.", "success")
        return redirect(url_for("manage_students", class_id=class_id))
    with db() as c:
        students = c.execute("""SELECT u.id,u.student_code,u.full_name,sec.name AS section_name FROM enrollments e
          JOIN users u ON u.id=e.student_id LEFT JOIN sections sec ON sec.id=e.section_id
          WHERE e.class_id=? ORDER BY sec.name,u.full_name""", (class_id,)).fetchall()
        sections = c.execute("SELECT id,name FROM sections WHERE class_id=? ORDER BY name", (class_id,)).fetchall()
    return render_template("students.html", cl=cl, students=students, sections=sections)

@app.route("/classes/<int:class_id>/start", methods=["POST"])
@login_required("teacher")
def start_session(class_id):
    owned_class(class_id)
    with db() as c:
        active = c.execute("SELECT id FROM attendance_sessions WHERE class_id=? AND ended_at IS NULL",
                           (class_id,)).fetchone()
        if active:
            flash("Ya hay una sesión abierta para esta clase.", "error")
        else:
            c.execute("INSERT INTO attendance_sessions(class_id,started_at) VALUES(?,?)",
                      (class_id, now()))
            sid = c.execute("SELECT last_insert_rowid()").fetchone()[0]
            flash("Asistencia iniciada.", "success")
            return redirect(url_for("session_page", session_id=sid))
    return redirect(url_for("teacher"))

@app.route("/sessions/<int:session_id>")
@login_required("teacher")
def session_page(session_id):
    with db() as c:
        s = c.execute("""SELECT s.*,cl.name FROM attendance_sessions s JOIN classes cl ON cl.id=s.class_id
          WHERE s.id=? AND cl.teacher_id=?""", (session_id, session["user_id"])).fetchone()
        if not s: abort(404)
        count = c.execute("SELECT COUNT(*) n FROM attendance WHERE session_id=?", (session_id,)).fetchone()["n"]
        enrolled = c.execute("SELECT COUNT(*) n FROM enrollments WHERE class_id=?", (s["class_id"],)).fetchone()["n"]
    return render_template("session.html", s=s, count=count, enrolled=enrolled,
                           refresh=QR_REFRESH_SECONDS)

@app.route("/sessions/<int:session_id>/qr")
@login_required("teacher")
def qr_image(session_id):
    with db() as c:
        s = c.execute("""SELECT s.id FROM attendance_sessions s JOIN classes cl ON cl.id=s.class_id
          WHERE s.id=? AND cl.teacher_id=? AND s.ended_at IS NULL""",
          (session_id, session["user_id"])).fetchone()
    if not s: abort(404)
    # Include a short time bucket so a refreshed QR gets a new signed token.
    bucket = int(time.time() // QR_REFRESH_SECONDS)
    token = signer.dumps({"sid": session_id, "bucket": bucket})
    target = url_for("mark_attendance", token=token, _external=True)
    img = qrcode.make(target)
    out = io.BytesIO()
    img.save(out, format="PNG")
    out.seek(0)
    return send_file(out, mimetype="image/png", max_age=0)

@app.route("/sessions/<int:session_id>/status")
@login_required("teacher")
def session_status(session_id):
    with db() as c:
        s = c.execute("""SELECT s.id,s.ended_at FROM attendance_sessions s JOIN classes cl ON cl.id=s.class_id
          WHERE s.id=? AND cl.teacher_id=?""", (session_id, session["user_id"])).fetchone()
        if not s: abort(404)
        rows = c.execute("""SELECT u.full_name,u.student_code AS username,a.marked_at,sec.name AS section_name FROM attendance a
          JOIN users u ON u.id=a.student_id LEFT JOIN sections sec ON sec.id=a.section_id
          WHERE a.session_id=? ORDER BY a.marked_at""",
          (session_id,)).fetchall()
        enrolled = c.execute("SELECT COUNT(*) n FROM enrollments e JOIN attendance_sessions s ON s.class_id=e.class_id WHERE s.id=?",
                             (session_id,)).fetchone()["n"]
    return jsonify(active=s["ended_at"] is None, count=len(rows), enrolled=enrolled,
                   attendance=[dict(r) for r in rows])

@app.route("/sessions/<int:session_id>/end", methods=["POST"])
@login_required("teacher")
def end_session(session_id):
    with db() as c:
        c.execute("""UPDATE attendance_sessions SET ended_at=? WHERE id=? AND ended_at IS NULL
          AND class_id IN (SELECT id FROM classes WHERE teacher_id=?)""",
          (now(), session_id, session["user_id"]))
    flash("Sesión cerrada.", "success")
    return redirect(url_for("teacher"))

@app.route("/classes/<int:class_id>/report")
@login_required("teacher")
def class_report(class_id):
    cl = owned_class(class_id)
    section_id = request.args.get("section_id", type=int)
    with db() as c:
        sections = c.execute("SELECT id,name FROM sections WHERE class_id=? ORDER BY name", (class_id,)).fetchall()
        sql = """SELECT u.full_name AS student_name, cl.name AS class_name, sec.name AS section_name,
                 'Presente' AS status, a.marked_at FROM attendance a
                 JOIN users u ON u.id=a.student_id JOIN attendance_sessions ss ON ss.id=a.session_id
                 JOIN classes cl ON cl.id=ss.class_id LEFT JOIN sections sec ON sec.id=a.section_id
                 WHERE cl.id=?"""
        params = [class_id]
        if section_id:
            sql += " AND a.section_id=?"; params.append(section_id)
        sql += " ORDER BY a.marked_at DESC"
        records = c.execute(sql, params).fetchall()
    return render_template("report.html", cl=cl, sections=sections, records=records, selected_section=section_id)

@app.route("/student")
@login_required("student")
def student():
    with db() as c:
        rows = c.execute("""SELECT cl.name,s.started_at,a.marked_at FROM attendance a
          JOIN attendance_sessions s ON s.id=a.session_id JOIN classes cl ON cl.id=s.class_id
          WHERE a.student_id=? ORDER BY a.id DESC LIMIT 30""", (session["user_id"],)).fetchall()
    return render_template("student.html", rows=rows)

@app.route("/mark/<token>", methods=["GET","POST"])
def mark_attendance(token):
    try:
        data = signer.loads(token, max_age=QR_MAX_AGE)
    except SignatureExpired:
        return render_template("result.html", ok=False, message="Este QR venció. Escanea el código actual que muestra tu docente.")
    except BadSignature:
        abort(400)
    # Reject QR tokens from a previous 15-second rotation bucket.
    if data.get("bucket") != int(time.time() // QR_REFRESH_SECONDS):
        return render_template("result.html", ok=False, message="El QR ya cambió. Escanea el código actual.")
    sid = data.get("sid")
    with db() as c:
        row = c.execute("""SELECT s.*,cl.name FROM attendance_sessions s
          JOIN classes cl ON cl.id=s.class_id WHERE s.id=? AND s.ended_at IS NULL""", (sid,)).fetchone()
        if not row:
            return render_template("result.html", ok=False, message="La asistencia está cerrada.")
        if request.method == "GET":
            return render_template("mark.html", token=token, class_name=row["name"])
        student_code = request.form.get("student_code", "").strip()
        student = c.execute("""SELECT u.id,e.section_id,sec.name AS section_name
          FROM users u JOIN enrollments e ON e.student_id=u.id
          LEFT JOIN sections sec ON sec.id=e.section_id
          WHERE u.student_code=? AND u.role='student' AND e.class_id=?""",
          (student_code, row["class_id"])).fetchone()
        if not student:
            return render_template("mark.html", token=token, class_name=row["name"],
                                   error="No encontramos ese número de cuenta en la lista de esta clase. Verifica que esté escrito correctamente.", entered=student_code)
        section_id = student["section_id"]
        try:
            c.execute("""INSERT INTO attendance(session_id,student_id,marked_at,ip_address,user_agent,section_id)
              VALUES(?,?,?,?,?,?)""",
              (sid, student["id"], now(), request.remote_addr, request.user_agent.string[:250], section_id))
        except sqlite3.IntegrityError:
            return render_template("result.html", ok=False, message="Este código ya registró su asistencia en esta sesión.")
    return render_template("result.html", ok=True, message=f"Tu asistencia en {row['name']} quedó registrada.")

@app.cli.command("create-user")
def create_user():
    """Create a user: flask --app app create-user"""
    import getpass
    username = input("Usuario: ").strip()
    full_name = input("Nombre completo: ").strip()
    role = input("Rol (teacher/student): ").strip().lower()
    if role not in ("teacher","student"):
        print("Rol inválido."); return
    password = getpass.getpass("Contraseña: ")
    if len(password) < 8:
        print("La contraseña debe tener al menos 8 caracteres."); return
    try:
        with db() as c:
            c.execute("INSERT INTO users(username,password_hash,role,full_name) VALUES(?,?,?,?)",
                      (username, generate_password_hash(password), role, full_name))
        print("Usuario creado.")
    except sqlite3.IntegrityError:
        print("Ese usuario ya existe.")

@app.cli.command("seed-demo")
def seed_demo():
    """Create demo users if the database is empty."""
    with db() as c:
        if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]:
            print("Ya existen usuarios; no se modificó la base de datos."); return
        demo = [
          ("docente","Docente de prueba","teacher","Docente123!"),
          ("estudiante","Estudiante de prueba","student","Estudiante123!")
        ]
        for u,n,r,p in demo:
            c.execute("INSERT INTO users(username,full_name,role,password_hash) VALUES(?,?,?,?)",
                      (u,n,r,generate_password_hash(p)))
        print("Usuarios demo creados. Cambia las contraseñas antes de usar datos reales.")

if __name__ == "__main__":
    app.run(debug=True)
