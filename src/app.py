"""
SIGA - Laboratorio de Ciberseguridad (Portal Académico vulnerable)
====================================================================
SOLO PARA USO LOCAL / EDUCATIVO. No exponer a internet ni desplegar
en un servidor público: contiene vulnerabilidades a propósito.

Vulnerabilidades incluidas (OWASP Top 10):
  1. SQL Injection                -> /login
  2. Cross-Site Scripting (XSS)
       - Reflejado                -> /buscar
       - Almacenado               -> /foro
  3. IDOR (Broken Access Control) -> /notas/<id>

Cada ruta vulnerable tiene un comentario "# VULNERABLE:" explicando
el problema y, comentado debajo, cómo se vería la versión corregida
(para tu sección de mitigación).
"""

import sqlite3
from flask import (
    Flask, request, render_template, render_template_string,
    g, redirect, url_for, session
)

app = Flask(__name__)
app.secret_key = "dev-secret-no-usar-en-produccion"  # ok para lab local
DB_PATH = "lab.db"


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL,
            password TEXT NOT NULL,
            nombre_completo TEXT NOT NULL,
            curso TEXT NOT NULL,
            es_admin INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS calificaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            estudiante_id INTEGER NOT NULL,
            materia TEXT NOT NULL,
            nota REAL NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS foro (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            autor TEXT NOT NULL,
            mensaje TEXT NOT NULL
        )
    """)

    cur.execute("SELECT COUNT(*) FROM usuarios")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO usuarios (usuario, password, nombre_completo, curso, es_admin) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                ("jperez",  "juliana123", "Juliana Perez",  "10A", 0),
                ("crodrig", "camilo456",  "Camilo Rodriguez", "10A", 0),
                ("admin",   "S3cr3tPass!", "Administrador",  "-",   1),
            ],
        )
        conn.commit()

        cur.execute("SELECT id, usuario FROM usuarios")
        ids = {row[1]: row[0] for row in cur.fetchall()}

        cur.executemany(
            "INSERT INTO calificaciones (estudiante_id, materia, nota) VALUES (?, ?, ?)",
            [
                (ids["jperez"],  "Matematicas", 3.1),
                (ids["jperez"],  "Ingles",      4.9),
                (ids["jperez"],  "Fisica",      3.9),
                (ids["crodrig"], "Matematicas", 4.2),
                (ids["crodrig"], "Ingles",      3.4),
                (ids["crodrig"], "Fisica",      4.6),
            ],
        )
        cur.executemany(
            "INSERT INTO foro (autor, mensaje) VALUES (?, ?)",
            [("Coordinación académica", "Bienvenidos al semestre 2026-2.")],
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", user=session.get("usuario"))


# ---------------------------------------------------------------------------
# 1) SQL INJECTION
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        password = request.form.get("password", "")

        # VULNERABLE: concatenación directa de input del usuario dentro
        # del SQL. Permite bypass de autenticación, ej. en el campo
        # "usuario":   admin' --
        query = (
            f"SELECT * FROM usuarios WHERE usuario = '{usuario}' "
            f"AND password = '{password}'"
        )
        cur = get_db().execute(query)
        row = cur.fetchone()

        # --- Versión corregida (comentada) ---
        # query = "SELECT * FROM usuarios WHERE usuario = ? AND password = ?"
        # cur = get_db().execute(query, (usuario, password))
        # row = cur.fetchone()
        # (Además: nunca guardar passwords en texto plano, usar hashing
        #  con bcrypt/argon2)

        if row:
            session["usuario"] = row["usuario"]
            session["usuario_id"] = row["id"]
            session["es_admin"] = bool(row["es_admin"])
            return redirect(url_for("mis_notas"))
        else:
            error = "Usuario o contraseña incorrectos."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 2a) XSS REFLEJADO
# ---------------------------------------------------------------------------
@app.route("/buscar")
def buscar():
    termino = request.args.get("q", "")

    # VULNERABLE: el término de búsqueda se inserta en el HTML sin escapar,
    # construyendo la página a mano en vez de usar autoescape de Jinja2.
    # Prueba: /buscar?q=<script>alert(document.cookie)</script>
    plantilla = """
    <!doctype html><html lang="es"><head><meta charset="utf-8">
    <link rel="stylesheet" href="/static/css/style.css"></head><body>
      <div class="topnav">
        <a href="/">Inicio</a><a href="/login">Login</a>
        <a href="/buscar">Buscar</a><a href="/foro">Foro</a>
        <a href="/mis-notas">Mis notas</a>
      </div>
      <div class="card-outer"><div class="wrap card">
        <div class="logo-row"><div class="logo-mark"></div><span class="logo-text">SIGA</span></div>
        <h1>Buscar materia o estudiante</h1>
        <form method="get" style="margin-bottom:16px;">
          <input type="text" name="q" placeholder="Escribe un nombre...">
          <button type="submit">Buscar</button>
        </form>
        <p class="subtitle">Resultados para: """ + termino + """</p>
        <div class="grade-list"><div class="grade-row">
          <span>Sin resultados</span><span></span></div></div>
      </div></div>
    </body></html>
    """
    return render_template_string(plantilla)

    # --- Versión corregida ---
    # return render_template("buscar_seguro.html", termino=termino)
    # (Jinja2 escapa automáticamente {{ termino }} con render_template
    #  normal, en vez de construir el HTML a mano con concatenación)


# ---------------------------------------------------------------------------
# 2b) XSS ALMACENADO
# ---------------------------------------------------------------------------
@app.route("/foro", methods=["GET", "POST"])
def foro():
    db = get_db()
    if request.method == "POST":
        autor = request.form.get("autor") or "Anónimo"
        mensaje = request.form.get("mensaje", "")
        db.execute("INSERT INTO foro (autor, mensaje) VALUES (?, ?)", (autor, mensaje))
        db.commit()

    anuncios = db.execute("SELECT autor, mensaje FROM foro ORDER BY id DESC").fetchall()

    # VULNERABLE: en foro.html el mensaje se renderiza con el filtro
    # "| safe", que desactiva el autoescape de Jinja2. Cualquier
    # <script>/<img onerror> guardado se ejecuta para todo el que
    # visite /foro después.
    # Prueba en "Mensaje": <img src=x onerror=alert('XSS-almacenado')>
    return render_template("foro.html", anuncios=anuncios)

    # --- Versión corregida ---
    # En foro.html usar {{ mensaje }} normal (autoescapado), nunca
    # {{ mensaje | safe }} con contenido de usuario. Aplicar además una
    # Content-Security-Policy y, si se necesita permitir HTML limitado,
    # sanitizar en el servidor con una librería como bleach.


# ---------------------------------------------------------------------------
# 3) IDOR (Broken Access Control)
# ---------------------------------------------------------------------------
def _cargar_boletin(estudiante_id):
    db = get_db()
    estudiante = db.execute(
        "SELECT id, nombre_completo, curso FROM usuarios WHERE id = ?",
        (estudiante_id,),
    ).fetchone()
    if estudiante is None:
        return None, None
    notas = db.execute(
        "SELECT materia, nota FROM calificaciones WHERE estudiante_id = ?",
        (estudiante_id,),
    ).fetchall()
    return estudiante, notas


@app.route("/mis-notas")
def mis_notas():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    estudiante, notas = _cargar_boletin(session["usuario_id"])
    return render_template("mis_notas.html", estudiante=estudiante, notas=notas)


@app.route("/notas/<int:estudiante_id>")
def notas_detail(estudiante_id):
    # VULNERABLE: solo se exige que haya UNA sesión iniciada, pero nunca
    # se valida que estudiante_id pertenezca al usuario en sesión. Cualquier
    # estudiante logueado puede ver el boletín de cualquier otro cambiando
    # el número en la URL.
    # Prueba: inicia sesión como jperez (id=1) y visita /notas/2 o /notas/3
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    estudiante, notas = _cargar_boletin(estudiante_id)
    if estudiante is None:
        return "Estudiante no encontrado", 404

    return render_template("notas_detail.html", estudiante=estudiante, notas=notas)

    # --- Versión corregida ---
    # if estudiante_id != session["usuario_id"] and not session.get("es_admin"):
    #     return "No autorizado", 403


if __name__ == "__main__":
    init_db()
    print("SIGA corriendo en http://127.0.0.1:5000  (SOLO LOCAL)")
    print("Usuarios de prueba: jperez/juliana123, crodrig/camilo456, admin/S3cr3tPass!")
    app.run(debug=True, host="127.0.0.1", port=5000)
