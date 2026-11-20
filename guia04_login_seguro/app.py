"""
Guía 04 - ISW Seguro
  Ejercicio 1.2 : Login y registro resistentes a ataques comunes
  Ejercicio 3.1 : POST /api/tasks con validación en el servidor
  Actividad 04  : CRUD de tareas (búsqueda parametrizada, control de propiedad, escapado XSS)
"""
import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    DATABASE=os.environ.get("DATABASE", "usuarios.db"),
    MAX_CONTENT_LENGTH=4 * 1024,                        # límite de tamaño de la solicitud (4 KB)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),   # la sesión expira en 30 min
    SESSION_COOKIE_HTTPONLY=True,                       # JavaScript no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",
)

if os.environ.get("EN_INTERNET") == "1":     # al publicarla (Render): cookie solo por HTTPS e IP real
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config["SESSION_COOKIE_SECURE"] = True

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log_seguridad = logging.getLogger("seguridad")   # eventos de seguridad, SIN contraseñas ni datos enviados

ph = PasswordHasher()                        # Argon2id: hash lento y moderno
HASH_FALSO = ph.hash("solo-para-igualar-tiempos")
MAX_INTENTOS_CUENTA = 5
MAX_INTENTOS_IP = 20
MENSAJE_GENERICO = "Correo o contraseña incorrectos."


# ---------------------------------------------------------------- base de datos
def db():
    con = sqlite3.connect(app.config["DATABASE"])
    con.row_factory = sqlite3.Row
    return con


def crear_tablas():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            correo TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intentos (
            clave TEXT PRIMARY KEY,          -- 'cuenta:<correo>' o 'ip:<ip>'
            fallos INTEGER NOT NULL DEFAULT 0,
            bloqueos INTEGER NOT NULL DEFAULT 0,
            bloqueado_hasta TEXT
        );
        CREATE TABLE IF NOT EXISTS tareas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            titulo TEXT NOT NULL,
            descripcion TEXT NOT NULL DEFAULT '',
            estado TEXT NOT NULL DEFAULT 'pendiente'
        );""")


crear_tablas()


# ---------------------------------------------------------------- reglas de contraseña
def errores_password(pw):
    """Devuelve la lista de requisitos que NO cumple la contraseña."""
    faltan = []
    if len(pw) < 12:
        faltan.append("mínimo 12 caracteres")
    if not re.search(r"[a-z]", pw):
        faltan.append("una letra minúscula")
    if not re.search(r"[A-Z]", pw):
        faltan.append("una letra mayúscula")
    if not re.search(r"\d", pw):
        faltan.append("un número")
    if not re.search(r"[^A-Za-z0-9]", pw):
        faltan.append("un carácter especial (!@#$%&*)")
    return faltan


# ---------------------------------------------------------------- límite de intentos
def bloqueado(clave):
    with db() as con:
        fila = con.execute("SELECT bloqueado_hasta FROM intentos WHERE clave = ?", (clave,)).fetchone()
    if fila and fila["bloqueado_hasta"]:
        hasta = datetime.fromisoformat(fila["bloqueado_hasta"])
        if hasta > datetime.now():
            return int((hasta - datetime.now()).total_seconds() // 60) + 1   # minutos restantes
    return 0


def registrar_fallo(clave, limite):
    """Suma un fallo; al llegar al límite bloquea 1, 2, 4, 8... minutos (bloqueo progresivo)."""
    with db() as con:
        con.execute("INSERT OR IGNORE INTO intentos (clave) VALUES (?)", (clave,))
        con.execute("UPDATE intentos SET fallos = fallos + 1 WHERE clave = ?", (clave,))
        fila = con.execute("SELECT fallos, bloqueos FROM intentos WHERE clave = ?", (clave,)).fetchone()
        if fila["fallos"] >= limite:
            minutos = min(2 ** fila["bloqueos"], 60)
            hasta = (datetime.now() + timedelta(minutes=minutos)).isoformat()
            con.execute("UPDATE intentos SET fallos = 0, bloqueos = bloqueos + 1, bloqueado_hasta = ? "
                        "WHERE clave = ?", (hasta, clave))
            return 0
        return limite - fila["fallos"]           # intentos que le quedan


def limpiar_fallos(clave):
    with db() as con:
        con.execute("UPDATE intentos SET fallos = 0 WHERE clave = ?", (clave,))


# ---------------------------------------------------------------- rutas
@app.route("/")
def inicio():
    return redirect(url_for("panel") if "usuario_id" in session else url_for("login"))


@app.route("/registro", methods=["GET", "POST"])
def registro():
    errores, datos = {}, {}
    if request.method == "POST":
        datos = {"nombre": request.form.get("nombre", "").strip(),
                 "apellido": request.form.get("apellido", "").strip(),
                 "correo": request.form.get("correo", "").strip().lower()}
        password = request.form.get("password", "")
        confirmar = request.form.get("confirmar", "")

        if len(datos["nombre"]) < 2:
            errores["nombre"] = "Ingresa tu nombre."
        if len(datos["apellido"]) < 2:
            errores["apellido"] = "Ingresa tu apellido."
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}", datos["correo"]):
            errores["correo"] = "Ingresa un correo válido. Ejemplo: luis.flores@gmail.com"
        faltan = errores_password(password)
        if faltan:
            errores["password"] = "Contraseña débil. Le falta: " + ", ".join(faltan) + "."
        if password != confirmar:
            errores["confirmar"] = "Las contraseñas no coinciden."

        if not errores:
            try:
                with db() as con:   # consulta parametrizada (sin concatenar texto)
                    con.execute("INSERT INTO usuarios (nombre, correo, password_hash) VALUES (?, ?, ?)",
                                (datos["nombre"] + " " + datos["apellido"], datos["correo"], ph.hash(password)))
                return redirect(url_for("login", registrado=1))
            except sqlite3.IntegrityError:
                errores["correo"] = "No se pudo registrar con ese correo. Prueba con otro o inicia sesión."
    return render_template("registro.html", errores=errores, datos=datos)


@app.route("/login", methods=["GET", "POST"])
def login():
    error, correo, codigo = None, "", 200
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")
        ip = request.remote_addr or "0.0.0.0"

        minutos = bloqueado("cuenta:" + correo) or bloqueado("ip:" + ip)
        if minutos:
            codigo = 429                                             # Too Many Requests
            error = f"Demasiados intentos fallidos. Cuenta bloqueada temporalmente, intenta en {minutos} min."
        else:
            with db() as con:
                usuario = con.execute("SELECT * FROM usuarios WHERE correo = ?", (correo,)).fetchone()
            try:   # si el correo no existe se verifica un hash falso para tardar lo mismo
                ph.verify(usuario["password_hash"] if usuario else HASH_FALSO, password)
                correcto = usuario is not None
            except VerifyMismatchError:
                correcto = False

            if correcto:
                limpiar_fallos("cuenta:" + correo)
                session.clear()                    # nuevo identificador de sesión
                session.permanent = True           # expira en 30 minutos
                session["usuario_id"] = usuario["id"]
                session["nombre"] = usuario["nombre"]
                return redirect(url_for("panel"))

            registrar_fallo("ip:" + ip, MAX_INTENTOS_IP)
            quedan = registrar_fallo("cuenta:" + correo, MAX_INTENTOS_CUENTA)
            log_seguridad.warning("login_fallido cuenta=%s ip=%s", correo[:254], ip)   # nunca la contraseña
            if quedan:
                codigo = 401                                         # Unauthorized
                error = f"{MENSAJE_GENERICO} Te quedan {quedan} intento(s)."
            else:
                codigo = 429
                log_seguridad.warning("cuenta_bloqueada cuenta=%s ip=%s", correo[:254], ip)
                error = "Demasiados intentos fallidos. Cuenta bloqueada temporalmente, intenta en unos minutos."
    return render_template("login.html", error=error, correo=correo,
                           registrado=request.args.get("registrado")), codigo


@app.route("/panel")
def panel():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tareas"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================================================================ TAREAS
ESTADOS = {"pendiente": "Pendiente", "en_progreso": "En progreso", "completada": "Completada"}
CAMPOS_PERMITIDOS = {"titulo", "descripcion", "estado"}


def validar_tarea(datos):
    """Validación en el SERVIDOR (Ej. 3.1). Devuelve (tarea_limpia, errores)."""
    errores = {}
    for campo in set(datos) - CAMPOS_PERMITIDOS:           # rechaza campos inesperados (ej. role)
        errores[campo] = "Campo no permitido."
    titulo = " ".join(str(datos.get("titulo") or "").split())          # quita espacios de más
    descripcion = str(datos.get("descripcion") or "").strip()
    estado = str(datos.get("estado") or "pendiente")

    if not 3 <= len(titulo) <= 120:
        errores["titulo"] = "El título es obligatorio y debe tener entre 3 y 120 caracteres."
    if len(descripcion) > 1000:
        errores["descripcion"] = "La descripción admite como máximo 1000 caracteres."
    if estado not in ESTADOS:
        errores["estado"] = "Estado no válido. Usa: pendiente, en_progreso o completada."

    for campo, regla in errores.items():   # OWASP: registrar campo y regla, NUNCA el contenido enviado
        log_seguridad.warning("validacion_fallida campo=%s regla=%s usuario=%s",
                              campo, regla.split(".")[0], session.get("usuario_id"))
    return {"titulo": titulo, "descripcion": descripcion, "estado": estado}, errores


def usuario_actual():
    if "usuario_id" not in session:
        return None
    return session["usuario_id"]


def tarea_propia(tarea_id):
    """Control de propiedad (anti-IDOR): solo el dueño puede ver, editar o eliminar."""
    with db() as con:
        tarea = con.execute("SELECT * FROM tareas WHERE id = ?", (tarea_id,)).fetchone()
    if tarea is None:
        abort(404)
    if tarea["owner_id"] != session["usuario_id"]:
        log_seguridad.warning("acceso_denegado tarea=%s usuario=%s", tarea_id, session["usuario_id"])
        abort(403)
    return tarea


@app.route("/tareas")
def tareas():
    if not usuario_actual():
        return redirect(url_for("login"))
    busqueda = request.args.get("q", "").strip()
    error = None
    # Ej. 4.1: validación de longitud y caracteres permitidos del parámetro de búsqueda
    if len(busqueda) > 50 or not re.fullmatch(r"[\w\sáéíóúÁÉÍÓÚñÑ.,'\"#-]*", busqueda):
        error, busqueda = "Búsqueda no válida: máximo 50 caracteres (letras, números y . , - ' \" #).", ""
    with db() as con:   # consulta parametrizada: el texto buscado nunca altera la consulta SQL
        lista = con.execute("SELECT * FROM tareas WHERE owner_id = ? AND titulo LIKE ? ORDER BY id DESC",
                            (session["usuario_id"], f"%{busqueda}%")).fetchall()
    return render_template("tareas.html", tareas=lista, q=busqueda, error=error, estados=ESTADOS,
                           nombre=session["nombre"], aviso=request.args.get("aviso")), (400 if error else 200)


@app.route("/tareas/nueva", methods=["GET", "POST"])
def nueva_tarea():
    if not usuario_actual():
        return redirect(url_for("login"))
    datos, errores = {"estado": "pendiente"}, {}
    if request.method == "POST":
        datos, errores = validar_tarea({c: request.form.get(c) for c in CAMPOS_PERMITIDOS})
        if not errores:
            with db() as con:
                con.execute("INSERT INTO tareas (owner_id, titulo, descripcion, estado) VALUES (?, ?, ?, ?)",
                            (session["usuario_id"], datos["titulo"], datos["descripcion"], datos["estado"]))
            return redirect(url_for("tareas", aviso="creada"))
    return render_template("tarea_form.html", datos=datos, errores=errores, estados=ESTADOS, editar=False)


@app.route("/tareas/<int:tarea_id>/editar", methods=["GET", "POST"])
def editar_tarea(tarea_id):
    if not usuario_actual():
        return redirect(url_for("login"))
    datos, errores = dict(tarea_propia(tarea_id)), {}
    if request.method == "POST":
        datos, errores = validar_tarea({c: request.form.get(c) for c in CAMPOS_PERMITIDOS})
        if not errores:
            with db() as con:
                con.execute("UPDATE tareas SET titulo = ?, descripcion = ?, estado = ? WHERE id = ? AND owner_id = ?",
                            (datos["titulo"], datos["descripcion"], datos["estado"], tarea_id, session["usuario_id"]))
            return redirect(url_for("tareas", aviso="actualizada"))
    return render_template("tarea_form.html", datos=datos, errores=errores, estados=ESTADOS,
                           editar=True, tarea_id=tarea_id)


@app.route("/tareas/<int:tarea_id>/eliminar", methods=["POST"])
def eliminar_tarea(tarea_id):
    if not usuario_actual():
        return redirect(url_for("login"))
    tarea_propia(tarea_id)
    with db() as con:
        con.execute("DELETE FROM tareas WHERE id = ? AND owner_id = ?", (tarea_id, session["usuario_id"]))
    return redirect(url_for("tareas", aviso="eliminada"))


# ---------------------------------------------------------------- Ej. 3.1: API JSON
@app.route("/api/tasks", methods=["POST"])
def api_crear_tarea():
    if not usuario_actual():
        return jsonify({"error": "Autenticación requerida."}), 401
    cuerpo = request.get_json(silent=True)
    if not isinstance(cuerpo, dict):
        return jsonify({"error": "Se esperaba un objeto JSON."}), 400
    datos, errores = validar_tarea(cuerpo)
    if errores:
        return jsonify({"errores": errores}), 400
    with db() as con:
        cur = con.execute("INSERT INTO tareas (owner_id, titulo, descripcion, estado) VALUES (?, ?, ?, ?)",
                          (session["usuario_id"], datos["titulo"], datos["descripcion"], datos["estado"]))
    return jsonify({"id": cur.lastrowid, **datos}), 201


@app.errorhandler(403)
def prohibido(_e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Acceso prohibido."}), 403
    return render_template("error.html", codigo=403, mensaje="No tienes permiso para acceder a esta tarea."), 403


@app.errorhandler(404)
def no_encontrado(_e):
    return render_template("error.html", codigo=404, mensaje="La página o tarea no existe."), 404


@app.errorhandler(413)
def muy_grande(_e):
    return jsonify({"error": "La solicitud supera el tamaño máximo permitido (4 KB)."}), 413


if __name__ == "__main__":
    app.run(debug=False)
