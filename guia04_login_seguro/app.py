"""
Ejercicio 1.2 - Login y Registro resistentes a ataques comunes (Guía 04 - ISW Seguro)
"""
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    DATABASE=os.environ.get("DATABASE", "usuarios.db"),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),   # la sesión expira en 30 min
    SESSION_COOKIE_HTTPONLY=True,                       # JavaScript no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",
)

if os.environ.get("EN_INTERNET") == "1":     # al publicarla (Render): cookie solo por HTTPS e IP real
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config["SESSION_COOKIE_SECURE"] = True

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
    error, correo = None, ""
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")
        ip = request.remote_addr or "0.0.0.0"

        minutos = bloqueado("cuenta:" + correo) or bloqueado("ip:" + ip)
        if minutos:
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
            if quedan:
                error = f"{MENSAJE_GENERICO} Te quedan {quedan} intento(s)."
            else:
                error = "Demasiados intentos fallidos. Cuenta bloqueada temporalmente, intenta en unos minutos."
    return render_template("login.html", error=error, correo=correo,
                           registrado=request.args.get("registrado"))


@app.route("/panel")
def panel():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    return render_template("panel.html", nombre=session["nombre"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=False)
