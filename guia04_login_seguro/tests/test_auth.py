"""Pruebas de seguridad del login y registro (Ejercicio 1.2)."""
import os
import sys
import tempfile

os.environ["DATABASE"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as modulo  # noqa: E402

CLAVE = "Cusco#Machu2026"


def cliente():
    modulo.app.config["TESTING"] = True
    return modulo.app.test_client()


def registrar(c, correo, clave=CLAVE):
    return c.post("/registro", data={"nombre": "Ana", "apellido": "Quispe", "correo": correo,
                                     "password": clave, "confirmar": clave})


def entrar(c, correo, clave):
    return c.post("/login", data={"correo": correo, "password": clave})


def test_contrasena_debil_es_rechazada():
    r = registrar(cliente(), "debil@unsaac.edu.pe", "hola123")
    html = r.get_data(as_text=True)
    assert "Contraseña débil" in html and "mínimo 12 caracteres" in html


def test_contrasena_se_guarda_con_argon2id():
    registrar(cliente(), "hash@unsaac.edu.pe")
    with modulo.db() as con:
        h = con.execute("SELECT password_hash FROM usuarios WHERE correo='hash@unsaac.edu.pe'").fetchone()[0]
    assert h.startswith("$argon2id$") and CLAVE not in h


def test_login_correcto_entra_al_panel():
    c = cliente()
    registrar(c, "ok@unsaac.edu.pe")
    r = entrar(c, "ok@unsaac.edu.pe", CLAVE)
    assert r.headers["Location"].endswith("/panel")


def test_credenciales_invalidas_mensaje_generico():
    c = cliente()
    registrar(c, "gen@unsaac.edu.pe")
    a = entrar(c, "gen@unsaac.edu.pe", "Incorrecta#2026").get_data(as_text=True)   # correo existe
    b = entrar(c, "noexiste@unsaac.edu.pe", "Incorrecta#2026").get_data(as_text=True)  # no existe
    assert "Correo o contraseña incorrectos." in a and "Correo o contraseña incorrectos." in b


def test_fuerza_bruta_bloquea_la_cuenta():
    c = cliente()
    registrar(c, "bruta@unsaac.edu.pe")
    for i in range(5):
        entrar(c, "bruta@unsaac.edu.pe", f"Mala#{i}xxxxxxx")
    r = entrar(c, "bruta@unsaac.edu.pe", CLAVE)  # ni con la clave correcta entra
    assert "bloqueada temporalmente" in r.get_data(as_text=True)


def test_panel_sin_sesion_redirige_al_login():
    r = cliente().get("/panel")
    assert r.headers["Location"].endswith("/login")


def test_sesion_expira_en_30_minutos():
    assert modulo.app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 30 * 60
    assert modulo.app.config["SESSION_COOKIE_HTTPONLY"] is True


def test_logout_cierra_la_sesion():
    c = cliente()
    registrar(c, "salir@unsaac.edu.pe")
    entrar(c, "salir@unsaac.edu.pe", CLAVE)
    c.get("/logout")
    assert c.get("/panel").headers["Location"].endswith("/login")
