"""Pruebas del Ejercicio 3.1 (validación), 4.1 (búsqueda parametrizada) y CRUD seguro."""
import os
import sys
import tempfile

os.environ.setdefault("DATABASE", os.path.join(tempfile.mkdtemp(), "test.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as modulo  # noqa: E402

CLAVE = "Cusco#Machu2026"


def usuario(correo):
    c = modulo.app.test_client()
    c.post("/registro", data={"nombre": "Luis", "apellido": "Flores", "correo": correo,
                              "password": CLAVE, "confirmar": CLAVE})
    c.post("/login", data={"correo": correo, "password": CLAVE})
    return c


def crear(c, **datos):
    base = {"titulo": "Estudiar ISW", "descripcion": "", "estado": "pendiente"}
    base.update(datos)
    return c.post("/api/tasks", json=base)


# ---------------------------------------------------------- Ej. 3.1: validación
def test_api_crea_tarea_valida():
    r = crear(usuario("t1@gmail.com"))
    assert r.status_code == 201 and r.get_json()["titulo"] == "Estudiar ISW"


def test_campo_vacio_rechazado():
    r = crear(usuario("t2@gmail.com"), titulo="")
    assert r.status_code == 400 and "titulo" in r.get_json()["errores"]


def test_campo_demasiado_largo_rechazado():
    c = usuario("t3@gmail.com")
    assert crear(c, titulo="A" * 121).status_code == 400
    assert crear(c, descripcion="B" * 1001).status_code == 400


def test_estado_invalido_rechazado():
    r = crear(usuario("t4@gmail.com"), estado="borrado")
    assert r.status_code == 400 and "estado" in r.get_json()["errores"]


def test_campo_inyectado_role_admin_rechazado():
    r = crear(usuario("t5@gmail.com"), role="admin")
    assert r.status_code == 400 and r.get_json()["errores"]["role"] == "Campo no permitido."


def test_unicode_y_espacios_se_normalizan():
    r = crear(usuario("t6@gmail.com"), titulo="   Revisar   año 2026 — ñandú   ")
    assert r.status_code == 201 and r.get_json()["titulo"] == "Revisar año 2026 — ñandú"


def test_solicitud_sin_token_401():
    r = modulo.app.test_client().post("/api/tasks", json={"titulo": "Hola mundo"})
    assert r.status_code == 401


def test_solicitud_muy_grande_413():
    r = usuario("t7@gmail.com").post("/api/tasks", data="x" * 5000, content_type="application/json")
    assert r.status_code == 413


def test_log_no_guarda_el_payload(caplog):
    crear(usuario("t8@gmail.com"), titulo="<script>robar()</script>" * 10)
    assert "validacion_fallida campo=titulo" in caplog.text
    assert "robar" not in caplog.text


# ---------------------------------------------------------- Ej. 4.1: búsqueda
def test_busqueda_normal():
    c = usuario("b1@gmail.com")
    crear(c, titulo="Leer capítulo 4")
    crear(c, titulo="Hacer ejercicios")
    html = c.get("/tareas?q=capítulo").get_data(as_text=True)
    assert "Leer capítulo 4" in html and "Hacer ejercicios" not in html


def test_busqueda_con_comillas_no_inyecta_sql():
    ajena = usuario("ajena@gmail.com")
    crear(ajena, titulo="Tarea secreta de otro usuario")
    c = usuario("b2@gmail.com")
    # pasa la lista blanca (letras y comillas) y llega a la consulta: se trata como TEXTO literal
    r = c.get("/tareas", query_string={"q": "' OR 'a' LIKE 'a"})
    assert r.status_code == 200 and "Tarea secreta" not in r.get_data(as_text=True)
    # con = o -- ni siquiera llega a la base de datos: lo rechaza la validación
    assert c.get("/tareas", query_string={"q": "' OR 1=1 --"}).status_code == 400


def test_busqueda_cadena_larga_rechazada():
    assert usuario("b3@gmail.com").get("/tareas?q=" + "a" * 51).status_code == 400


def test_busqueda_caracteres_especiales_rechazados():
    assert usuario("b4@gmail.com").get("/tareas?q=;DROP TABLE tareas;--").status_code == 400


def test_busqueda_vacia_lista_todo():
    c = usuario("b5@gmail.com")
    crear(c, titulo="Primera tarea")
    assert "Primera tarea" in c.get("/tareas?q=").get_data(as_text=True)


# ---------------------------------------------------------- CRUD seguro
def test_editar_tarea_propia():
    c = usuario("c1@gmail.com")
    tid = crear(c).get_json()["id"]
    r = c.post(f"/tareas/{tid}/editar", data={"titulo": "Estudiar ISW (editado)", "descripcion": "",
                                              "estado": "completada"})
    assert r.status_code == 302
    assert "Estudiar ISW (editado)" in c.get("/tareas").get_data(as_text=True)


def test_idor_editar_tarea_ajena_403():
    duena = usuario("c2@gmail.com")
    tid = crear(duena).get_json()["id"]
    atacante = usuario("c3@gmail.com")
    r = atacante.post(f"/tareas/{tid}/editar", data={"titulo": "hackeada", "estado": "pendiente"})
    assert r.status_code == 403


def test_idor_eliminar_tarea_ajena_403():
    duena = usuario("c4@gmail.com")
    tid = crear(duena).get_json()["id"]
    assert usuario("c5@gmail.com").post(f"/tareas/{tid}/eliminar").status_code == 403
    assert "Estudiar ISW" in duena.get("/tareas").get_data(as_text=True)   # sigue existiendo


def test_eliminar_tarea_propia():
    c = usuario("c6@gmail.com")
    tid = crear(c, titulo="Tarea a borrar").get_json()["id"]
    c.post(f"/tareas/{tid}/eliminar")
    assert "Tarea a borrar" not in c.get("/tareas").get_data(as_text=True)


def test_xss_en_titulo_se_muestra_escapado():
    c = usuario("x1@gmail.com")
    crear(c, titulo="<script>alert(1)</script>")
    html = c.get("/tareas").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
