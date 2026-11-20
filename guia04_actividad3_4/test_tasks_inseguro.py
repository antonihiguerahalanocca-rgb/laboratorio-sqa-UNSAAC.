"""ANTES: demuestra que la versión insegura acepta datos maliciosos."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tasks_inseguro  # noqa: E402

c = tasks_inseguro.app.test_client()


def test_antes_acepta_titulo_vacio():
    assert c.post("/tasks", json={"title": "", "status": "pendiente"}).status_code == 201


def test_antes_acepta_titulo_gigante():
    assert c.post("/tasks", json={"title": "A" * 5000, "status": "x"}).status_code == 201


def test_antes_acepta_role_admin_y_sin_token():
    r = c.post("/tasks", json={"title": "hack", "status": "pendiente", "role": "admin"})
    assert r.status_code == 201 and r.get_json()["role"] == "admin"


def test_antes_inyeccion_sql_en_busqueda_filtra_tareas_ajenas():
    r = c.get("/tasks/buscar", query_string={"search": "' OR 1=1 --"})
    titulos = [fila[2] for fila in r.get_json()]
    assert "Tarea privada de Ana" in titulos       # se filtró una tarea de OTRO usuario
