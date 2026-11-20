"""Pruebas negativas: el ataque funciona en app_vulnerable y es bloqueado en app_segura."""
import os
import subprocess
import sys

import pytest

AQUI = os.path.dirname(os.path.abspath(__file__))
os.chdir(AQUI)
subprocess.run([sys.executable, "crear_bd.py"], check=True, capture_output=True)
sys.path.insert(0, AQUI)

import app_segura      # noqa: E402
import app_vulnerable  # noqa: E402

SQLI = "/api/reserva?id=1 OR 1=1&user_id=99"
IDOR = "/api/reserva?id=105&user_id=99"          # la reserva 105 es del usuario 10
XSS = "/bienvenida?nombre=<script>alert(1)</script>"


@pytest.fixture
def vulnerable():
    return app_vulnerable.app.test_client()


@pytest.fixture
def segura():
    return app_segura.app.test_client()


# ---------------- ANTES: app_vulnerable.py (el ataque funciona) ----------------
def test_antes_sqli_devuelve_datos(vulnerable):
    r = vulnerable.get(SQLI)
    assert r.status_code == 200 and "cliente" in r.get_json()


def test_antes_idor_entrega_reserva_ajena(vulnerable):
    r = vulnerable.get(IDOR)
    assert r.status_code == 200 and r.get_json()["usuario_id"] == 10


def test_antes_xss_ejecuta_script(vulnerable):
    assert "<script>alert(1)</script>" in vulnerable.get(XSS).get_data(as_text=True)


# ---------------- DESPUÉS: app_segura.py (el ataque es bloqueado) ----------------
def test_despues_sqli_responde_400(segura):
    r = segura.get(SQLI)
    assert r.status_code == 400 and "cliente" not in r.get_json()


def test_despues_idor_responde_403(segura):
    r = segura.get(IDOR)
    assert r.status_code == 403
    assert r.get_json() == {"error": "Acceso prohibido al recurso solicitante"}


def test_despues_dueno_si_accede(segura):
    r = segura.get("/api/reserva?id=105&user_id=10")
    assert r.status_code == 200 and r.get_json()["id"] == 105


def test_despues_xss_escapado(segura):
    html = segura.get(XSS).get_data(as_text=True)
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_despues_reserva_inexistente_404(segura):
    assert segura.get("/api/reserva?id=999&user_id=10").status_code == 404
