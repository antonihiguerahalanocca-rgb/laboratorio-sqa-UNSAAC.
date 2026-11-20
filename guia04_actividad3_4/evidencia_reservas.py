"""Ataques de la guía contra app_vulnerable.py (ANTES) y app_segura.py (DESPUÉS)."""
import json
import os
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
os.chdir(AQUI)
subprocess.run([sys.executable, "crear_bd.py"], check=True, capture_output=True)
sys.path.insert(0, AQUI)
import app_segura  # noqa: E402
import app_vulnerable  # noqa: E402

ATAQUES = [
    ("PR-01 Inyección SQL", "/api/reserva?id=1 OR 1=1&user_id=99"),
    ("PR-02 IDOR (reserva 105 es del usuario 10)", "/api/reserva?id=105&user_id=99"),
    ("PR-03 XSS reflejado", "/bienvenida?nombre=<script>alert(1)</script>"),
]
for titulo_app, modulo in (("ANTES  -> app_vulnerable.py", app_vulnerable), ("DESPUÉS -> app_segura.py", app_segura)):
    print("=" * 18, titulo_app, "=" * 18)
    c = modulo.app.test_client()
    for nombre, url in ATAQUES:
        r = c.get(url)
        cuerpo = r.get_json(silent=True)
        texto = json.dumps(cuerpo, ensure_ascii=False) if cuerpo is not None else r.get_data(as_text=True)
        print(f"# {nombre}")
        print(f"GET {url}")
        print(f"<- HTTP {r.status_code}  {texto[:110]}")
    print()
