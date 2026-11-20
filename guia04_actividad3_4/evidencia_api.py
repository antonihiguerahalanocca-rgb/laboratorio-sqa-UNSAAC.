"""Ejecuta solicitudes reales contra POST /api/tasks y muestra la respuesta (evidencia Ej. 3.1)."""
import json
import os
import sys
import tempfile

os.environ["DATABASE"] = os.path.join(tempfile.mkdtemp(), "evidencia.db")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guia04_login_seguro"))
import logging  # noqa: E402
import app as modulo  # noqa: E402

logging.getLogger("seguridad").setLevel(logging.CRITICAL)
c = modulo.app.test_client()
CLAVE = "Cusco#Machu2026"
c.post("/registro", data={"nombre": "Luis", "apellido": "Flores Quispe", "correo": "luis.flores@gmail.com",
                          "password": CLAVE, "confirmar": CLAVE})
anonimo = modulo.app.test_client()


def probar(nombre, cuerpo, cliente=None):
    r = (cliente or c).post("/api/tasks", json=cuerpo)
    print(f"# {nombre}")
    print(f"POST /api/tasks  {json.dumps(cuerpo, ensure_ascii=False)[:90]}")
    print(f"<- HTTP {r.status_code}  {json.dumps(r.get_json(), ensure_ascii=False)[:120]}")
    print()


probar("Sin token de autenticación", {"titulo": "Estudiar ISW"}, anonimo)
c.post("/login", data={"correo": "luis.flores@gmail.com", "password": CLAVE})
probar("Campo vacío", {"titulo": "", "estado": "pendiente"})
probar("Campo demasiado largo (121 caracteres)", {"titulo": "A" * 121, "estado": "pendiente"})
probar("Valor de estado inválido", {"titulo": "Estudiar ISW", "estado": "borrado"})
probar("Campo adicional inyectado", {"titulo": "Estudiar ISW", "estado": "pendiente", "role": "admin"})
probar("Unicode y espacios (se normaliza)", {"titulo": "   Revisar   año 2026 ñandú  ", "estado": "en_progreso"})
probar("Tarea válida", {"titulo": "Estudiar ISW", "descripcion": "Capítulo 4", "estado": "pendiente"})
r = c.post("/api/tasks", data="x" * 5000, content_type="application/json")
print("# Solicitud de 5000 bytes (límite de tamaño)")
print("POST /api/tasks  <cuerpo de 5000 bytes>")
print(f"<- HTTP {r.status_code}  {json.dumps(r.get_json(), ensure_ascii=False)}")
