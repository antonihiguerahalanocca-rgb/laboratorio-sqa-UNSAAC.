"""VERSIÓN INSEGURA (ANTES) - Ejercicios 3.1 y 4.1. Solo para demostrar las fallas."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
con = sqlite3.connect(":memory:", check_same_thread=False)
con.execute("CREATE TABLE tasks (id INTEGER PRIMARY KEY, owner_id INT, title TEXT, description TEXT, status TEXT, role TEXT)")
con.execute("INSERT INTO tasks (owner_id, title, status) VALUES (1, 'Tarea de Luis', 'pendiente')")
con.execute("INSERT INTO tasks (owner_id, title, status) VALUES (2, 'Tarea privada de Ana', 'pendiente')")


# Ej. 3.1 - INSEGURO: acepta cualquier dato y lo guarda directamente (sin token ni validación)
@app.route("/tasks", methods=["POST"])
def crear_tarea():
    datos = request.get_json()
    con.execute("INSERT INTO tasks (title, description, status, role) VALUES (?, ?, ?, ?)",
                (datos.get("title"), datos.get("description"), datos.get("status"), datos.get("role")))
    return jsonify(datos), 201


# Ej. 4.1 - INSEGURO: búsqueda construida por concatenación de cadenas
@app.route("/tasks/buscar", methods=["GET"])
def buscar():
    search = request.args.get("search", "")
    query = "SELECT * FROM tasks WHERE owner_id = 1 AND title LIKE '%" + search + "%'"
    filas = con.execute(query).fetchall()
    return jsonify([list(f) for f in filas]), 200
