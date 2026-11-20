import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('reservas.db')
    conn.row_factory = sqlite3.Row
    return conn

# VULNERABILIDAD 1: Inyección SQL + IDOR
@app.route('/api/reserva', methods=['GET'])
def obtener_reserva():
    id_reserva = request.args.get('id')
    user_id_session = request.args.get('user_id') # Simulación de usuario autenticado

    conn = get_db_connection()
    cursor = conn.cursor()
    # Inseguro: Concatenación directa de entradas en la consulta SQL
    query = f"SELECT * FROM reservas WHERE id = {id_reserva}"
    reserva = cursor.execute(query).fetchone()

    if reserva is None:
        return jsonify({"error": "Reserva no encontrada"}), 404

    # Inseguro: No se valida si reserva['usuario_id'] == user_id_session (IDOR)
    return jsonify(dict(reserva)), 200

# VULNERABILIDAD 2: Cross-Site Scripting (XSS)
@app.route('/bienvenida', methods=['GET'])
def bienvenida():
    nombre = request.args.get('nombre', '')
    # Inseguro: Renderizado directo de cadenas sin sanitizar/escapar HTML
    template = f"<h1>Bienvenido, {nombre}!</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
