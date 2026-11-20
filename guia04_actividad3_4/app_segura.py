import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('reservas.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/reserva', methods=['GET'])
def obtener_reserva():
    id_reserva = request.args.get('id')
    user_id_session = request.args.get('user_id') # ID proveniente del token/sesión validada

    # Validar entrada
    if not id_reserva or not id_reserva.isdigit() or not user_id_session:
        return jsonify({"error": "Parámetros inválidos o sesión no provista"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Corrección SQLi: Consulta parametrizada
    query = "SELECT * FROM reservas WHERE id = ?"
    reserva = cursor.execute(query, (id_reserva,)).fetchone()

    if reserva is None:
        return jsonify({"error": "Reserva no encontrada"}), 404

    # 2. Corrección IDOR: Verificación estricta de propiedad en servidor
    if str(reserva['usuario_id']) != str(user_id_session):
        # Fallar de forma segura: Bloquear acceso a recursos ajenos
        return jsonify({"error": "Acceso prohibido al recurso solicitante"}), 403

    return jsonify(dict(reserva)), 200

@app.route('/bienvenida', methods=['GET'])
def bienvenida():
    nombre = request.args.get('nombre', '')
    # 3. Corrección XSS: el motor de plantillas Jinja2 escapa automáticamente {{ nombre }}
    #    (< > " ' & se convierten en entidades HTML, igual que markupsafe.escape())
    return render_template_string("<h1>Bienvenido, {{ nombre }}!</h1>", nombre=nombre)

if __name__ == '__main__':
    app.run(debug=False, port=5000)
