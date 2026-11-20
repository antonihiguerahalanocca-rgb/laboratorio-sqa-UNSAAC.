"""Crea reservas.db con datos de ejemplo para las Actividades 3 y 4."""
import sqlite3

con = sqlite3.connect("reservas.db")
con.executescript("""
DROP TABLE IF EXISTS reservas;
CREATE TABLE reservas (
    id INTEGER PRIMARY KEY,
    usuario_id INTEGER NOT NULL,
    cliente TEXT NOT NULL,
    telefono TEXT NOT NULL,
    cancha TEXT NOT NULL,
    fecha TEXT NOT NULL
);
INSERT INTO reservas VALUES
 (104, 10, 'Luis Flores Quispe',  '987654321', 'Cancha 1 - Fútbol', '2026-11-25 18:00'),
 (105, 10, 'Luis Flores Quispe',  '987654321', 'Cancha 2 - Vóley',  '2026-11-26 19:00'),
 (106, 20, 'Ana Mamani Huamán',   '912345678', 'Cancha 3 - Básquet','2026-11-27 17:00'),
 (107, 30, 'Brayan Higuera',      '934567890', 'Cancha 1 - Fútbol', '2026-11-28 20:00');
""")
con.commit()
con.close()
print("reservas.db creada con 4 reservas")
