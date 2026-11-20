# SecureLogin: login y registro seguros

Ejercicio 1.2 de la Guía de Práctica 04 (Ingeniería de Software Seguro, UNSAAC).

- Contraseñas guardadas con **Argon2id**.
- Contraseña de mínimo **12 caracteres** con minúscula, mayúscula, número y carácter especial. Un medidor muestra su nivel en rojo, naranja o verde.
- **Ojito** para mostrar u ocultar la contraseña en el login y en el registro.
- Límite de 5 intentos por cuenta y 20 por IP, con **bloqueo progresivo** de 1, 2, 4, 8… minutos.
- Mensajes de error **genéricos** que no revelan si el correo existe.
- Sesión que **expira a los 30 minutos** y se regenera al iniciar sesión.

## Ejecutar
```bash
pip install -r requirements.txt
python app.py          # abrir http://127.0.0.1:5000
python -m pytest -v    # 8 pruebas
```

## Publicar gratis (Render)
Sube el proyecto a GitHub. En render.com entra a **New → Blueprint** y elige el repositorio.
