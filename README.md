# Vault — Plataforma de Autenticación Segura
![CI](https://img.shields.io/badge/CI-passing-brightgreen) ![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue) ![Flask](https://img.shields.io/badge/Flask-black) ![License](https://img.shields.io/badge/License-MIT-lightgrey)

Aplicación web de registro e inicio de sesión construida con Flask, enfocada en seguridad de contraseñas aplicada, no solo en tener un formulario que funcione. Es la evolución de tres proyectos anteriores de práctica (gestor de tareas en CLI, CRUD de usuarios con SQLite, y validador de contraseñas con regex), unidos en una sola aplicación con propósito claro.

## Por qué existe este proyecto

Cualquiera puede hacer un formulario de login. La pregunta que este proyecto intenta responder es: ¿qué debería pasar exactamente cuando alguien crea una contraseña, y por qué? Cada decisión de este repo tiene una razón de seguridad detrás, explicada en el código y aquí abajo.

## Funcionalidades

- Registro e inicio de sesión con validación de usuario/correo duplicados.
- Hashing de contraseñas con bcrypt (salt automático por usuario) — la contraseña en texto plano nunca se almacena, ni siquiera temporalmente en una columna de base de datos.
- Medidor de fuerza de contraseña en tiempo real, sin recargar la página: longitud, mayúsculas, minúsculas, números y símbolos.
- Verificación contra filtraciones conocidas usando la API pública de Have I Been Pwned con el modelo k-Anonymity: la contraseña se hashea con SHA-1 en el navegador del usuario y otra vez en el backend, y solo se envían los primeros 5 caracteres del hash a la API externa — la contraseña real jamás sale de la aplicación.
- Protección contra fuerza bruta: bloqueo temporal de la cuenta tras 5 intentos fallidos de inicio de sesión.
- Mensajes de error genéricos en login ("usuario o contraseña incorrectos") para no revelar si el problema fue el usuario o la contraseña — evita que un atacante pueda enumerar cuentas válidas.
- Protección CSRF en todos los formularios (Flask-WTF).
- Sesiones gestionadas con Flask-Login, rutas protegidas con `@login_required`.
- **Autenticación de dos factores (TOTP)**, compatible con cualquier app autenticadora que soporte TOTP — se recomienda **Google Authenticator**, aunque también funciona con Authy, 1Password, Microsoft Authenticator, etc.:
  - Código QR generado en el propio servidor (el secreto nunca se manda a un servicio externo de generación de QR).
  - El secreto también se puede ingresar de forma manual en la app autenticadora, sin necesidad de escanear el QR.
  - Protección anti-replay: el mismo código de 6 dígitos no se puede reutilizar dos veces dentro de su ventana de validez.
  - Códigos de respaldo de un solo uso por si el usuario pierde su dispositivo — cada uno se invalida automáticamente después de usarse una vez.
  - Límite de intentos en la verificación del segundo factor (igual que el bloqueo de login por contraseña).

## Arquitectura

```
secure-auth-platform/
├── app/
│   ├── __init__.py        # Application factory (patrón factory de Flask)
│   ├── models.py           # Modelo User (SQLAlchemy)
│   ├── routes.py           # Blueprints: auth, main, api
│   ├── security.py         # Validación de fuerza + chequeo HIBP + TOTP/2FA (sin dependencias de Flask)
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/password-check.js   # Medidor de fuerza en vivo + llamada AJAX a /api/check-password
│   └── templates/          # Jinja2: base, index, register, login, dashboard, setup/verify/disable 2FA
├── scripts/
│   └── migrate_add_2fa_columns.py   # Agrega las columnas de 2FA a una DB SQLite ya existente
├── tests/
│   ├── test_security.py       # Tests unitarios puros (sin Flask, sin red)
│   ├── test_auth_routes.py    # Tests de integración con test client + SQLite en memoria
│   └── test_totp_routes.py    # Tests de integración del flujo completo de 2FA
├── .github/workflows/ci.yml    # Corre lint + tests en cada push/PR
├── requirements.txt
└── run.py
```

`app/security.py` está deliberadamente desacoplado de Flask: son funciones puras de Python que reciben un string y devuelven un resultado, para que se puedan probar sin levantar un servidor ni tocar una base de datos.

## Cómo funciona el chequeo de filtraciones (k-Anonymity)

1. El usuario escribe una contraseña en `/register`.
2. El backend calcula `SHA1(password)` → por ejemplo `A94A8FE5CC...`.
3. Solo se envían los primeros 5 caracteres (`A94A8`) a la API de HIBP.
4. HIBP responde con todos los sufijos de hash que comparten ese prefijo (cientos de ellos).
5. La comparación del sufijo completo se hace localmente, en nuestro propio código — la API nunca recibe la contraseña, ni su hash completo.

## Instalación local

```bash
git clone https://github.com/k1618/vault-secure-auth.git
cd vault-secure-auth

python -m venv .venv
source .venv/bin/activate        # En Windows: .venv\Scripts\activate

pip install -r requirements-dev.txt

cp .env.example .env             # y edita SECRET_KEY

python run.py
```

La app queda disponible en `http://127.0.0.1:5000`.

**Si ya tenías el proyecto corriendo antes de la versión con 2FA:** tu `instance/app.db` local no se actualiza solo (`instance/` está en `.gitignore`, así que `git pull` no lo toca). Corre esto una vez para agregar las columnas nuevas sin perder tus usuarios existentes:

```bash
python scripts/migrate_add_2fa_columns.py
```

## Correr los tests

```bash
pytest -v                        # tests
pytest --cov=app                 # con reporte de cobertura
flake8 app tests                 # estilo
```

Los tests que dependen de la API externa de HIBP se saltan automáticamente (en vez de fallar) si el entorno donde corren no tiene salida a esa API — por ejemplo, un runner de CI con red restringida.

## Decisiones de seguridad y por qué se tomaron

| Decisión | Razón |
|---|---|
| bcrypt en vez de SHA-256 simple | bcrypt es deliberadamente lento y tiene salt integrado, lo que hace inviables los ataques de fuerza bruta con GPU/rainbow tables |
| k-Anonymity para HIBP | Verificar filtraciones sin exponer la contraseña real a un tercero |
| Bloqueo tras 5 intentos | Mitiga ataques de fuerza bruta online contra una cuenta específica |
| Mensajes de error genéricos en login | Evita enumeración de usuarios válidos |
| CSRF token en formularios | Evita que un sitio malicioso envíe formularios en nombre del usuario autenticado |
| TOTP + códigos de respaldo de un solo uso | Segundo factor de autenticación resistente a robo de contraseña, con recuperación segura si se pierde el dispositivo |
| `.env` fuera de git | Evita subir `SECRET_KEY` u otras credenciales al repositorio |

## Roadmap (próximas mejoras)

- [ ] Verificación de correo al registrarse
- [ ] Rate limiting a nivel de IP con Flask-Limiter
- [ ] Migrar de SQLite a PostgreSQL para despliegue en producción
- [ ] Despliegue en Render/Railway con demo en vivo

## Stack

Python · Flask · SQLAlchemy · Flask-Login · Flask-Bcrypt · Flask-WTF · SQLite · pytest · GitHub Actions

## Autor

Dilan Eduardo Martínez Castro — Estudiante de Ingeniería en Desarrollo de Software, Universidad Ciudadana de Nuevo León. GitHub · LinkedIn

## Licencia

MIT — ver LICENSE.
