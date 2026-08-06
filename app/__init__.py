"""
Application factory.

Se usa el patrón "app factory" en vez de una instancia global de Flask
para que la app se pueda instanciar varias veces con configuraciones
distintas (desarrollo, pruebas, producción) — esto es lo que permite
que los tests corran contra una base de datos aislada en memoria.
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

CONFIGS = {
    "development": {
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}",
        "DEBUG": True,
    },
    "testing": {
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
    },
    "production": {
        "SQLALCHEMY_DATABASE_URI": os.getenv(
            "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}"
        ),
        "DEBUG": False,
    },
}


def create_app(env: str = "development"):
    app = Flask(__name__)

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        if env == "production":
            # SECRET_KEY firma las cookies de sesión (incluida la sesión
            # "pendiente" del segundo factor en 2FA) y los tokens CSRF.
            # Un valor por defecto público en producción anula ambas
            # protecciones — mejor que la app no arranque, a que arranque
            # insegura sin que nadie se dé cuenta.
            raise RuntimeError(
                "SECRET_KEY no está configurada. Define la variable de entorno "
                "SECRET_KEY antes de arrancar en producción (ver .env.example)."
            )
        secret_key = "dev-key-change-me-in-.env"  # solo aceptable en development/testing
    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.update(CONFIGS.get(env, CONFIGS["development"]))

    os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)

    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Inicia sesión para continuar."
    login_manager.login_message_category = "info"

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.routes import auth_bp, main_bp, api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    return app
