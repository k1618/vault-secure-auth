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

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key-change-me-in-.env")
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
