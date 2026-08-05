from datetime import datetime, timezone

from flask_login import UserMixin
from app import db, bcrypt


def utcnow_naive() -> datetime:
    """
    UTC actual como datetime *naive* (sin tzinfo).

    Se usa naive a propósito: SQLite no conserva la zona horaria al
    guardar un DateTime, así que cualquier valor que se compare contra
    lo leído de la base de datos debe ser naive también, o Python lanza
    TypeError al comparar aware vs naive (bug real que se encontró y
    corrigió en este proyecto). datetime.utcnow() hacía esto mismo pero
    está deprecado desde Python 3.12+.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    """
    Modelo de usuario.

    La contraseña NUNCA se guarda en texto plano ni siquiera temporalmente
    en un atributo: `set_password` recibe la contraseña, la hashea con
    bcrypt (que incluye salt automático) y descarta el texto original.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow_naive)
    last_login_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, plain_password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(plain_password).decode("utf-8")

    def check_password(self, plain_password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, plain_password)

    def __repr__(self):
        return f"<User {self.username}>"
