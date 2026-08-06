import json
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

    # --- 2FA (TOTP) ---
    # totp_secret se guarda en texto plano (base32) a propósito: es la
    # llave simétrica que la app necesita releer en cada verificación
    # para regenerar el código esperado, así que no puede guardarse
    # hasheada (a diferencia de la contraseña). La protección real de
    # este dato depende de proteger la base de datos en reposo (fuera
    # del alcance de este proyecto de portafolio).
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    # Último "paso" temporal (bloque de 30s) de TOTP aceptado. Evita que
    # alguien que interceptó un código válido (p. ej. por shoulder-surfing)
    # lo reutilice dentro de la misma ventana de tolerancia.
    totp_last_counter = db.Column(db.Integer, nullable=True)
    # Lista JSON de hashes bcrypt, uno por código de respaldo sin usar.
    # Los códigos SÍ se hashean (a diferencia del secreto TOTP) porque
    # son de un solo uso y equivalen a una contraseña alterna: nunca se
    # vuelven a necesitar en texto plano una vez generados.
    backup_codes = db.Column(db.Text, nullable=True)

    def set_password(self, plain_password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(plain_password).decode("utf-8")

    def check_password(self, plain_password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, plain_password)

    def set_backup_codes(self, plain_codes: list[str]) -> None:
        """Reemplaza los códigos de respaldo por una nueva lista (hasheados)."""
        hashes = [bcrypt.generate_password_hash(code).decode("utf-8") for code in plain_codes]
        self.backup_codes = json.dumps(hashes)

    def consume_backup_code(self, plain_code: str) -> bool:
        """
        Verifica un código de respaldo y, si es válido, lo elimina de la
        lista (uso único). Devuelve True si el código era válido.
        """
        if not self.backup_codes:
            return False

        hashes = json.loads(self.backup_codes)
        for stored_hash in hashes:
            if bcrypt.check_password_hash(stored_hash, plain_code):
                hashes.remove(stored_hash)
                self.backup_codes = json.dumps(hashes)
                return True
        return False

    def remaining_backup_codes(self) -> int:
        return len(json.loads(self.backup_codes)) if self.backup_codes else 0

    def __repr__(self):
        return f"<User {self.username}>"
