"""
Lógica de seguridad de contraseñas, separada de las rutas para que sea
fácil de probar de forma aislada (ver tests/test_security.py).

Contiene dos verificaciones independientes:

1. validate_password_strength():
   Reglas locales (longitud, mayúsculas, minúsculas, números, símbolos).
   Es la evolución del validador de regex del proyecto original.

2. check_password_pwned():
   Consulta la API pública de "Have I Been Pwned" usando el modelo
   k-Anonymity: la contraseña se hashea con SHA-1 localmente y solo se
   envían los primeros 5 caracteres del hash a la API. HIBP responde con
   todos los sufijos que comparten ese prefijo, y la comparación final
   del sufijo completo se hace en nuestro propio código. Así la
   contraseña real (ni siquiera su hash completo) nunca sale de la
   máquina del usuario.
   Referencia: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import base64
import hashlib
import io
import re
import secrets
from dataclasses import dataclass, field

import pyotp
import qrcode
import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
HIBP_TIMEOUT_SECONDS = 4

MIN_LENGTH = 8


@dataclass
class PasswordStrengthResult:
    score: int  # 0-5
    checks: dict = field(default_factory=dict)
    is_acceptable: bool = False

    def to_dict(self):
        return {
            "score": self.score,
            "checks": self.checks,
            "is_acceptable": self.is_acceptable,
        }


def validate_password_strength(password: str) -> PasswordStrengthResult:
    """Evalúa una contraseña contra reglas locales de complejidad."""
    checks = {
        "length": len(password) >= MIN_LENGTH,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    score = sum(checks.values())
    # Se exige longitud mínima siempre + al menos 3 de las otras 4 reglas.
    is_acceptable = checks["length"] and sum(
        v for k, v in checks.items() if k != "length"
    ) >= 3

    return PasswordStrengthResult(score=score, checks=checks, is_acceptable=is_acceptable)


class HIBPServiceError(Exception):
    """La API de HIBP no respondió correctamente (no confundir con 'sí filtrada')."""


def check_password_pwned(password: str) -> int:
    """
    Devuelve cuántas veces ha aparecido esta contraseña en brechas conocidas.

    Retorna 0 si no aparece. Lanza HIBPServiceError si el servicio no
    pudo consultarse (para que quien llame decida si bloquea el registro
    o simplemente lo deja pasar con una advertencia).
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(
            f"{HIBP_API_URL}{prefix}",
            headers={"Add-Padding": "true"},
            timeout=HIBP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HIBPServiceError(str(exc)) from exc

    for line in response.text.splitlines():
        candidate_suffix, count = line.split(":")
        if candidate_suffix == suffix:
            return int(count)
    return 0


# ---------------------------------------------------------------------
# 2FA — TOTP (RFC 6238) vía pyotp, compatible con Google Authenticator,
# Authy, 1Password, etc. El secreto se genera localmente y nunca sale
# de la app (el QR se genera como imagen en el propio servidor, no se
# manda a un servicio externo de generación de QR).
# ---------------------------------------------------------------------

TOTP_ISSUER_NAME = "Vault"
BACKUP_CODE_COUNT = 10
TOTP_INTERVAL_SECONDS = 30  # default de pyotp.totp.TOTP; explícito para el cálculo anti-replay


def generate_totp_secret() -> str:
    """Genera un secreto base32 aleatorio nuevo para un usuario."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, account_name: str) -> str:
    """URI otpauth:// estándar que las apps autenticadoras leen del QR."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_name, issuer_name=TOTP_ISSUER_NAME
    )


def generate_qr_code_data_uri(uri: str) -> str:
    """
    Genera el QR como PNG en memoria y lo devuelve como data URI
    (base64), para incrustarlo directo en <img src="..."> sin guardar
    el archivo en disco ni depender de un servicio externo.
    """
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifica un código de 6 dígitos contra el secreto, con una ventana
    de tolerancia de ±1 intervalo (30s) para compensar desfases de
    reloj entre el teléfono del usuario y el servidor.
    """
    if not code or not code.isdigit():
        return False
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """
    Genera códigos de un solo uso, formato "XXXX-XXXX" (8 caracteres
    alfanuméricos en mayúsculas), usando `secrets` (criptográficamente
    seguro, a diferencia de `random`).
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin caracteres ambiguos (0/O, 1/I/L)
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes
