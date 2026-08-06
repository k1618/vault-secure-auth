import time
from datetime import timedelta

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func

from app import db
from app.models import User, utcnow_naive
from app.security import (
    validate_password_strength,
    check_password_pwned,
    HIBPServiceError,
    generate_totp_secret,
    get_totp_uri,
    generate_qr_code_data_uri,
    verify_totp_code,
    generate_backup_codes,
    TOTP_INTERVAL_SECONDS,
)

auth_bp = Blueprint("auth", __name__)
main_bp = Blueprint("main", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
MAX_2FA_ATTEMPTS = 5


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        errors = []
        if not username or not email or not password:
            errors.append("Todos los campos son obligatorios.")
        if User.query.filter(func.lower(User.username) == username.lower()).first():
            errors.append("Ese nombre de usuario ya está en uso.")
        if User.query.filter(func.lower(User.email) == email).first():
            errors.append("Ese correo ya está registrado.")

        strength = validate_password_strength(password)
        if not strength.is_acceptable:
            errors.append("La contraseña no cumple los requisitos mínimos de seguridad.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html"), 400

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Cuenta creada correctamente. Ya puedes iniciar sesión.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter(
            (func.lower(User.username) == identifier) | (func.lower(User.email) == identifier)
        ).first()

        if user and user.locked_until and user.locked_until > utcnow_naive():
            flash("Cuenta bloqueada temporalmente por intentos fallidos. Intenta más tarde.", "error")
            return render_template("login.html"), 429

        if user and user.check_password(password):
            user.failed_login_attempts = 0
            user.locked_until = None

            if user.totp_enabled:
                # No se llama login_user() todavía: la sesión queda
                # "pendiente" hasta que se verifique el segundo factor.
                db.session.commit()
                session["pending_2fa_user_id"] = user.id
                session["pending_2fa_attempts"] = 0
                return redirect(url_for("auth.verify_totp"))

            user.last_login_at = utcnow_naive()
            db.session.commit()
            login_user(user)
            return redirect(url_for("main.dashboard"))

        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = utcnow_naive() + timedelta(minutes=LOCKOUT_MINUTES)
            db.session.commit()

        # Mensaje genérico a propósito: no revelar si falló el usuario o la contraseña.
        flash("Usuario o contraseña incorrectos.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("main.index"))


@auth_bp.route("/2fa/verify", methods=["GET", "POST"])
def verify_totp():
    """
    Segundo paso del login cuando el usuario tiene 2FA activado.
    Requiere una sesión "pendiente" creada por /login tras validar la
    contraseña correctamente; no es accesible sin haber pasado por ahí.
    """
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled:
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_attempts", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip().upper().replace(" ", "")
        current_counter = int(time.time() // TOTP_INTERVAL_SECONDS)

        valid = False
        if verify_totp_code(user.totp_secret, code):
            # Bloquea reutilizar el mismo código dos veces (replay).
            if user.totp_last_counter is None or current_counter > user.totp_last_counter:
                user.totp_last_counter = current_counter
                valid = True
        elif user.consume_backup_code(code):
            valid = True

        if valid:
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_attempts", None)
            user.last_login_at = utcnow_naive()
            db.session.commit()
            login_user(user)
            flash("Sesión iniciada correctamente.", "success")
            return redirect(url_for("main.dashboard"))

        attempts = session.get("pending_2fa_attempts", 0) + 1
        session["pending_2fa_attempts"] = attempts

        if attempts >= MAX_2FA_ATTEMPTS:
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_attempts", None)
            flash("Demasiados intentos fallidos. Inicia sesión de nuevo.", "error")
            return redirect(url_for("auth.login"))

        flash("Código incorrecto.", "error")
        return render_template("verify_2fa.html", attempts_left=MAX_2FA_ATTEMPTS - attempts), 401

    return render_template("verify_2fa.html", attempts_left=MAX_2FA_ATTEMPTS)


@auth_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_totp():
    if current_user.totp_enabled:
        flash("La verificación en dos pasos ya está activada en tu cuenta.", "info")
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        secret = session.get("setup_totp_secret")
        code = request.form.get("code", "").strip()

        if not secret:
            flash("La configuración expiró. Escanea el código QR de nuevo.", "error")
            return redirect(url_for("auth.setup_totp"))

        if not verify_totp_code(secret, code):
            flash("Código incorrecto. Revisa la hora de tu dispositivo e inténtalo de nuevo.", "error")
            uri = get_totp_uri(secret, current_user.email)
            qr_data_uri = generate_qr_code_data_uri(uri)
            return render_template("setup_2fa.html", secret=secret, qr_data_uri=qr_data_uri), 400

        backup_codes = generate_backup_codes()
        current_user.totp_secret = secret
        current_user.totp_enabled = True
        # OJO: no se toca totp_last_counter aquí. Este código solo
        # confirma la configuración, no es un "login"; si lo marcáramos
        # como usado, un usuario que active 2FA y luego inicie sesión
        # de inmediato (dentro de los mismos 30s) sería rechazado por
        # el anti-replay con un código perfectamente válido — un bug
        # real que se encontró y corrigió durante las pruebas de este
        # cambio (ver test_login_completes_with_correct_totp_code).
        current_user.set_backup_codes(backup_codes)
        db.session.commit()
        session.pop("setup_totp_secret", None)

        return render_template("backup_codes.html", backup_codes=backup_codes)

    # GET: reutiliza el secreto ya generado en esta sesión de configuración
    # (si el usuario recarga la página) en vez de invalidar el QR que ya
    # pudo haber escaneado.
    secret = session.get("setup_totp_secret")
    if not secret:
        secret = generate_totp_secret()
        session["setup_totp_secret"] = secret

    uri = get_totp_uri(secret, current_user.email)
    qr_data_uri = generate_qr_code_data_uri(uri)
    return render_template("setup_2fa.html", secret=secret, qr_data_uri=qr_data_uri)


@auth_bp.route("/2fa/disable", methods=["GET", "POST"])
@login_required
def disable_totp():
    if not current_user.totp_enabled:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if not current_user.check_password(password):
            flash("Contraseña incorrecta.", "error")
            return render_template("disable_2fa.html"), 401

        current_user.totp_enabled = False
        current_user.totp_secret = None
        current_user.totp_last_counter = None
        current_user.backup_codes = None
        db.session.commit()
        flash("Verificación en dos pasos desactivada.", "info")
        return redirect(url_for("main.dashboard"))

    return render_template("disable_2fa.html")


@api_bp.route("/check-password", methods=["POST"])
def check_password():
    """
    Endpoint usado por el JS del formulario de registro para dar
    retroalimentación en vivo mientras el usuario escribe su contraseña,
    sin necesidad de enviar el formulario completo.
    """
    password = request.json.get("password", "") if request.is_json else ""
    if not password:
        return jsonify({"error": "password requerida"}), 400

    strength = validate_password_strength(password)

    breach_count = None
    breach_check_available = True
    try:
        breach_count = check_password_pwned(password)
    except HIBPServiceError:
        breach_check_available = False

    return jsonify({
        **strength.to_dict(),
        "breach_count": breach_count,
        "breach_check_available": breach_check_available,
    })
