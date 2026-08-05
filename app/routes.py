from datetime import timedelta

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func

from app import db
from app.models import User, utcnow_naive
from app.security import validate_password_strength, check_password_pwned, HIBPServiceError

auth_bp = Blueprint("auth", __name__)
main_bp = Blueprint("main", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


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
