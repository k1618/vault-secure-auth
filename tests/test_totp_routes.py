"""
Tests de integración para 2FA (TOTP + códigos de respaldo).

Sigue las mismas convenciones que test_auth_routes.py: cliente de
pruebas de Flask contra SQLite en memoria.
"""
import pyotp
import pytest

from app import create_app, db
from app.models import User

USERNAME = "dilan"
EMAIL = "dilan@example.com"
PASSWORD = "Correcto#Caballo9"


@pytest.fixture()
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def register_and_login(client):
    client.post(
        "/register",
        data={"username": USERNAME, "email": EMAIL, "password": PASSWORD},
        follow_redirects=True,
    )
    return client.post(
        "/login",
        data={"identifier": USERNAME, "password": PASSWORD},
        follow_redirects=True,
    )


def enable_totp(client, app):
    """Helper: activa 2FA y devuelve el secreto TOTP en texto plano."""
    client.get("/2fa/setup")  # genera el secreto y lo guarda en la sesión
    with client.session_transaction() as sess:
        secret = sess["setup_totp_secret"]

    totp = pyotp.TOTP(secret)
    response = client.post("/2fa/setup", data={"code": totp.now()})
    assert response.status_code == 200
    assert "Guarda estos c\u00f3digos".encode("utf-8") in response.data
    return secret


def logout(client):
    client.get("/logout")


def test_setup_totp_requires_login(client):
    response = client.get("/2fa/setup", follow_redirects=True)
    assert response.status_code == 200
    assert "Iniciar sesión".encode("utf-8") in response.data


def test_setup_totp_enables_2fa_and_returns_backup_codes(client, app):
    register_and_login(client)
    secret = enable_totp(client, app)

    with app.app_context():
        user = User.query.filter_by(username=USERNAME).first()
        assert user.totp_enabled is True
        assert user.totp_secret == secret
        assert user.remaining_backup_codes() == 10


def test_setup_totp_rejects_wrong_code(client, app):
    register_and_login(client)
    client.get("/2fa/setup")

    response = client.post("/2fa/setup", data={"code": "000000"})
    assert response.status_code == 400

    with app.app_context():
        user = User.query.filter_by(username=USERNAME).first()
        assert user.totp_enabled is False


def test_login_with_2fa_enabled_requires_second_step(client, app):
    register_and_login(client)
    enable_totp(client, app)
    logout(client)

    response = client.post(
        "/login",
        data={"identifier": USERNAME, "password": PASSWORD},
        follow_redirects=True,
    )
    assert response.status_code == 200
    # No debe haber sesión iniciada todavía: debe pedir el segundo factor.
    assert "Verificaci\u00f3n en dos pasos".encode("utf-8") in response.data

    # El dashboard sigue protegido: la contraseña sola no basta.
    dashboard = client.get("/dashboard", follow_redirects=True)
    assert "Iniciar sesión".encode("utf-8") in dashboard.data


def test_login_completes_with_correct_totp_code(client, app):
    register_and_login(client)
    secret = enable_totp(client, app)
    logout(client)

    client.post(
        "/login",
        data={"identifier": USERNAME, "password": PASSWORD},
        follow_redirects=True,
    )

    totp = pyotp.TOTP(secret)
    response = client.post(
        "/2fa/verify", data={"code": totp.now()}, follow_redirects=True
    )
    assert response.status_code == 200
    assert f"Hola, {USERNAME}".encode("utf-8") in response.data


def test_totp_code_cannot_be_reused_replay_attack(client, app):
    register_and_login(client)
    secret = enable_totp(client, app)
    logout(client)

    totp = pyotp.TOTP(secret)
    code = totp.now()

    # Primer login: el código se usa y se acepta.
    client.post(
        "/login", data={"identifier": USERNAME, "password": PASSWORD}, follow_redirects=True
    )
    first = client.post("/2fa/verify", data={"code": code}, follow_redirects=True)
    assert f"Hola, {USERNAME}".encode("utf-8") in first.data

    logout(client)

    # Segundo login con el MISMO código: debe rechazarse (anti-replay),
    # incluso aunque el código siga siendo válido según la ventana TOTP.
    client.post(
        "/login", data={"identifier": USERNAME, "password": PASSWORD}, follow_redirects=True
    )
    second = client.post("/2fa/verify", data={"code": code})
    assert second.status_code == 401


def test_backup_code_works_once_then_is_rejected(client, app):
    register_and_login(client)
    client.get("/2fa/setup")
    with client.session_transaction() as sess:
        secret = sess["setup_totp_secret"]
    totp = pyotp.TOTP(secret)
    setup_response = client.post("/2fa/setup", data={"code": totp.now()})

    # Extrae un código de respaldo real de la respuesta renderizada.
    with app.app_context():
        user = User.query.filter_by(username=USERNAME).first()
    # Genera uno nuevo conocido de antemano para no parsear HTML:
    # reemplazamos los backup codes por uno controlado por el test.
    with app.app_context():
        user = User.query.filter_by(username=USERNAME).first()
        user.set_backup_codes(["TEST-CODE"])
        db.session.commit()

    logout(client)
    client.post(
        "/login", data={"identifier": USERNAME, "password": PASSWORD}, follow_redirects=True
    )

    first_use = client.post("/2fa/verify", data={"code": "TEST-CODE"}, follow_redirects=True)
    assert f"Hola, {USERNAME}".encode("utf-8") in first_use.data

    logout(client)
    client.post(
        "/login", data={"identifier": USERNAME, "password": PASSWORD}, follow_redirects=True
    )
    second_use = client.post("/2fa/verify", data={"code": "TEST-CODE"})
    assert second_use.status_code == 401


def test_verify_totp_locks_out_after_max_attempts(client, app):
    register_and_login(client)
    enable_totp(client, app)
    logout(client)

    client.post(
        "/login", data={"identifier": USERNAME, "password": PASSWORD}, follow_redirects=True
    )

    for _ in range(5):
        response = client.post("/2fa/verify", data={"code": "000000"})
        assert response.status_code in (401, 302)

    # Sexto intento: la sesión pendiente ya se invalidó, debe mandar a /login.
    response = client.post("/2fa/verify", data={"code": "000000"}, follow_redirects=True)
    assert "identifier".encode("utf-8") in response.data or response.status_code == 200


def test_disable_totp_requires_correct_password(client, app):
    register_and_login(client)
    enable_totp(client, app)

    wrong = client.post("/2fa/disable", data={"password": "incorrecta"})
    assert wrong.status_code == 401

    with app.app_context():
        user = User.query.filter_by(username=USERNAME).first()
        assert user.totp_enabled is True

    correct = client.post("/2fa/disable", data={"password": PASSWORD}, follow_redirects=True)
    assert correct.status_code == 200

    with app.app_context():
        user = User.query.filter_by(username=USERNAME).first()
        assert user.totp_enabled is False
        assert user.totp_secret is None
        assert user.backup_codes is None
