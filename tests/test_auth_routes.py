"""
Tests de integración: usan el cliente de pruebas de Flask contra una
base de datos SQLite en memoria (config "testing"), así que no tocan
la base de datos real y cada test corre con datos limpios.
"""
import pytest

from app import create_app, db


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


def register(client, username="dilan", email="dilan@example.com", password="Correcto#Caballo9"):
    return client.post(
        "/register",
        data={"username": username, "email": email, "password": password},
        follow_redirects=True,
    )


def test_register_creates_user(client):
    response = register(client)
    assert response.status_code == 200
    assert "Ya puedes iniciar sesión".encode("utf-8") in response.data


def test_register_rejects_weak_password(client):
    response = register(client, password="123")
    assert response.status_code == 400


def test_register_rejects_duplicate_username(client):
    register(client)
    response = register(client, email="otro@example.com")
    assert response.status_code == 400


def test_login_with_correct_credentials_reaches_dashboard(client):
    register(client)
    response = client.post(
        "/login",
        data={"identifier": "dilan", "password": "Correcto#Caballo9"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Hola, dilan".encode("utf-8") in response.data


def test_login_is_case_insensitive_for_username(client):
    register(client, username="Dilan")
    response = client.post(
        "/login",
        data={"identifier": "dilan", "password": "Correcto#Caballo9"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Hola, Dilan".encode("utf-8") in response.data


def test_login_with_wrong_password_is_rejected(client):
    register(client)
    response = client.post(
        "/login",
        data={"identifier": "dilan", "password": "incorrecta"},
    )
    assert response.status_code == 401


def test_dashboard_requires_login(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert "Iniciar sesión".encode("utf-8") in response.data


def test_account_locks_after_max_failed_attempts_without_crashing(client):
    register(client)
    for _ in range(5):
        response = client.post("/login", data={"identifier": "dilan", "password": "mala"})
        assert response.status_code == 401

    # Este 6to intento es el que antes tronaba con un 500 por comparar
    # un datetime "aware" contra uno "naive" (bug real encontrado en
    # pruebas manuales) — ahora debe responder 429, sin importar si la
    # contraseña es correcta o no, porque la cuenta ya está bloqueada.
    locked_response = client.post(
        "/login", data={"identifier": "dilan", "password": "Correcto#Caballo9"}
    )
    assert locked_response.status_code == 429
