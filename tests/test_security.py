"""
Tests del módulo app.security.

Las pruebas de validate_password_strength son puras (sin red).
Las de check_password_pwned dependen de la API pública de HIBP: si el
entorno donde corren los tests no tiene salida a esa API (sandbox, CI
con egress restringido, etc.), el test se salta en lugar de fallar,
para no confundir "el código está mal" con "esta red no puede llegar
al servicio externo".
"""
import pytest

from app.security import validate_password_strength, check_password_pwned, HIBPServiceError


class TestValidatePasswordStrength:
    def test_empty_password_is_rejected(self):
        result = validate_password_strength("")
        assert result.is_acceptable is False
        assert result.score == 0

    def test_short_password_is_rejected_even_if_complex(self):
        result = validate_password_strength("Ab1!")
        assert result.checks["length"] is False
        assert result.is_acceptable is False

    def test_only_lowercase_long_password_is_rejected(self):
        result = validate_password_strength("abcdefghijk")
        assert result.checks["length"] is True
        assert result.is_acceptable is False  # le faltan mayúsculas, dígitos y símbolos

    def test_strong_password_is_accepted(self):
        result = validate_password_strength("Correcto#Caballo9Grapa")
        assert result.checks == {
            "length": True,
            "uppercase": True,
            "lowercase": True,
            "digit": True,
            "special": True,
        }
        assert result.score == 5
        assert result.is_acceptable is True

    def test_acceptable_with_three_of_four_extra_rules(self):
        # Cumple longitud + 3 de las 4 reglas restantes (falta símbolo) -> aceptable
        result = validate_password_strength("Password123")
        assert result.is_acceptable is True


class TestCheckPasswordPwned:
    def test_known_leaked_password_is_flagged(self):
        # "password" es, por mucho, una de las contraseñas más filtradas del mundo.
        try:
            count = check_password_pwned("password")
        except HIBPServiceError:
            pytest.skip("API de HIBP no alcanzable desde este entorno")
        assert count > 0

    def test_random_strong_password_is_not_flagged(self):
        try:
            count = check_password_pwned("Xk9$mQ2!vLp7#Rz4wT8n")
        except HIBPServiceError:
            pytest.skip("API de HIBP no alcanzable desde este entorno")
        assert count == 0
