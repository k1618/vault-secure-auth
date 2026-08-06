"""
Migración manual: agrega las columnas de 2FA a una base de datos SQLite
que ya existía ANTES de este cambio.

¿Por qué es necesario esto?
----------------------------
`db.create_all()` (lo que corre run.py al arrancar) solo CREA tablas
que no existen — nunca modifica una tabla que ya existe. Si tu archivo
`instance/app.db` fue creado con una versión anterior del modelo User
(sin las columnas totp_secret, totp_enabled, totp_last_counter,
backup_codes), la app va a fallar con:

    sqlite3.OperationalError: no such column: users.totp_secret

en cuanto intentes registrar un usuario o iniciar sesión. `instance/`
está en .gitignore, así que un `git pull` nunca corrige esto por ti.

Uso
----
    python scripts/migrate_add_2fa_columns.py
    python scripts/migrate_add_2fa_columns.py --db instance/app.db

Es seguro correrlo más de una vez: cada columna se agrega solo si
todavía no existe, y tus usuarios/contraseñas existentes no se tocan.
"""
import argparse
import os
import sqlite3

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "app.db"
)

# (nombre_columna, definición SQL)
NEW_COLUMNS = [
    ("totp_secret", "VARCHAR(32)"),
    ("totp_enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ("totp_last_counter", "INTEGER"),
    ("backup_codes", "TEXT"),
]


def migrate(db_path: str) -> None:
    if not os.path.exists(db_path):
        print(f"No se encontró {db_path} — no hay nada que migrar "
              f"(se creará con el esquema nuevo la próxima vez que corras la app).")
        return

    conn = sqlite3.connect(db_path)
    try:
        existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}

        added = []
        for column_name, column_def in NEW_COLUMNS:
            if column_name in existing_columns:
                continue
            conn.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_def}")
            added.append(column_name)

        conn.commit()

        if added:
            print(f"Columnas agregadas a {db_path}: {', '.join(added)}")
        else:
            print(f"{db_path} ya tenía todas las columnas de 2FA — nada que hacer.")
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Ruta al archivo .db de SQLite (default: instance/app.db)",
    )
    args = parser.parse_args()
    migrate(args.db)
