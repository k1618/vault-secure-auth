"""
Punto de entrada de la aplicación.

Uso:
    python run.py
"""
import os
from app import create_app, db

app = create_app(os.getenv("FLASK_ENV", "development"))


@app.shell_context_processor
def make_shell_context():
    """Permite usar `flask shell` con el modelo User ya importado."""
    from app.models import User
    return {"db": db, "User": User}


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=os.getenv("FLASK_DEBUG", "1") == "1")
