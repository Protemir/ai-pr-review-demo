"""Мини-реализация RealWorld (Conduit) API для демо-стенда ИИ-ревью."""
from flask import Flask

from .db import close_db, init_db


def create_app(db_path: str = ":memory:") -> Flask:
    app = Flask(__name__)
    app.config["DATABASE"] = db_path
    app.teardown_appcontext(close_db)

    from .articles import bp as articles_bp

    app.register_blueprint(articles_bp)
    with app.app_context():
        init_db()
    return app
