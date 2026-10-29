"""F2 offline knowledge base module (Python 3.7 compatible)."""
from .api import api
from .db import initialize_database


def register_module(app):
    """Attach F2 storage and routes to the shared backend application."""
    initialize_database(app.config["F2_DB_PATH"])
    app.register_blueprint(api, url_prefix="/api/f2")
