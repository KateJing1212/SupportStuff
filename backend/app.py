"""Composition root for the complete local backend application."""
import os

from flask import Flask, send_from_directory

try:
    from .f2 import register_module as register_f2
except ImportError:
    # Also support the documented `python backend/run.py` invocation, where
    # backend/ is the script import root rather than a package.
    from f2 import register_module as register_f2


BACKEND_ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_ROOT)

# Register each backend module here as it is implemented. Modules expose a
# register_module(app) function and add their own services/blueprints.
MODULE_REGISTRARS = (
    register_f2,
)


def create_app(config=None):
    """Create the full application and register all available backend modules."""
    app = Flask(__name__)
    app.config.update(
        F2_DB_PATH=os.environ.get(
            "F2_DB_PATH", os.path.join(BACKEND_ROOT, "data", "f2.sqlite3")
        ),
        MAX_CONTENT_LENGTH=512 * 1024 * 1024,
    )
    if config:
        app.config.update(config)

    for register_module in MODULE_REGISTRARS:
        register_module(app)

    prototype_dir = os.path.join(PROJECT_ROOT, "prototype")
    if os.path.isfile(os.path.join(prototype_dir, "index.html")):
        app.add_url_rule(
            "/", "prototype_index",
            lambda: send_from_directory(prototype_dir, "index.html"),
        )
        app.add_url_rule(
            "/prototype/<path:filename>", "prototype_asset",
            lambda filename: send_from_directory(prototype_dir, filename),
        )
    return app
