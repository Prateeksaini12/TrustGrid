"""
app.py
------
TrustGrid - Federated Fraud Detection System

Entry point. Creates the Flask application, registers all blueprints,
initialises the database, and ensures FE keys exist.
"""

import os

from flask import Flask
from flask_cors import CORS

from config import DEBUG, PORT, UPLOAD_FOLDER
from database.schema import init_db
from routes.analysis import analysis_bp
from routes.auth import auth_bp
from routes.data import data_bp
from routes.report import report_bp
from utils.functional_encryption import ensure_fe_keys


def create_app() -> Flask:
    """Create and configure the Flask app instance."""
    app = Flask(__name__)
    CORS(app)

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    ensure_fe_keys()

    app.register_blueprint(auth_bp)
    app.register_blueprint(data_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(report_bp)

    return app


if __name__ == "__main__":
    init_db()
    ensure_fe_keys()

    print("\n" + "=" * 52)
    print("  TrustGrid Backend  -  http://localhost:5000")
    print("=" * 52 + "\n")

    app = create_app()
    app.run(debug=DEBUG, port=PORT)
