"""
config.py
---------
Central configuration for TrustGrid.
All environment-specific settings live here.
Never hardcode these values in route files.
"""

import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = (
    os.environ.get("TRUSTGRID_DB_PATH")
    or os.environ.get("TRUSTGRID_TEST_DB")
    or os.path.join(BASE_DIR, "trustgrid.db")
)
UPLOAD_FOLDER = os.environ.get("TRUSTGRID_UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads"))
FE_KEY_DIR = os.environ.get("TRUSTGRID_FE_KEY_DIR", os.path.join(BASE_DIR, "keys"))
FE_MASTER_KEY_PATH = os.path.join(FE_KEY_DIR, "fe_master_key.json")
FE_PUBLIC_KEY_PATH = os.path.join(FE_KEY_DIR, "fe_public_key.json")

# Fraud Detection Rules
FRAUD_AMOUNT_THRESHOLD = 10_000
FRAUD_HOUR_THRESHOLD = 5
FRAUD_RATE_THRESHOLD = 5.0

# Functional encryption
# Vector layout: [high_amount_flag, night_transaction_flag]
FE_VECTOR_DIM = 2
FE_SCORE_WEIGHTS = [1, 1]
FE_DECRYPT_BOUND = (0, 2)
FE_FRAUD_SCORE_THRESHOLD = 1

# Collaboration Rules
MIN_NODES_FOR_ANALYSIS = 2
DATA_WINDOW_HOURS = 24

# Ollama / LLM
OLLAMA_MODEL = "gemma4:e4b"
OLLAMA_MAX_TOKENS = 150
OLLAMA_TEMPERATURE = 0.3

# Flask
DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
PORT = int(os.environ.get("PORT", 5000))
