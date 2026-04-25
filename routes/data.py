"""
routes/data.py
--------------
Data ingestion routes: upload CSV, analyze, clear.

Endpoints
---------
POST /upload      - upload a CSV dataset for a node
POST /analyze     - run fraud detection on uploaded CSV
POST /clear_data  - delete a node's transaction data
"""

import os

import pandas as pd
from flask import Blueprint, jsonify, request

from config import UPLOAD_FOLDER
from database.schema import get_db
from utils.functional_encryption import (
    decrypt_inner_product,
    derive_function_key,
    encode_transaction_vector,
    encrypt_vector,
    is_fraud_score,
    load_master_key,
    load_public_key,
    serialize_ciphertext,
)
from utils.fraud import detect_amount_column, detect_time_column

data_bp = Blueprint("data", __name__)


@data_bp.route("/upload", methods=["POST"])
def upload():
    """
    Upload a CSV file for a registered node.
    Deletes any previously uploaded file for this node before saving the new one,
    so stale files can never be accidentally re-analyzed.

    Form data:
        file    (file):  CSV file to upload.
        node_id (str):   Registered node ID.
    """
    node_id = request.form.get("node_id", "").strip()
    if not node_id:
        return jsonify({"success": False, "message": "node_id is required"}), 400

    if "file" not in request.files or request.files["file"].filename == "":
        return jsonify({"success": False, "message": "No file uploaded"}), 400

    upload_file = request.files["file"]

    if not upload_file.filename.lower().endswith(".csv"):
        return jsonify({"success": False, "message": "Only CSV files are accepted"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE node_id = ?", (node_id,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "message": "Node not found. Please log in first."}), 404

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    for old_file in os.listdir(UPLOAD_FOLDER):
        if old_file.startswith(node_id + "_"):
            os.remove(os.path.join(UPLOAD_FOLDER, old_file))

    filepath = os.path.join(UPLOAD_FOLDER, f"{node_id}_{upload_file.filename}")
    upload_file.save(filepath)

    try:
        df = pd.read_csv(filepath)
        df.columns = [col.strip().lower().replace(" ", "_") for col in df.columns]
        cols = list(df.columns)

        amount_col = detect_amount_column(cols)
        time_col = detect_time_column(cols)

        if amount_col is None or time_col is None:
            os.remove(filepath)
            missing = []
            if amount_col is None:
                missing.append("'amount'")
            if time_col is None:
                missing.append("'time'")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": (
                            f"CSV is missing required columns: {', '.join(missing)}. "
                            "Your CSV needs columns named 'amount' and 'time'."
                        ),
                    }
                ),
                400,
            )

    except Exception as exc:
        os.remove(filepath)
        return jsonify({"success": False, "message": f"Could not read CSV: {exc}"}), 400

    return jsonify(
        {
            "success": True,
            "message": f"File uploaded and validated for {user['company']}. Call /analyze to process it.",
            "node_id": node_id,
            "company": user["company"],
            "rows": len(df),
            "columns": cols,
        }
    )


@data_bp.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyze the most recently uploaded CSV for a node.
    Transaction features are encrypted with the FE public key (mpk), and only
    the allowed fraud score is recovered via a function key derived from msk.

    Body (JSON):
        node_id (str): Node to analyze.
    """
    data = request.get_json()
    node_id = data.get("node_id", "").strip()

    if not node_id:
        return jsonify({"success": False, "message": "node_id is required"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE node_id = ?", (node_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "Node not found"}), 404

    company = user["company"]

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    uploaded = sorted([name for name in os.listdir(UPLOAD_FOLDER) if name.startswith(node_id + "_")])
    if not uploaded:
        conn.close()
        return (
            jsonify(
                {
                    "success": False,
                    "message": "No uploaded file found for this node. Please upload a CSV first.",
                }
            ),
            404,
        )

    filepath = os.path.join(UPLOAD_FOLDER, uploaded[-1])

    try:
        df = pd.read_csv(filepath)
    except Exception as exc:
        conn.close()
        return jsonify({"success": False, "message": f"Could not read CSV: {exc}"}), 500

    df.columns = [col.strip().lower().replace(" ", "_") for col in df.columns]
    cols = list(df.columns)

    amount_col = detect_amount_column(cols)
    time_col = detect_time_column(cols)

    if amount_col is None:
        conn.close()
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"CSV is missing an amount column. Found: {cols}. Rename your column to 'amount'.",
                }
            ),
            400,
        )

    if time_col is None:
        conn.close()
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"CSV is missing a time column. Found: {cols}. Rename your column to 'time'.",
                }
            ),
            400,
        )

    conn.execute("DELETE FROM transactions WHERE node_id = ?", (node_id,))

    public_key = load_public_key()
    master_key = load_master_key()
    function_key = derive_function_key(master_key=master_key)

    total = len(df)
    n_fraud = 0
    for _, row in df.iterrows():
        vector = encode_transaction_vector(row[amount_col], row[time_col])
        ciphertext = encrypt_vector(vector, public_key)
        score = decrypt_inner_product(ciphertext, function_key, public_key)
        fraud = is_fraud_score(score)
        n_fraud += int(fraud)

        conn.execute(
            """
            INSERT INTO transactions (company, node_id, fe_ciphertext, fraud_score, is_fraud)
            VALUES (?, ?, ?, ?, ?)
            """,
            (company, node_id, serialize_ciphertext(ciphertext), int(score), int(fraud)),
        )

    conn.commit()
    conn.close()

    fraud_rate = round(n_fraud / total * 100, 2) if total else 0
    return jsonify(
        {
            "success": True,
            "company": company,
            "node_id": node_id,
            "total": total,
            "fraud_count": n_fraud,
            "safe_count": total - n_fraud,
            "fraud_rate": fraud_rate,
            "message": f"Analysis complete for {company}",
        }
    )


@data_bp.route("/clear_data", methods=["POST"])
def clear_data():
    """
    Delete all transaction data and uploaded files for a node.
    Used to clear stale data before a fresh analysis.
    """
    data = request.get_json()
    node_id = data.get("node_id", "").strip()

    if not node_id:
        return jsonify({"success": False, "message": "node_id is required"}), 400

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    for old_file in os.listdir(UPLOAD_FOLDER):
        if old_file.startswith(node_id + "_"):
            os.remove(os.path.join(UPLOAD_FOLDER, old_file))

    conn = get_db()
    conn.execute("DELETE FROM transactions WHERE node_id = ?", (node_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Data and uploaded files cleared successfully"})
