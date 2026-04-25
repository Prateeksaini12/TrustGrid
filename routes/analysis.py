"""
routes/analysis.py
------------------
Read-only analysis and query routes.

Endpoints
---------
GET  /results         - per-node fraud summary
GET  /global_analysis - collaborative multi-node fraud decision
GET  /logs            - recent FE-encrypted activity for a node
GET  /nodes           - all registered nodes
GET  /outcomes        - past global fraud decisions
GET  /fe/public_key   - FE master public key (mpk)
POST /discontinue     - remove a node's data from the network
"""

import json

from flask import Blueprint, jsonify, request

from config import DATA_WINDOW_HOURS, FE_SCORE_WEIGHTS, FE_VECTOR_DIM, FRAUD_RATE_THRESHOLD, MIN_NODES_FOR_ANALYSIS
from database.schema import get_db
from utils.functional_encryption import export_public_key_payload, preview_ciphertext

analysis_bp = Blueprint("analysis", __name__)

_WINDOW = f"-{DATA_WINDOW_HOURS} hours"


@analysis_bp.route("/results", methods=["GET"])
def results():
    """Return per-node fraud summary."""
    node_id = request.args.get("node_id")
    conn = get_db()

    query = "SELECT company, node_id, COUNT(*) AS total, SUM(is_fraud) AS fraud_count FROM transactions"
    params = []
    if node_id:
        query += " WHERE node_id = ?"
        params.append(node_id)
    query += " GROUP BY node_id"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    data = [
        {
            "company": r["company"],
            "node_id": r["node_id"],
            "total": r["total"],
            "fraud_count": r["fraud_count"],
            "safe_count": r["total"] - r["fraud_count"],
            "fraud_rate": round(r["fraud_count"] / r["total"] * 100, 2) if r["total"] else 0,
        }
        for r in rows
    ]

    return jsonify({"success": True, "results": data})


@analysis_bp.route("/global_analysis", methods=["GET"])
def global_analysis():
    """Perform collaborative fraud detection across all nodes."""
    conn = get_db()

    nodes_with_data = conn.execute(
        """
        SELECT DISTINCT node_id FROM transactions
        WHERE created >= datetime('now', ?)
        """,
        (_WINDOW,),
    ).fetchall()

    node_count = len(nodes_with_data)
    if node_count < MIN_NODES_FOR_ANALYSIS:
        conn.close()
        return (
            jsonify(
                {
                    "success": False,
                    "node_count": node_count,
                    "message": (
                        f"Only {node_count} node(s) have submitted data in the last "
                        f"{DATA_WINDOW_HOURS} hours. Minimum {MIN_NODES_FOR_ANALYSIS} required."
                    ),
                }
            ),
            400,
        )

    row = conn.execute(
        """
        SELECT COUNT(*) AS total_records, SUM(is_fraud) AS total_fraud
        FROM transactions
        WHERE created >= datetime('now', ?)
        """,
        (_WINDOW,),
    ).fetchone()

    total = row["total_records"]
    fraud = row["total_fraud"] or 0
    rate = round(fraud / total * 100, 2) if total else 0
    decision = "FRAUD DETECTED" if rate > FRAUD_RATE_THRESHOLD else "SAFE"

    node_ids = [n["node_id"] for n in nodes_with_data]
    conn.execute(
        """
        INSERT INTO fraud_outcomes
               (participating_nodes, total_records, total_fraud, node_count, decision)
        VALUES (?, ?, ?, ?, ?)
        """,
        (json.dumps(node_ids), total, fraud, node_count, decision),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "success": True,
            "node_count": node_count,
            "total_records": total,
            "total_fraud": fraud,
            "total_safe": total - fraud,
            "fraud_rate": rate,
            "decision": decision,
            "message": f"Global analysis complete across {node_count} nodes",
        }
    )


@analysis_bp.route("/logs", methods=["GET"])
def logs():
    """Return the 20 most recent FE-encrypted transactions for a node."""
    node_id = request.args.get("node_id")
    if not node_id:
        return jsonify({"success": False, "message": "node_id is required"}), 400

    conn = get_db()
    rows = conn.execute(
        """
        SELECT company, fe_ciphertext, fraud_score, is_fraud, created
        FROM   transactions
        WHERE  node_id = ?
        ORDER  BY id DESC
        LIMIT  20
        """,
        (node_id,),
    ).fetchall()
    conn.close()

    logs_list = [
        {
            "company": r["company"],
            "hash_preview": preview_ciphertext(r["fe_ciphertext"]),
            "fraud_score": r["fraud_score"],
            "status": "FRAUD" if r["is_fraud"] else "SAFE",
            "timestamp": r["created"],
        }
        for r in rows
    ]

    return jsonify({"success": True, "logs": logs_list})


@analysis_bp.route("/nodes", methods=["GET"])
def nodes():
    """Return all registered nodes and whether each has submitted data."""
    conn = get_db()
    rows = conn.execute(
        """
        SELECT u.node_id,
               u.company,
               u.created,
               CASE WHEN t.node_id IS NOT NULL THEN 1 ELSE 0 END AS has_data
        FROM   users u
        LEFT JOIN (SELECT DISTINCT node_id FROM transactions) t
               ON u.node_id = t.node_id
        """
    ).fetchall()
    conn.close()

    return jsonify(
        {
            "success": True,
            "count": len(rows),
            "nodes": [
                {
                    "node_id": r["node_id"],
                    "company": r["company"],
                    "joined": r["created"],
                    "has_data": bool(r["has_data"]),
                }
                for r in rows
            ],
        }
    )


@analysis_bp.route("/outcomes", methods=["GET"])
def outcomes():
    """Return the 10 most recent global fraud decisions."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM fraud_outcomes ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()

    return jsonify(
        {
            "success": True,
            "outcomes": [
                {
                    "id": r["id"],
                    "nodes": json.loads(r["participating_nodes"]),
                    "total_records": r["total_records"],
                    "total_fraud": r["total_fraud"],
                    "node_count": r["node_count"],
                    "decision": r["decision"],
                    "timestamp": r["created"],
                }
                for r in rows
            ],
        }
    )


@analysis_bp.route("/fe/public_key", methods=["GET"])
def fe_public_key():
    """Expose the FE master public key (mpk) for external encryptors."""
    return jsonify(
        {
            "success": True,
            "scheme": "FeDamgard",
            "vector_dimension": FE_VECTOR_DIM,
            "function_weights": FE_SCORE_WEIGHTS,
            "public_key": export_public_key_payload(),
        }
    )


@analysis_bp.route("/discontinue", methods=["POST"])
def discontinue():
    """Remove a node's transactions from the network."""
    data = request.get_json()
    node_id = data.get("node_id")

    if not node_id:
        return jsonify({"success": False, "message": "node_id is required"}), 400

    conn = get_db()
    conn.execute("DELETE FROM transactions WHERE node_id = ?", (node_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Connection discontinued and data cleared."})
