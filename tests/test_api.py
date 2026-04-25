"""
tests/test_api.py
-----------------
Integration tests for the Flask API.
Uses a temp SQLite database and temp FE key directory.
"""

import os
import sys
import tempfile
from io import BytesIO

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["TRUSTGRID_TEST_DB"] = tmp_db.name
os.environ["TRUSTGRID_FE_KEY_DIR"] = tempfile.mkdtemp()
os.environ["TRUSTGRID_UPLOAD_FOLDER"] = tempfile.mkdtemp()

from app import create_app
from database.schema import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestRegister:
    def test_register_success(self, client):
        res = client.post("/register", json={"node_id": "test_node", "key": "secret", "company": "Test Bank"})
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_register_duplicate_node_id(self, client):
        res = client.post("/register", json={"node_id": "test_node", "key": "secret2", "company": "Another Bank"})
        assert res.status_code == 409

    def test_register_missing_fields(self, client):
        res = client.post("/register", json={"node_id": "x"})
        assert res.status_code == 400


class TestLogin:
    def test_login_success(self, client):
        res = client.post("/login", json={"node_id": "test_node", "key": "secret"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["company"] == "Test Bank"

    def test_login_wrong_key(self, client):
        res = client.post("/login", json={"node_id": "test_node", "key": "wrongkey"})
        assert res.status_code == 401

    def test_login_unknown_node(self, client):
        res = client.post("/login", json={"node_id": "ghost", "key": "x"})
        assert res.status_code == 404


class TestResetKey:
    def test_reset_key_success(self, client):
        res = client.post(
            "/reset_key",
            json={"node_id": "test_node", "company": "Test Bank", "new_key": "newpassword"},
        )
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_login_with_new_key(self, client):
        res = client.post("/login", json={"node_id": "test_node", "key": "newpassword"})
        assert res.status_code == 200

    def test_reset_key_wrong_company(self, client):
        res = client.post(
            "/reset_key",
            json={"node_id": "test_node", "company": "Wrong Bank", "new_key": "hacked"},
        )
        assert res.status_code == 401


class TestNodes:
    def test_nodes_returns_list(self, client):
        res = client.get("/nodes")
        assert res.status_code == 200
        data = res.get_json()
        assert "nodes" in data
        assert isinstance(data["nodes"], list)


class TestResults:
    def test_results_empty(self, client):
        res = client.get("/results")
        assert res.status_code == 200
        assert res.get_json()["success"] is True


class TestGlobalAnalysis:
    def test_global_fails_with_no_data(self, client):
        res = client.get("/global_analysis")
        assert res.status_code == 400
        assert res.get_json()["success"] is False


class TestFunctionalEncryptionAPI:
    def test_public_key_is_available(self, client):
        res = client.get("/fe/public_key")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["scheme"] == "FeDamgard"
        assert data["public_key"]["n"] == 2

    def test_upload_and_analyze_store_fe_ciphertext(self, client):
        csv_payload = b"amount,time\n15000,02:30\n500,14:00\n"
        upload = client.post(
            "/upload",
            data={"node_id": "test_node", "file": (BytesIO(csv_payload), "sample.csv")},
            content_type="multipart/form-data",
        )
        assert upload.status_code == 200

        analyze = client.post("/analyze", json={"node_id": "test_node"})
        assert analyze.status_code == 200
        data = analyze.get_json()
        assert data["success"] is True
        assert data["fraud_count"] == 1

        logs = client.get("/logs?node_id=test_node")
        assert logs.status_code == 200
        payload = logs.get_json()
        assert payload["logs"]
        assert payload["logs"][0]["hash_preview"].endswith("...")
        assert payload["logs"][0]["fraud_score"] in {0, 1, 2}


class TestClearData:
    def test_clear_data(self, client):
        res = client.post("/clear_data", json={"node_id": "test_node"})
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_clear_data_missing_node_id(self, client):
        res = client.post("/clear_data", json={})
        assert res.status_code == 400
