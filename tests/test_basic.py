# tests/test_basic.py
from fastapi.testclient import TestClient

from src.main import app

client = TestClient(app)


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_docs_available():
    """Test API docs are available."""
    response = client.get("/docs")
    assert response.status_code == 200


def test_openapi_schema():
    """Test OpenAPI schema is valid."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "openapi" in response.json()
