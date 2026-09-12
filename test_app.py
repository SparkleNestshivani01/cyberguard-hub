import pytest
from app import app, evaluate_password, calculate_entropy

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# ==========================================
# 1. UNIT TESTS: PASSWORD ENGINE
# ==========================================
def test_calculate_entropy():
    # Empty password should have 0 entropy
    assert calculate_entropy("") == 0.0
    # Stronger passwords should have higher entropy
    assert calculate_entropy("password123") < calculate_entropy("P@ssw0rd123!#$")

def test_evaluate_password_weak():
    res = evaluate_password("123456")
    assert res["status"] == "Very Weak"
    assert "This is an extremely common blacklisted password." in res["suggestions"]

def test_evaluate_password_strong():
    res = evaluate_password("Cyb3rGu@rd#2026!")
    assert res["status"] in ["Strong", "Very Strong"]
    assert res["score"] >= 75

# ==========================================
# 2. INTEGRATION TESTS: REST API ENDPOINTS
# ==========================================
def test_home_route(client):
    response = client.get('/')
    assert response.status_code == 200

def test_threat_scan_endpoint(client):
    response = client.post('/api/v1/threats/scan', json={})
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert len(data["data"]) > 0
    # Verify JSON structure and serialization
    first_item = data["data"][0]
    assert "source_ip" in first_item
    assert "is_anomaly" in first_item
    assert isinstance(first_item["is_anomaly"], bool)

def test_password_analyze_endpoint(client):
    response = client.post('/api/v1/password/analyze', json={"password": "TestPassword123!"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "entropy_bits" in data["data"]

def test_password_generate_endpoint(client):
    response = client.get('/api/v1/password/generate')
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert len(data["password"]) == 16