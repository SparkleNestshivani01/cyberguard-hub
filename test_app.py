import io
import pytest
from app import app, db, evaluate_password, calculate_entropy

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

# ==========================================
# 1. UNIT TESTS: PASSWORD ENGINE
# ==========================================
def test_calculate_entropy():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("password123") < calculate_entropy("P@ssw0rd123!#$")

def test_evaluate_password_weak():
    res = evaluate_password("123456")
    assert res["status"] == "Very Weak"
    assert "Blacklisted password." in res["suggestions"]

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
    first_item = data["data"][0]
    assert "source_ip" in first_item
    assert "is_anomaly" in first_item
    assert isinstance(first_item["is_anomaly"], bool)

def test_password_analyze_endpoint(client):
    response = client.post('/api/v1/password/analyze', json={"password": "TestPassword123!"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "entropy" in data["data"]

def test_upload_csv_endpoint(client):
    csv_data = "source_ip,bytes_sent,request_rate\n10.0.0.1,500,20\n10.0.0.2,4500,250\n"
    data = {
        'file': (io.BytesIO(csv_data.encode('utf-8')), 'test_log.csv')
    }
    response = client.post('/api/v1/threats/upload-csv', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["total_scanned"] == 2