import math
import re
import secrets
import string
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# ==========================================
# 1. AI THREAT DETECTION ENGINE
# ==========================================
class ThreatDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.08, random_state=42, n_estimators=100)
        self._train_baseline()

    def _train_baseline(self):
        np.random.seed(42)
        n_samples = 1000
        normal_data = {
            'packet_size': np.random.normal(500, 100, n_samples),
            'duration': np.random.normal(1.5, 0.5, n_samples),
            'failed_logins': np.random.choice([0, 1, 2], n_samples, p=[0.85, 0.12, 0.03]),
            'request_rate': np.random.normal(20, 5, n_samples),
            'bytes_transferred': np.random.normal(10000, 2000, n_samples)
        }
        df = pd.DataFrame(normal_data)
        
        # Inject synthetic anomalies
        anomaly_idx = np.random.choice(n_samples, 80, replace=False)
        df.loc[anomaly_idx, 'packet_size'] *= np.random.uniform(3, 8, 80)
        df.loc[anomaly_idx, 'failed_logins'] += np.random.randint(5, 15, 80)
        df.loc[anomaly_idx, 'request_rate'] *= np.random.uniform(5, 12, 80)
        
        X = df[['packet_size', 'duration', 'failed_logins', 'request_rate', 'bytes_transferred']]
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

    def analyze_logs(self, raw_logs):
        df = pd.DataFrame(raw_logs)
        features = ['packet_size', 'duration', 'failed_logins', 'request_rate', 'bytes_transferred']
        
        for col in features:
            if col not in df.columns:
                df[col] = 0.0

        X_scaled = self.scaler.transform(df[features])
        predictions = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        results = []
        for idx, row in df.iterrows():
            is_anomaly =bool( predictions[idx] == -1)
            score = float(scores[idx])
            
            if score < -0.15:
                severity = "CRITICAL"
            elif score < 0:
                severity = "HIGH"
            elif score < 0.1:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            results.append({
                "source_ip": row.get("source_ip", "192.168.1.100"),
                "packet_size": float(row["packet_size"]),
                "duration": float(row["duration"]),
                "failed_logins": int(row["failed_logins"]),
                "request_rate": float(row["request_rate"]),
                "bytes_transferred": float(row["bytes_transferred"]),
                "is_anomaly": is_anomaly,
                "anomaly_score": round(score, 4),
                "severity": severity
            })
        return results

detector = ThreatDetector()

# ==========================================
# 2. PASSWORD SECURITY ENGINE
# ==========================================
def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    pool_size = 0
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"[0-9]", password): pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool_size += 32
    return len(password) * math.log2(pool_size) if pool_size > 0 else 0.0

def evaluate_password(password: str) -> dict:
    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "numbers": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }
    
    common_passwords = ["123456", "password", "admin123", "qwerty", "welcome", "12345678"]
    is_common = password.lower() in common_passwords
    entropy = calculate_entropy(password)
    
    score = 0
    if not is_common and len(password) > 0:
        passed = sum(checks.values())
        score = min(100, int((passed / 5) * 60 + (min(entropy, 80) / 80) * 40))

    if is_common or score < 30:
        status, color = "Very Weak", "#ef4444"
    elif score < 55:
        status, color = "Weak", "#f97316"
    elif score < 75:
        status, color = "Moderate", "#eab308"
    elif score < 90:
        status, color = "Strong", "#10b981"
    else:
        status, color = "Very Strong", "#059669"

    suggestions = []
    if is_common: suggestions.append("This is an extremely common blacklisted password.")
    if len(password) < 12: suggestions.append("Extend password length to 12+ characters.")
    if not checks["uppercase"]: suggestions.append("Add uppercase letters (A-Z).")
    if not checks["lowercase"]: suggestions.append("Add lowercase letters (a-z).")
    if not checks["numbers"]: suggestions.append("Add numeric digits (0-9).")
    if not checks["special"]: suggestions.append("Add symbols (!@#$%^&*).")

    return {
        "score": score,
        "status": status,
        "color": color,
        "entropy_bits": round(entropy, 1),
        "checks": checks,
        "suggestions": suggestions
    }

# ==========================================
# 3. REST API ENDPOINTS
# ==========================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/v1/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if username == "admin@cyberguard.sec" and password == "Admin@123456!":
        return jsonify({"success": True, "token": "cg_sec_session_token_998123"}), 200
    return jsonify({"success": False, "error": "Invalid SOC Analyst credentials"}), 401

@app.route('/api/v1/threats/scan', methods=['POST'])
def api_scan_threats():
    data = request.get_json(force=True)
    logs = data.get("logs", [])
    if not logs:
        np.random.seed()
        logs = [
            {"source_ip": "192.168.1.105", "packet_size": 480, "duration": 1.2, "failed_logins": 0, "request_rate": 18, "bytes_transferred": 9800},
            {"source_ip": "10.0.0.45", "packet_size": 3200, "duration": 14.5, "failed_logins": 14, "request_rate": 280, "bytes_transferred": 450000},
            {"source_ip": "192.168.1.112", "packet_size": 520, "duration": 1.8, "failed_logins": 1, "request_rate": 22, "bytes_transferred": 11200},
            {"source_ip": "172.16.0.88", "packet_size": 2900, "duration": 8.1, "failed_logins": 18, "request_rate": 195, "bytes_transferred": 890000},
            {"source_ip": "192.168.1.120", "packet_size": 510, "duration": 1.1, "failed_logins": 0, "request_rate": 19, "bytes_transferred": 10100}
        ]
    analysis = detector.analyze_logs(logs)
    return jsonify({"success": True, "data": analysis}), 200

@app.route('/api/v1/password/analyze', methods=['POST'])
def api_analyze_password():
    data = request.get_json(force=True)
    password = data.get("password", "")
    if len(password) > 256:
        return jsonify({"error": "Password exceeds limits"}), 400
    return jsonify({"success": True, "data": evaluate_password(password)}), 200

@app.route('/api/v1/password/generate', methods=['GET'])
def api_generate_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
    return jsonify({"success": True, "password": pwd}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
