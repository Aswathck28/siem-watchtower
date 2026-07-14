"""
SIEM-Watchtower ML Microservice
Flask REST API — exposes POST /predict for anomaly scoring + MITRE classification
"""

from flask import Flask, request, jsonify
import joblib
import numpy as np
import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [ML] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────
# LOAD MODELS AT STARTUP
# ─────────────────────────────────────────────

# Function: load_models
# Description: Synchronously loads pre-trained machine learning models (Isolation Forest, 
#              Random Forest), label encoders, scalers, and feature metadata from the 
#              local filesystem into memory.
# Parameters:
#   - None
# Returns:
#   - Tuple: (IsolationForest, RandomForest, LabelEncoder, dict: metadata, Scaler)
# Throws:
#   - FileNotFoundError: If any of the required .pkl or .json files are missing.
def load_models():
    iso_path  = os.path.join(SCRIPT_DIR, 'isolation_forest.pkl')
    rf_path   = os.path.join(SCRIPT_DIR, 'random_forest.pkl')
    le_path   = os.path.join(SCRIPT_DIR, 'label_encoder.pkl')
    meta_path = os.path.join(SCRIPT_DIR, 'feature_meta.json')
    scaler_path = os.path.join(SCRIPT_DIR, 'scaler.pkl')

    if not all(os.path.exists(p) for p in [iso_path, rf_path, le_path, meta_path, scaler_path]):
        raise FileNotFoundError(
            "Model files not found. Please run: python train.py"
        )

    iso  = joblib.load(iso_path)
    rf   = joblib.load(rf_path)
    le   = joblib.load(le_path)
    scaler = joblib.load(scaler_path)
    with open(meta_path) as f:
        meta = json.load(f)

    logger.info("✅ Models loaded successfully.")
    return iso, rf, le, meta, scaler

try:
    ISOLATION_FOREST, RANDOM_FOREST, LABEL_ENCODER, META, SCALER = load_models()
    MODELS_READY = True
except FileNotFoundError as e:
    logger.warning(f"⚠️  {e}")
    MODELS_READY = False

# ─────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────

# Function: encode_features
# Description: Transforms raw JSON log data into a structured numerical numpy array 
#              using mappings and heuristic extraction (e.g., path length, sensitive 
#              keyword detection) required for model input.
# Parameters:
#   - data (dict): The raw JSON object from the incoming request.
# Returns:
#   - numpy.ndarray: A 2D array of shape (1, 12) containing encoded float features.
def encode_features(data):
    method_map   = META.get('method_map',   {}) if MODELS_READY else {}
    action_types = META.get('action_types', {}) if MODELS_READY else {}

    method_enc   = method_map.get(str(data.get('method', 'GET')).upper(), 0)
    action_enc   = action_types.get(str(data.get('action_type', 'network_request')), 24)
    status       = int(data.get('status_code', 200))
    response_ms  = min(int(data.get('response_time_ms', 100)), 30000)
    payload_size = min(int(data.get('payload_size_bytes', 0)), 1_000_000)
    path         = str(data.get('path', '/'))
    path_len     = len(path)
    has_sensitive = 1 if any(k in path.lower() for k in [
        '.env', 'config', '.git', 'backup', 'admin', 'passwd']) else 0
    has_injection = 1 if any(k in path.lower() for k in [
        'union', 'select', '1=1', '<script', 'onerror', '../']) else 0

    # --- NEW FEATURES INTERACTION ---
    req_freq     = int(data.get('request_freq_1m', 1))
    sess_dur     = int(data.get('session_duration_m', 0))
    cpu_use      = float(data.get('cpu_usage_pct', 5.0))
    failed_log   = int(data.get('failed_login_attempts', 0))

    return np.array([[method_enc, action_enc, status, response_ms,
                      payload_size, path_len, has_sensitive, has_injection, req_freq, sess_dur, cpu_use, failed_log]],
                    dtype=float)


def _to_bounded_int(value, field_name, minimum, maximum, default=None):
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} must be an integer")
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}")
    return parsed


def _to_bounded_float(value, field_name, minimum, maximum, default=None):
    if value is None:
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} must be a number")
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}")
    return parsed


def validate_predict_payload(data):
    if not isinstance(data, dict):
        return None, ["JSON body must be an object"]

    errors = []
    cleaned = {}

    method = data.get("method", "GET")
    if not isinstance(method, str) or not method.strip():
        errors.append("method must be a non-empty string")
    else:
        cleaned["method"] = method.strip().upper()[:20]

    action_type = data.get("action_type", "network_request")
    if not isinstance(action_type, str) or not action_type.strip():
        errors.append("action_type must be a non-empty string")
    else:
        cleaned["action_type"] = action_type.strip()[:80]

    path = data.get("path", "/")
    if not isinstance(path, str) or not path.strip():
        errors.append("path must be a non-empty string")
    else:
        cleaned["path"] = path[:4096]

    try:
        cleaned["status_code"] = _to_bounded_int(data.get("status_code"), "status_code", 100, 599, 200)
        cleaned["response_time_ms"] = _to_bounded_int(data.get("response_time_ms"), "response_time_ms", 0, 30000, 100)
        cleaned["payload_size_bytes"] = _to_bounded_int(data.get("payload_size_bytes"), "payload_size_bytes", 0, 1_000_000, 0)
        cleaned["request_freq_1m"] = _to_bounded_int(data.get("request_freq_1m"), "request_freq_1m", 0, 100000, 1)
        cleaned["session_duration_m"] = _to_bounded_int(data.get("session_duration_m"), "session_duration_m", 0, 10080, 0)
        cleaned["failed_login_attempts"] = _to_bounded_int(data.get("failed_login_attempts"), "failed_login_attempts", 0, 10000, 0)
        cleaned["cpu_usage_pct"] = _to_bounded_float(data.get("cpu_usage_pct"), "cpu_usage_pct", 0.0, 100.0, 5.0)
    except ValueError as e:
        errors.append(str(e))

    if errors:
        return None, errors
    return cleaned, []

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

# Route: GET /health
# Description: Monitoring endpoint to check the service health and model availability.
# Parameters:
#   - None
# Returns:
#   - JSON: Object indicating 'ok' status and whether models are loaded.
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':       'ok',
        'models_ready': MODELS_READY
    })


# Route: POST /predict
# Description: Core inference endpoint. Accepts telemetry data, encodes it, 
#              calculates an anomaly score using Isolation Forest, and performs 
#              attack classification using a Random Forest model.
# Parameters:
#   - Request JSON: Attributes like 'method', 'path', 'status_code', etc.
# Returns:
#   - JSON: Prediction results including 'anomaly' (bool), 'score' (0-1 float), 
#           'attack_type' (str), and 'confidence' (float).
@app.route('/predict', methods=['POST'])
def predict():
    if not MODELS_READY:
        return jsonify({'error': 'Models not trained yet. Run train.py first.'}), 503

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Invalid JSON body'}), 400
    cleaned_data, validation_errors = validate_predict_payload(data)
    if validation_errors:
        return jsonify({'error': 'Validation failed', 'details': validation_errors}), 400

    try:
        X = encode_features(cleaned_data)
        X_scaled = SCALER.transform(X)

        # ── ISOLATION FOREST ──────────────────────────────
        # score_samples returns negative values; more negative = more anomalous
        raw_score     = float(ISOLATION_FOREST.score_samples(X_scaled)[0])
        # Normalise to 0.0–1.0 where 1.0 = most anomalous
        anomaly_score = max(0.0, min(1.0, 1.0 - (raw_score + 0.5) / 1.0))
        iso_pred      = int(ISOLATION_FOREST.predict(X_scaled)[0])   # -1=anomaly, 1=normal
        is_anomaly    = bool(iso_pred == -1)

        # ── HIST GRADIENT BOOSTING ─────────────────────────────────
        rf_pred_enc   = RANDOM_FOREST.predict(X_scaled)[0]
        mitre_id      = LABEL_ENCODER.inverse_transform([rf_pred_enc])[0]
        proba         = RANDOM_FOREST.predict_proba(X_scaled)[0]
        confidence    = float(np.max(proba))

        # ── HYBRID DETECTION CORRELATION ─────────────────
        # Random Forest categorizes the attack type
        attack_map = {
            'T1078': 'Normal',
            'T1204': 'Normal',
            'T1110': 'Brute Force',
        }
        attack_type = attack_map.get(str(mitre_id), 'Suspicious Activity')
        
        # If Isolation Forest says it's normal, ensure we don't label it a threat
        # UNLESS Random Forest has a very high confidence it is an attack
        if not is_anomaly and attack_type != 'Normal':
            if confidence < 0.85:
                attack_type = 'Suspicious Activity'
            
        if not is_anomaly and mitre_id in ['T1078', 'T1204']:
             attack_type = 'Normal'

        response = {
            'anomaly':      is_anomaly,
            'score':        round(anomaly_score, 4),
            'attack_type':  attack_type,
            'mitre_technique_id': mitre_id,
            'confidence':   round(confidence, 4),
        }

        logger.info(
            f"Predicted: mitre={mitre_id} anomaly={is_anomaly} "
            f"score={anomaly_score:.3f} conf={confidence:.3f}"
        )
        return jsonify(response)

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({'error': str(e)}), 500


# Route: POST /reload
# Description: Administrative endpoint to reload serialized models from disk 
#              into the running process memory without a full service restart.
# Parameters:
#   - None
# Returns:
#   - JSON: Confirmation of model reload.
@app.route('/reload', methods=['POST'])
def reload_models():
    """Re-load models from disk without restarting the service."""
    global ISOLATION_FOREST, RANDOM_FOREST, LABEL_ENCODER, META, SCALER, MODELS_READY
    try:
        ISOLATION_FOREST, RANDOM_FOREST, LABEL_ENCODER, META, SCALER = load_models()
        MODELS_READY = True
        return jsonify({'status': 'models reloaded'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    logger.info("Starting SIEM-Watchtower ML Service on port 5001...")
    app.run(host='0.0.0.0', port=5001, debug=False)
