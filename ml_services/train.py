"""
SIEM-Watchtower ML Training Script
Generates synthetic log data and trains:
  1. Isolation Forest  - anomaly detection
  2. Random Forest     - MITRE technique classification
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────
# 1. FEATURE ENGINEERING HELPERS
# ─────────────────────────────────────────────

METHOD_MAP   = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'PATCH': 4, 'OPTIONS': 5, 'HEAD': 6}
ACTION_TYPES = {
    'login_success':    0,  'login_fail':      1,  'logout':          2,
    'session_start':    3,  'promote_admin':   4,  'delete_user':     5,
    'change_password':  6,  'create_user':     7,  'sql_injection':   8,
    'xss_attack':       9,  'path_traversal':  10, 'js_error':        11,
    'console_open':     12, 'source_view':     13, 'network_error':   14,
    'clipboard':        15, 'download':         16, 'upload':          17,
    'delete_log':       18, 'nav_rapid':        19, 'device_fingerprint': 20,
    'battery_drain':    21, 'brute_force_simulation': 22, 'rage_click': 23,
    'network_request':  24, 'performance_metric': 25, 'route_change':  26,
}

# Function: encode_features
# Description: Converts a list of raw log dictionaries into a structured numerical 
#              feature matrix (numpy array) suitable for scikit-learn model training.
# Parameters:
#   - rows (list): A list of dictionaries, where each dict represents a single log entry.
# Returns:
#   - numpy.ndarray: A 2D array of encoded float features.
def encode_features(rows):
    """Convert list of dicts to feature matrix."""
    result = []
    for r in rows:
        method_enc   = METHOD_MAP.get(str(r.get('method', 'GET')).upper(), 0)
        action_enc   = ACTION_TYPES.get(str(r.get('action_type', 'network_request')), 24)
        status       = int(r.get('status_code', 200))
        response_ms  = min(int(r.get('response_time_ms', 100)), 30000)  # cap at 30s
        payload_size = min(int(r.get('payload_size_bytes', 0)), 1_000_000)
        path_len     = len(str(r.get('path', '/')))
        has_sensitive = 1 if any(k in str(r.get('path', '')).lower()
                                 for k in ['.env', 'config', '.git', 'backup', 'admin', 'passwd']) else 0
        has_injection = 1 if any(k in str(r.get('path', '')).lower()
                                 for k in ['union', 'select', '1=1', '<script', 'onerror', '../']) else 0
                                 
        # --- NEW FEATURES INTERACTION ---
        req_freq     = int(r.get('request_freq_1m', 1))
        sess_dur     = int(r.get('session_duration_m', 0))
        cpu_use      = float(r.get('cpu_usage_pct', 5.0))
        failed_log   = int(r.get('failed_login_attempts', 0))
        
        result.append([method_enc, action_enc, status, response_ms, payload_size,
                        path_len, has_sensitive, has_injection, req_freq, sess_dur, cpu_use, failed_log])
    return np.array(result, dtype=float)

# ─────────────────────────────────────────────
# 2. SYNTHETIC DATA GENERATION
# ─────────────────────────────────────────────

# Function: generate_data
# Description: Programmatically generates a balanced dataset of synthetic log entries 
#              simulating both normal system behavior and various MITRE ATT&CK 
#              threat patterns (e.g., Brute Force, SQLi, XSS).
# Parameters:
#   - n_normal (int): Number of normal traffic samples to generate. Defaults to 5000.
#   - n_attack (int): Approximate modifier for attack samples. Defaults to 1000.
# Returns:
#   - Tuple: (list: rows, list: labels) where labels are MITRE technique IDs.
def generate_data(n_normal=5000, n_attack=1000):
    rows   = []
    labels = []   # MITRE technique IDs

    rng = np.random.default_rng(42)

    # --- Normal Traffic (T1078 - Valid Accounts / T1204 - User Execution) ---
    for _ in range(n_normal):
        rows.append({
            'method':             rng.choice(['GET', 'POST']),
            'action_type':        rng.choice(['login_success', 'logout', 'route_change', 'network_request']),
            'status_code':        rng.choice([200, 204, 301, 302], p=[0.7, 0.1, 0.1, 0.1]),
            'response_time_ms':   int(rng.normal(120, 40)),
            'payload_size_bytes': int(rng.normal(1500, 500)),
            'path':               rng.choice(['/api/login', '/api/log', '/', '/dashboard', '/portal']),
            'request_freq_1m':    int(rng.normal(5, 2)),
            'session_duration_m': int(rng.normal(30, 15)),
            'cpu_usage_pct':      float(rng.normal(15, 5)),
            'failed_login_attempts': 0
        })
        labels.append(rng.choice(['T1078', 'T1204']))

    # --- Brute Force (T1110) ---
    for _ in range(200):
        rows.append({
            'method':             'POST',
            'action_type':        'login_fail',
            'status_code':        rng.choice([401, 403]),
            'response_time_ms':   int(rng.normal(50, 10)),
            'payload_size_bytes': int(rng.normal(200, 50)),
            'path':               '/api/login',
            'request_freq_1m':    int(rng.normal(80, 15)),  # Aggressive frequency
            'session_duration_m': 0,
            'cpu_usage_pct':      float(rng.normal(25, 5)), # Higher CPU from attempts
            'failed_login_attempts': int(rng.normal(15, 3)) # Extremely High failures
        })
        labels.append('T1110')

    # --- Active Scanning (T1595) ---
    for _ in range(200):
        rows.append({
            'method':             'GET',
            'action_type':        'network_request',
            'status_code':        rng.choice([404, 403]),
            'response_time_ms':   int(rng.normal(30, 10)),
            'payload_size_bytes': 0,
            'path':               rng.choice(['.env', 'config.php', '.git/HEAD', 'backup.sql', 'admin/passwd']),
            'request_freq_1m':    int(rng.normal(60, 15)),  # Very rapid scanning
            'session_duration_m': 1,
            'cpu_usage_pct':      float(rng.normal(10, 3)),
            'failed_login_attempts': 0
        })
        labels.append('T1595')

    # --- SQL Injection (T1190) ---
    for _ in range(150):
        rows.append({
            'method':             rng.choice(['GET', 'POST']),
            'action_type':        'sql_injection',
            'status_code':        rng.choice([200, 500]),
            'response_time_ms':   int(rng.normal(600, 150)),  # Heavy queries
            'payload_size_bytes': int(rng.normal(1500, 400)), # Obfuscated large payloads
            'path':               rng.choice(['/api/login', '/api/users', '/portal/search']),
        })
        labels.append('T1190')

    # --- XSS (T1059.007) ---
    for _ in range(150):
        rows.append({
            'method':             'POST',
            'action_type':        'xss_attack',
            'status_code':        200,
            'response_time_ms':   int(rng.normal(200, 50)),
            'payload_size_bytes': int(rng.normal(600, 150)),
            'path':               rng.choice(['/api/log', '/portal/comment', '/api/login']),
        })
        labels.append('T1059.007')

    # --- Clipboard / Data Collection (T1115) ---
    for _ in range(100):
        rows.append({
            'method':             'POST',
            'action_type':        'clipboard',
            'status_code':        200,
            'response_time_ms':   int(rng.normal(80, 20)),
            'payload_size_bytes': int(rng.normal(400, 100)),
            'path':               '/api/log',
        })
        labels.append('T1115')

    # --- Path Traversal (T1083) ---
    for _ in range(100):
        rows.append({
            'method':             'GET',
            'action_type':        'path_traversal',
            'status_code':        rng.choice([403, 200]),
            'response_time_ms':   int(rng.normal(60, 15)),
            'payload_size_bytes': 0,
            'path':               rng.choice(['../etc/passwd', '../../boot.ini', '../../../windows/system32']),
        })
        labels.append('T1083')

    # --- Exfiltration (T1567) ---
    for _ in range(100):
        rows.append({
            'method':             rng.choice(['GET', 'POST']),
            'action_type':        'download',
            'status_code':        200,
            'response_time_ms':   int(rng.normal(500, 150)),
            'payload_size_bytes': int(rng.normal(50_000, 10_000)),  # large payloads
            'path':               rng.choice(['/api/export', '/api/download', '/portal/data']),
        })
        labels.append('T1567')

    # --- Account Manipulation (T1098) ---
    for _ in range(100):
        rows.append({
            'method':             'POST',
            'action_type':        rng.choice(['promote_admin', 'delete_user', 'change_password']),
            'status_code':        200,
            'response_time_ms':   int(rng.normal(150, 40)),
            'payload_size_bytes': int(rng.normal(300, 80)),
            'path':               rng.choice(['/api/promote', '/api/users', '/api/delete-user']),
            'request_freq_1m':    int(rng.normal(10, 4)),
            'session_duration_m': int(rng.normal(120, 30)),
            'cpu_usage_pct':      float(rng.normal(20, 5)),
            'failed_login_attempts': 0
        })
        labels.append('T1098')

    return rows, labels

# ─────────────────────────────────────────────
# 3. TRAIN MODELS
# ─────────────────────────────────────────────

# Function: train
# Description: Orchestrates the entire training pipeline: generates synthetic data, 
#              encodes features, scales data, trains both anomaly detection 
#              (Isolation Forest) and classification (Random Forest) models, 
#              and serializes the resulting objects to disk for use by the microservice.
# Parameters:
#   - None
# Returns:
#   - None: Outputs progress and final accuracy to the console; saves .pkl files.
def train():
    print("[TRAIN] Generating synthetic data...")
    rows, labels = generate_data()

    X = encode_features(rows)
    y = np.array(labels)

    print("[TRAIN] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"[TRAIN] Dataset: {len(rows)} samples, {len(set(labels))} classes")

    # --- Isolation Forest (Anomaly Detection) ---
    print("[TRAIN] Tuning Isolation Forest Hyperparameters...")
    iso = IsolationForest(
        n_estimators=300,        # Boosted for higher variance reduction
        max_samples='auto',      # Tuned subsampling 
        contamination=0.05,      # Strict threshold tuning - Reduced FP rate
        max_features=1.0,        # Use all normalized features
        random_state=42, 
        n_jobs=-1
    )
    iso.fit(X_scaled)
    print("[TRAIN] Isolation Forest optimization complete.")

    # --- Label Encoding for Random Forest ---
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # --- Random Forest Classifier ---
    print("[TRAIN] Training Random Forest for Attack Classification...")
    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=None,
        min_samples_split=5,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_scaled, y_enc)
    train_acc = rf.score(X_scaled, y_enc)
    print(f"[TRAIN] Random Forest training accuracy: {train_acc:.3f}")

    # --- Save Models ---
    iso_path = os.path.join(SCRIPT_DIR, 'isolation_forest.pkl')
    rf_path  = os.path.join(SCRIPT_DIR, 'random_forest.pkl')
    le_path  = os.path.join(SCRIPT_DIR, 'label_encoder.pkl')
    scaler_path = os.path.join(SCRIPT_DIR, 'scaler.pkl')

    joblib.dump(iso, iso_path)
    joblib.dump(rf, rf_path)
    joblib.dump(le, le_path)
    joblib.dump(scaler, scaler_path)

    print(f"[TRAIN] ✅ Models saved:")
    print(f"        {iso_path}")
    print(f"        {rf_path}")
    print(f"        {le_path}")
    print(f"        {scaler_path}")

    # Save feature encoder info for app.py
    import json
    meta = {'method_map': METHOD_MAP, 'action_types': ACTION_TYPES}
    meta_path = os.path.join(SCRIPT_DIR, 'feature_meta.json')
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"        {meta_path}")
    print("[TRAIN] ✅ Training complete!")

if __name__ == '__main__':
    train()
