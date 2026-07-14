"""
SIEM-Watchtower ML Log Collector & Anomaly Detector
====================================================
Connects to the PostgreSQL database, pulls recent system and network logs,
runs them through the trained Isolation Forest + Random Forest models using
BATCH vectorized inference for high performance, and saves anomaly reports
to ml_services/anomaly_reports/.

Usage:
    python collect_and_detect.py              # Run once (default: last 1 hour)
    python collect_and_detect.py --hours 24   # Look back N hours
    python collect_and_detect.py --watch      # Run every 60s continuously
    python collect_and_detect.py --watch --interval 30   # Watch every 30s
"""

import os
import sys
import json
import time
import argparse
import datetime
import numpy as np
import joblib
import psycopg2
import psycopg2.extras

# Force UTF-8 output on Windows to avoid charmap encoding errors
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(SCRIPT_DIR, 'anomaly_reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# DB CONFIG  (matches server/.env defaults)
# ─────────────────────────────────────────────
DB_CONFIG = dict(
    host=os.environ.get('DB_HOST', 'localhost'),
    dbname=os.environ.get('DB_NAME', 'siem-watchtower'),
    user=os.environ.get('DB_USER', 'postgres'),
    password=os.environ.get('DB_PASS', 'pava4484'),
    port=int(os.environ.get('DB_PORT', 5432))
)

# ─────────────────────────────────────────────
# CONSTANTS  (must match train.py)
# ─────────────────────────────────────────────
METHOD_MAP = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3,
              'PATCH': 4, 'OPTIONS': 5, 'HEAD': 6, 'SYS': 7}

ACTION_TYPES = {
    'login_success': 0,  'login_fail': 1,     'logout': 2,
    'session_start': 3,  'promote_admin': 4,  'delete_user': 5,
    'change_password': 6,'create_user': 7,    'sql_injection': 8,
    'xss_attack': 9,     'path_traversal': 10,'js_error': 11,
    'console_open': 12,  'source_view': 13,   'network_error': 14,
    'clipboard': 15,     'download': 16,      'upload': 17,
    'delete_log': 18,    'nav_rapid': 19,     'device_fingerprint': 20,
    'battery_drain': 21, 'brute_force_simulation': 22, 'rage_click': 23,
    'network_request': 24,'performance_metric': 25,    'route_change': 26,
    'PROCESS_START': 27, 'PROCESS_STOP': 28,  'APP_LAUNCH': 29,
    'USB_INSERT': 30,    'WIFI_CONNECT': 31,  'LOGIN_FAILED': 32,
    'SCREEN_LOCKED': 33, 'MALWARE_DETECTED': 34,
}

# Key mappings for feature engineering
SENSITIVE_KEYS  = ['.env', 'config', '.git', 'backup', 'admin', 'passwd']
INJECTION_KEYS  = ['union', 'select', '1=1', '<script', 'onerror', '../']

# ─────────────────────────────────────────────
# LOAD ML MODELS
# ─────────────────────────────────────────────

# Function: load_models
# Description: Loads serialized machine learning model files (Isolation Forest, 
#              Random Forest, Label Encoder, and Scaler) from the script directory.
# Parameters:
#   - None
# Returns:
#   - Tuple: (IsolationForest, RandomForest, LabelEncoder, Scaler)
# Raises:
#   - SystemExit: If any required model file is missing.
def load_models():
    paths = {
        'iso':    os.path.join(SCRIPT_DIR, 'isolation_forest.pkl'),
        'rf':     os.path.join(SCRIPT_DIR, 'random_forest.pkl'),
        'le':     os.path.join(SCRIPT_DIR, 'label_encoder.pkl'),
        'scaler': os.path.join(SCRIPT_DIR, 'scaler.pkl'),
    }
    for name, p in paths.items():
        if not os.path.exists(p):
            print(f"[ERROR] Missing model: {p}\n[ERROR] Run: python train.py")
            sys.exit(1)

    iso    = joblib.load(paths['iso'])
    rf     = joblib.load(paths['rf'])
    le     = joblib.load(paths['le'])
    scaler = joblib.load(paths['scaler'])
    print("[ML] ✅ Isolation Forest + Random Forest + Scaler loaded.")
    return iso, rf, le, scaler

# ─────────────────────────────────────────────
# FEATURE BUILDERS  (vectorized — return 1-D arrays)
# ─────────────────────────────────────────────

# Function: build_network_feature
# Description: Converts a single network log database row into a numerical feature 
#              vector for model prediction. Extracts metadata like HTTP method, 
#              path length, and presence of security keywords.
# Parameters:
#   - row (dict): A dictionary representing a network_logs table record.
# Returns:
#   - list: A 1D list of 12 numerical features.
def build_network_feature(row):
    method       = str(row.get('method') or 'GET').upper()
    path         = str(row.get('path') or '/')
    status       = int(row.get('status_code') or 200)
    resp_ms      = min(int(row.get('response_time_ms') or 100), 30000)
    payload      = min(int(row.get('payload_size_bytes') or 0), 1_000_000)
    path_low     = path.lower()
    path_len     = len(path)
    has_sensitive= int(any(k in path_low for k in SENSITIVE_KEYS))
    has_injection= int(any(k in path_low for k in INJECTION_KEYS))
    failed_log   = int(status in [401, 403])
    return [METHOD_MAP.get(method, 0), 24, status, resp_ms, payload,
            path_len, has_sensitive, has_injection, 1, 0, 5.0, failed_log]

# Function: build_system_feature
# Description: Parses a system log record (including JSON 'details' field) and 
#              generates a numerical feature vector. Maps severity and event types 
#              to numerical encodings.
# Parameters:
#   - row (dict): A dictionary representing a system_logs table record.
# Returns:
#   - list: A 1D list of 12 numerical features compatible with the ML pipeline.
def build_system_feature(row):
    details = row.get('details') or {}
    if isinstance(details, str):
        try: details = json.loads(details)
        except: details = {}
    event_type  = str(row.get('event_type') or '')
    severity    = str(details.get('severity') or 'INFO').upper()
    user_action = str(details.get('user_action') or event_type)
    cpu_use     = float(details.get('cpu_usage') or 5.0)
    failed_log  = int('FAIL' in event_type.upper() or 'BRUTE' in event_type.upper())
    status      = 500 if severity == 'CRITICAL' else (403 if severity in ['HIGH','WARN'] else 200)
    action_enc  = ACTION_TYPES.get(user_action, ACTION_TYPES.get(event_type, 24))
    return [7, action_enc, status, 10, 512, 10, 0, 0, 1, 0, cpu_use, failed_log]

# ─────────────────────────────────────────────
# BATCH SCORING  (vectorized — fast)
# ─────────────────────────────────────────────

# Function: batch_score
# Description: Processes a collection of log rows through the ML pipeline using 
#              vectorized batch operations for high efficiency. Calculates anomaly 
#              scores and assigns MITRE classifications.
# Parameters:
#   - rows (list): List of log dictionaries to analyze.
#   - feature_fn (function): The feature builder function to use (network or system).
#   - iso (IsolationForest): The anomaly detection model.
#   - rf (RandomForestClassifier): The attack classification model.
#   - le (LabelEncoder): Encoder for MITRE ID strings.
#   - scaler (StandardScaler): Re-calculates input scaling.
# Returns:
#   - list: List of detected anomaly objects containing original data and ML scores.
def batch_score(rows, feature_fn, iso, rf, le, scaler):
    if not rows:
        return []

    # Build matrix in one shot
    X = np.array([feature_fn(r) for r in rows], dtype=float)
    X_scaled = scaler.transform(X)

    # Isolation Forest — batch
    raw_scores    = iso.score_samples(X_scaled)            # shape (n,)
    anomaly_scores= np.clip(1.0 - (raw_scores + 0.5), 0, 1)
    iso_preds     = iso.predict(X_scaled)                  # -1 or 1

    # Random Forest — batch
    rf_preds    = rf.predict(X_scaled)                     # encoded labels
    mitre_ids   = le.inverse_transform(rf_preds)           # string labels
    probas      = rf.predict_proba(X_scaled)               # (n, n_classes)
    confidences = np.max(probas, axis=1)

    results = []
    for i, row in enumerate(rows):
        is_anomaly = bool(iso_preds[i] == -1)
        if is_anomaly:
            results.append({
                'row':           row,
                'anomaly_score': round(float(anomaly_scores[i]), 4),
                'mitre_id':      mitre_ids[i],
                'confidence':    round(float(confidences[i]), 4),
                'severity':      'HIGH' if anomaly_scores[i] > 0.75 else 'MEDIUM',
            })
    return results

# ─────────────────────────────────────────────
# FETCH & ANALYSE
# ─────────────────────────────────────────────

# Function: fetch_and_detect
# Description: Connects to the PostgreSQL database, queries the most recent system 
#              and network logs based on a time window, and executes the batch ML 
#              analysis process.
# Parameters:
#   - hours_back (int): The number of hours of history to scan.
#   - iso, rf, le, scaler: The loaded ML components.
# Returns:
#   - Tuple: (list: anomalies, int: total_logs_analysed)
def fetch_and_detect(hours_back, iso, rf, le, scaler):
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours_back)).isoformat()
    print(f"[COLLECTOR] Looking back {hours_back}h (since {since} UTC)")

    conn = psycopg2.connect(**DB_CONFIG)
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ── Network Logs ───────────────────────────────────────────────────────
    cur.execute("""
        SELECT id, timestamp, method, path, status_code,
               response_time_ms, payload_size_bytes, source_ip
        FROM network_logs WHERE timestamp > %s
        ORDER BY timestamp DESC LIMIT 5000
    """, (since,))
    net_rows = [dict(r) for r in cur.fetchall()]
    print(f"[COLLECTOR] Network logs: {len(net_rows)} rows fetched")

    net_hits = batch_score(net_rows, build_network_feature, iso, rf, le, scaler)
    print(f"[COLLECTOR] Network anomalies detected: {len(net_hits)}")

    # ── System Logs ────────────────────────────────────────────────────────
    cur.execute("""
        SELECT id, timestamp, hostname, event_type, mapped_technique_id, details
        FROM system_logs WHERE timestamp > %s
        ORDER BY timestamp DESC LIMIT 5000
    """, (since,))
    sys_rows = [dict(r) for r in cur.fetchall()]
    print(f"[COLLECTOR] System logs: {len(sys_rows)} rows fetched")

    sys_hits = batch_score(sys_rows, build_system_feature, iso, rf, le, scaler)
    print(f"[COLLECTOR] System anomalies detected: {len(sys_hits)}")

    cur.close()
    conn.close()

    # Format anomaly records
    anomalies = []
    for hit in net_hits:
        r = hit['row']
        anomalies.append({
            'source':        'network_logs',
            'log_id':        r['id'],
            'timestamp':     str(r['timestamp']),
            'event':         f"{r.get('method','?')} {r.get('path','?')} [{r.get('status_code','?')}]",
            'source_ip':     str(r.get('source_ip', 'UNKNOWN')),
            'anomaly_score': hit['anomaly_score'],
            'mitre_id':      hit['mitre_id'],
            'confidence':    hit['confidence'],
            'severity':      hit['severity'],
        })
    for hit in sys_hits:
        r = hit['row']
        anomalies.append({
            'source':        'system_logs',
            'log_id':        r['id'],
            'timestamp':     str(r['timestamp']),
            'event':         f"{r.get('event_type','?')} @ {r.get('hostname','?')}",
            'hostname':      str(r.get('hostname', 'UNKNOWN')),
            'anomaly_score': hit['anomaly_score'],
            'mitre_id':      hit['mitre_id'],
            'confidence':    hit['confidence'],
            'severity':      hit['severity'],
        })

    return anomalies, len(net_rows) + len(sys_rows)

# ─────────────────────────────────────────────
# SAVE REPORT
# ─────────────────────────────────────────────

# Function: save_report
# Description: Aggregates detection results into a structured JSON report and writes 
#              it to the 'anomaly_reports' directory. Updates the 'latest' report 
#              sym-link file.
# Parameters:
#   - anomalies (list): The list of detected anomaly objects.
#   - total_logs (int): The total count of raw logs processed during the run.
# Returns:
#   - str: The filesystem path to the newly generated report file.
def save_report(anomalies, total_logs):
    ts      = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%S')
    fname   = f"anomaly_report_{ts}.json"
    fpath   = os.path.join(REPORTS_DIR, fname)
    latest  = os.path.join(REPORTS_DIR, 'latest_anomaly_report.json')

    report = {
        'generated_at':        datetime.datetime.utcnow().isoformat() + 'Z',
        'total_logs_analysed': total_logs,
        'total_anomalies':     len(anomalies),
        'anomaly_rate_pct':    round(len(anomalies) / max(total_logs, 1) * 100, 2),
        'models_used':         ['IsolationForest', 'RandomForestClassifier', 'StandardScaler'],
        'anomalies':           sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True),
    }

    def json_default(obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return str(obj)

    for p in [fpath, latest]:
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=json_default)

    print(f"[REPORT] ✅  Saved  → {fpath}")
    print(f"[REPORT] ✅  Latest → {latest}")
    print(f"[REPORT] 📊  {len(anomalies)} anomalies / {total_logs} logs "
          f"({report['anomaly_rate_pct']}% anomaly rate)")
    return fpath

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

# Function: run_once
# Description: Orchestrates a single collection and detection cycle, outputting 
#              execution time and terminal logs.
# Parameters:
#   - hours_back (int): The history window to process.
#   - iso, rf, le, scaler: The ML models.
# Returns:
#   - str: The path to the generated report file.
def run_once(hours_back, iso, rf, le, scaler):
    divider = '=' * 60
    print(f"\n{divider}")
    print(f" SIEM ANOMALY DETECTOR  |  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(divider)
    t0 = time.time()
    anomalies, total = fetch_and_detect(hours_back, iso, rf, le, scaler)
    path = save_report(anomalies, total)
    print(f"[DONE] Completed in {time.time()-t0:.1f}s\n")
    return path

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hours',    type=int, default=1,  help='Hours of logs to look back (default: 1)')
    parser.add_argument('--watch',    action='store_true',  help='Run continuously')
    parser.add_argument('--interval', type=int, default=60, help='Seconds between watch runs (default: 60)')
    args = parser.parse_args()

    iso, rf, le, scaler = load_models()

    if args.watch:
        print(f"[WATCHER] 👁  Running every {args.interval}s  (Ctrl+C to stop)")
        while True:
            try:
                run_once(args.hours, iso, rf, le, scaler)
            except Exception as e:
                print(f"[WATCHER ERROR] {e}")
            time.sleep(args.interval)
    else:
        run_once(args.hours, iso, rf, le, scaler)
