# ML Anomaly Detection — Integration Guide

## Overview

The SIEM Watchtower uses a Python **Flask microservice** for ML-based anomaly detection.  
It runs independently on **port 5001** and is called by the Node.js backend for every non-internal HTTP request.

---

## Architecture

```
Node.js Backend (port 5000)
        │
        │ POST /predict  (via axios, timeout: 2s)
        ▼
ML Service (Python Flask, port 5001)
        │
        ├── Isolation Forest  → anomaly_score, is_anomaly
        └── Random Forest     → mitre_technique_id, confidence
        │
        ▼
   Returns JSON to Node.js:
   { anomaly_score, is_anomaly, mitre_technique_id, confidence }
```

---

## Fallback Behaviour

If the ML service is unavailable (offline or timed out), the backend automatically **falls back** to the built-in `SIEMRuleEngine()` heuristic detector.  
The service is re-checked every 60 seconds.

---

## ML Service Endpoints

### POST `/predict`
Scores a single event for anomaly and classifies its MITRE technique.

**Request:**
```json
{
  "method": "GET",
  "path": "/api/login",
  "status_code": 401,
  "response_time_ms": 5,
  "payload_size_bytes": 128,
  "action_type": "login_fail"
}
```

**Response:**
```json
{
  "anomaly_score": 0.87,
  "is_anomaly": true,
  "mitre_technique_id": "T1110",
  "confidence": 0.91
}
```

### GET `/health`
```json
{ "status": "ok", "model": "isolation_forest_v1" }
```

---

## Models

| Model | Purpose | Algorithm | File |
|---|---|---|---|
| Isolation Forest | Anomaly detection (unsupervised) | sklearn IsolationForest | `isolation_forest.pkl` |
| Random Forest | MITRE technique classification | sklearn RandomForestClassifier | `random_forest.pkl` |
| Label Encoder | Converts technique IDs to class numbers | LabelEncoder | `label_encoder.pkl` |

---

## Training Data Features

The models are trained on these **6 features** (see `feature_meta.json`):

| Feature | Type | Description |
|---|---|---|
| `method` | categorical | HTTP method (GET, POST, etc.) |
| `path` | categorical | API endpoint path |
| `status_code` | numeric | HTTP response status |
| `response_time_ms` | numeric | Time to respond in ms |
| `payload_size_bytes` | numeric | Response size |
| `action_type` | categorical | Event type (login_fail, page_visit, etc.) |

---

## Retraining the Models

```bash
cd ml_service
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Edit train.py to load your new dataset, then:
python train.py
# Creates new .pkl files

# Restart the service:
python app.py
```

---

## Improving the ML Model (FYP Suggestions)

| Improvement | Description |
|---|---|
| **Real dataset** | Use CICIDS2017 or UNSW-NB15 instead of synthetic data |
| **More features** | Add hour-of-day, day-of-week, user-agent hash, geo-location |
| **LSTM / Autoencoder** | Use time-series models for sequential behaviour detection |
| **Online learning** | Update model weights in real-time as new events arrive |
| **Sliding window** | Score groups of 5–10 events together, not one at a time |
| **Feedback loop** | Allow admin to mark false positives → retrain model |
