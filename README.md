# 🛡️ SIEM Watchtower

> A Security Information and Event Management (SIEM) system built as a Final Year Project.  
> Monitors user behavior, detects threats, and maps them to the **MITRE ATT&CK** framework.

---

## 📌 Features

| Feature | Description |
|---|---|
| 🔐 User Authentication | Firebase-based login with role assignment (ADMIN / USER) and account prompt forcing |
| 🔥 Brute-Force Detection | Flags IPs with 5+ failed login attempts |
| 🕐 Session Tracking | Tracks login time, duration, long-session alerts |
| 🌐 Web Activity Logging | Outbound links, tab changes, site transitions, and context views |
| 🕵️ MITRE ATT&CK Mapping | Every event mapped to a MITRE technique ID |
| 🤖 ML Anomaly Detection | Python microservice using Isolation Forest |
| 📦 Log Archival | Auto-archives logs older than 30 days |
| 📥 Log Export | Export system/network/activity logs as CSV or JSON |
| 🚨 Email Alerts | Sends live email alerts for critical events |
| 🔒 Security Hardening | Helmet.js, rate limiting, SQL injection & XSS detection |
| ⚡ Near-Zero Overhead | Optimized C-level psutil sensors and sequential React polling |

---

## 📸 Screenshots (Project Showcase)

1. **Dashboard Overview:** `![Dashboard Placeholder](docs/images/dashboard.png)`
2. **Live Telemetry Feed (Web/Agent logs):** `![Telemetry Placeholder](docs/images/telemetry.png)`
3. **MITRE ATT&CK Mapping (Anomaly detected):** `![MITRE Placeholder](docs/images/mitre_mapping.png)`

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                          │
│                      React Dashboard                         │
│  • AdminDashboard.js      │  • NormalUserDashboard.js        │
│  • useTelemetry.js (DLP)  │  • useTabTracking.js             │
└───────────────────┬──────────────────────────────────────────┘
                    │ HTTP REST API
┌───────────────────▼──────────────────────────────────────────┐
│                     BACKEND LAYER                            │
│              Node.js + Express  (Port 5000)                  │
│  • SIEM Rule Engine     • MITRE ATT&CK Mapper                │
│  • Brute Force Detector • Email Alert System                 │
│  • Log Archival System  • Security Interceptor Middleware     │
└───────┬─────────────────────────────────┬────────────────────┘
        │ pg (postgres driver)             │ HTTP /predict
┌───────▼───────────────┐    ┌────────────▼────────────────────┐
│  PostgreSQL Database  │    │  ML Microservice (Python 5001)  │
│  • system_logs        │    │  • Isolation Forest             │
│  • network_logs       │    │  • Random Forest (MITRE class.) │
│  • activity_logs      │    │  • Flask REST API               │
│  • active_alerts      │    └─────────────────────────────────┘
│  • correlated_sessions│
│  • mitre_definitions  │
└───────────────────────┘
        ▲
┌───────┴──────────────────────────────────────────────────────┐
│                     AGENT LAYER                              │
│       app_tracker.py (Windows Monitor Agent - Python)        │
│  • Active process monitors       • Battery sensor tracking   │
│  • Foreground window changes     • Hardware controls (USB)   │
└──────────────────────────────────────────────────────────────┘
```

### 🔄 System Workflow (Data Lifecycle)
1. **Data Ingestion:** The Windows Agent (`app_tracker.py`) collects local telemetry and foreground window changes, sending JSON payloads to the Express.js API.
2. **Analysis & ML Routing:** The Node.js Express server routes standard traffic to PostgreSQL. For specific anomaly checks, it POSTs data to the Python Flask Microservice (`port 5001`).
3. **Anomaly Detection:** The Python Isolation Forest model scores the data. If the score is `< 0` (Anomaly), it alerts the Node.js backend to classify the event as a Threat.
4. **MITRE Correlation:** The backend parses the threat payload against the `mitre_definitions` table to output the specific TTP (e.g., *Command & Control / Exfiltration*).
5. **Real-time Display:** The React Dashboard continuously polls/receives these correlated logs and renders the visual Radar maps and metrics.

---

## 📁 Folder Structure

```
siem-watchtower/
├── client/                   # React dashboard
│   ├── src/
│   │   ├── AdminDashboard.js
│   │   ├── NormalUserDashboard.js
│   │   ├── App.js
│   │   ├── components/
│   │   └── hooks/
│   └── package.json
│
├── server/                   # Node.js + Express backend
│   ├── index.js              # Main server
│   ├── archiver.js           # Log archival module
│   ├── seed_mitre.js         # MITRE ATT&CK DB seeder
│   └── package.json
│
├── database/
│   └── init.sql              # PostgreSQL schema
│
├── ml_services/              # Python ML anomaly detection
│   ├── app.py                # Flask REST API
│   ├── train.py              # Model training script
│   └── requirements.txt      # Python dependencies
│
├── agents/                   # Native monitoring agents (optimized, low-resource)
│   ├── app_tracker/          # App activity tracker (processes, browser tabs, active window changes)
│   │   └── app_tracker.py
│   └── system_monitor/       # System health, resources, hardware logs, and offline SQL cache
│       ├── main.py           # Entry point
│       └── config.py         # Agent configuration
│
├── start-all.js              # Unified process orchestrator
├── .env                      # Global environment config (created on installation)
└── package.json              # Root script definitions
```

---

## 🚀 How to Run (One-Click Launch)

This project has been orchestrated for a seamless, professional launch during demonstrations.

### Prerequisites:
- **Node.js 18+**
- **PostgreSQL** (running locally on port 5432)
- **Python 3.10+**

### Step 1: Configuration (.env)
Create a `.env` file in the **root directory** (a template configuration is provided below). 

```env
# ==========================================
# SIEM Watchtower - Global Configuration
# ==========================================

# 1. ADMIN USER CONFIGURATION
# Set your email address as the Super Admin of the SIEM Dashboard.
SUPER_ADMIN_EMAIL=your_email@gmail.com
REACT_APP_SUPER_ADMIN_EMAIL=your_email@gmail.com

# 2. EMAIL ALERT SERVICE (Nodemailer)
# Used by the backend to send automated threat reports and panic signals.
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_app_password

# 3. DATABASE CONFIGURATION (Optional - defaults used if commented out)
# DB_USER=postgres
# DB_HOST=localhost
# DB_NAME=siem-watchtower
# DB_PASS=your_postgres_password
# DB_PORT=5432
```

### Step 2: Launch the System
Open a terminal in the root directory and run:
```bash
npm start
```

This single command triggers the unified launcher (`start-all.js`) which automatically:
1. Validates the database connection.
2. Synchronizes scripts executable permissions.
3. Sets up the Python virtual environment (`ml_services/venv`) and installs packages.
4. Trains/compiles ML models if missing.
5. Terminates stale background agent processes.
6. Launches the Express Backend (Port 5000), Python ML Service (Port 5001), React Frontend (Port 3000), and Background monitoring agents concurrently.

*The dashboard will automatically open in your browser at `http://localhost:3000` once compilation finishes.*

---

## ⚔️ How to Simulate an Attack (For Demo)

To demonstrate the SIEM actively blocking and tagging threats:

### 1. Simulate a Brute-Force Login Alert
Open a new terminal and POST a mock compromised log directly to the telemetry receiver:
```bash
curl -X POST http://localhost:5000/api/agent/log \
-H "Content-Type: application/json" \
-d "{\"event_type\":\"Authentication\",\"user_action\":\"LOGIN_FAILED\",\"application_name\":\"ssh\",\"severity\":\"WARN\",\"user_id\":\"123456\",\"hostname\":\"DESKTOP\"}"
```
*Result:* The dashboard will instantly flag an **Active Threat** and map it to MITRE T1110.

### 2. Simulate Web Activity Anomaly (ML Spike)
Open Developer Console in the dashboard or click any link repeatedly to generate high traffic.
*Result:* The Python Isolation Forest will score the heavy behavior and trigger a potential behavioral alert in the Alerts tab.

---

## 🚦 System Limitations & HA Fallbacks

**System Constraints (Current Limits):**
*   *Storage Indexing:* For massive enterprise deployments (>10M logs/day), the PostgreSQL relational database should be replaced with a NoSQL Time-Series indexer like Elasticsearch.

**High Availability (Fault Tolerance Fallbacks):**
*   **Microservice Decoupling:** The ML anomaly detection is an isolated Python Flask service. 
*   **Deterministic Fallback Safety:** If the ML API crashes, the Node.js backend features a hardcoded fallback. It automatically falls back to processing logs through a highly optimized Regex-Rule Engine, ensuring 100% SIEM availability even during analytic failures.

---

## 🧑‍💻 Author

Built as a Final Year Project (FYP) — SIEM system with ML anomaly detection, MITRE ATT&CK integration, and real-time monitoring.
