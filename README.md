# 🛡️ SENTINEL AI-SOC

> **AI-Powered Security Operations Center** — Real-time threat detection, automated response, and executive-grade reporting, all in one dashboard.

Built for the **Plutonium Hackathon** · Dark/Light premium UI · Human-in-the-loop AI

---

## ✨ Features

| Capability | Description |
|---|---|
| **Live Threat Feed** | Real-time WebSocket event stream with instant IP/country/type filtering |
| **AI Threat Analyst** | Google Gemini-powered streaming analyst — ask anything about active threats |
| **Kill Chain Tracker** | Visualizes MITRE ATT&CK stages as attacks progress in real-time |
| **Attack Origins Map** | World map with animated hotspot dots pinpointing attack origins |
| **Behavioral Anomaly** | Baseline-based login anomaly detection with bar chart visualization |
| **Human-in-the-Loop** | Approve / deny AI-recommended response actions before execution |
| **Counterfactual Engine** | "What if we hadn't blocked this?" simulated breach impact analysis |
| **Auto Response** | IP blocking, rate limiting, account lockout — executed automatically |
| **Report Generation** | One-click Incident Reports & Board-ready Executive Summaries (PDF export) |
| **Dark / Light Theme** | Smooth animated theme toggle — both themes are premium quality |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  React Frontend (Vite)               │
│  Dashboard · Live Feed · AI Chat · Map · Reports     │
└────────────────────┬────────────────────────────────┘
                     │ WebSocket + REST
┌────────────────────▼────────────────────────────────┐
│              FastAPI Backend (Python)                │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │Simulator │  │Detection │  │  AI Analyst        │  │
│  │(events)  │  │(ML+rules)│  │  (Gemini 2.5 Flash)│  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │Response  │  │Intelligence│ │  NLP Classifier   │  │
│  │Engine    │  │(MITRE/IP) │  │  (DistilBERT)     │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
│                     │                                │
│              ┌──────▼──────┐                         │
│              │  SQLite DB  │                         │
│              └─────────────┘                         │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- API keys (see `.env.example`)

### 1. Clone & configure

```bash
git clone https://github.com/your-username/sentinel-ai-soc.git
cd sentinel-ai-soc

# Copy env template and fill in your keys
cp .env.example .env
# Edit .env with your GEMINI_API_KEY, ABUSEIPDB_API_KEY, TWILIO_* keys
```

### 2. Backend

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the backend (port 8001)
uvicorn api.main:app --host 0.0.0.0 --port 8001 --reload
```

### 3. Frontend

```bash
cd dashboard
npm install
npm run dev        # Dev server at http://localhost:5173
```

### 4. Open the dashboard

Navigate to **http://localhost:5173** — the backend must be running on port 8001.

---

## 🎭 Demo Scenarios

Run attack scenarios from the demo controller:

```bash
# Start a coordinated multi-vector attack
python demo/attack_controller.py

# Or run individual scenarios
python demo/scenarios.py
```

**Scenario types available:**
- Brute force credential attacks
- SQL injection campaigns
- C2 beacon (Command & Control)
- Phishing delivery
- Data exfiltration
- Full kill-chain breach simulation

---

## 📁 Project Structure

```
sentinel-ai-soc/
├── api/                  # FastAPI routes, WebSocket handler
├── analyst/              # Gemini AI analyst integration
├── db/                   # SQLAlchemy models & session
├── demo/                 # Attack demo scenarios
├── detection/            # ML anomaly detection engine
├── intelligence/         # MITRE mapping, IP reputation, risk scoring
├── models/               # Pydantic event models
├── nlp/                  # DistilBERT phishing classifier
├── notifications/        # Twilio SMS alerts
├── response/             # Automated response engine & playbooks
├── simulator/            # Synthetic event generator
├── dashboard/            # React + TypeScript frontend
│   ├── src/
│   │   ├── App.tsx       # Main application component
│   │   ├── styles.css    # Premium dark/light theme
│   │   └── hooks/        # useSocStream, useAnalystStream
│   └── ...
├── .env.example          # Environment variable template
├── requirements.txt      # Python dependencies
└── README.md
```

---

## 🔑 API Keys Required

| Service | Purpose | Get it at |
|---|---|---|
| **Google Gemini** | AI threat analyst | [aistudio.google.com](https://aistudio.google.com/app/apikey) |
| **AbuseIPDB** | IP reputation scoring | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| **Twilio** *(optional)* | SMS alerts | [console.twilio.com](https://console.twilio.com) |

---

## 🛠️ Tech Stack

**Frontend:** React 18 · TypeScript · Vite · Recharts · React Simple Maps · Chart.js

**Backend:** FastAPI · Python 3.11 · SQLAlchemy · WebSockets · Uvicorn

**AI/ML:** Google Gemini 2.5 Flash · DistilBERT (HuggingFace) · Scikit-learn

**Integrations:** AbuseIPDB · MITRE ATT&CK · Twilio · jsPDF

---

## 📄 License

MIT — built with ❤️ for the Plutonium Hackathon.
