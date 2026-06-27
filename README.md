# TrustGrid

> Federated Fraud Detection — Collaborative. Private. Decentralised.

TrustGrid is a multi-node fraud detection system where banks collaborate to detect fraud **without sharing raw transaction data**. Each participant uploads their own dataset. The system combines signals across nodes and produces a final fraud decision — no single participant can determine this independently.

---

## How It Works

```
Bank Alpha          Bank Beta           Bank Gamma
    │                   │                   │
    ▼                   ▼                   ▼
Upload CSV          Upload CSV          Upload CSV
    │                   │                   │
    ▼                   ▼                   ▼
Local analysis      Local analysis      Local analysis
(FE-encrypted)      (FE-encrypted)      (FE-encrypted)
    │                   │                   │
    └───────────────────┼───────────────────┘
                        │
                        ▼
              TrustGrid Backend
           (combines signals only)
                        │
                        ▼
              FRAUD DETECTED / SAFE
```

No raw data ever leaves a node. Only processed signals (fraud flag, record count) are combined. Transaction features are encrypted with the FE public key (`mpk`), while only the trusted server keeps the master secret key (`msk`) needed to derive function keys.

---

## Features

- **Federated architecture** — each node analyzes its own data locally
- **Privacy-preserving** — public-key functional encryption for transaction features
- **Collaborative decision** — global fraud verdict requires ≥2 nodes
- **24-hour data window** — stale data is excluded from global analysis
- **Per-IP node enforcement** — prevents one user from faking multiple nodes
- **AI-generated reports** — PDF reports with Gemma 4 narrative via Ollama
- **Case memory** — all past global decisions are stored and viewable
- **Auto-refresh** — dashboard polls backend every 15–20 seconds

---

## Fraud Detection Rules

| Rule | Condition | Result |
|------|-----------|--------|
| High amount | `amount > 10,000` | 🔴 FRAUD |
| Night transaction | `hour < 5 AM` | 🔴 FRAUD |
| Global decision | fraud rate `> 5%` | 🔴 FRAUD DETECTED |

---

## Project Structure

```
trustgrid/
├── app.py                  # Entry point — Flask app factory
├── config.py               # All configuration in one place
├── requirements.txt        # Python dependencies
├── .gitignore
│
├── routes/                 # Flask blueprints (one per feature area)
│   ├── auth.py             # /register, /login, /reset_key
│   ├── data.py             # /upload, /analyze, /clear_data
│   ├── analysis.py         # /results, /global_analysis, /logs, /nodes, /outcomes
│   └── report.py           # /report (PDF download)
│
├── utils/                  # Pure helper functions (no Flask dependency)
│   ├── crypto.py           # General hashing helpers
│   ├── functional_encryption.py  # FE setup, mpk/msk helpers, ciphertext handling
│   ├── fraud.py            # Fraud detection rules
│   └── pdf.py              # PDF generation + Ollama narrative
│
├── database/
│   └── schema.py           # DB connection + table creation
│
├── frontend/
│   └── index.html          # Single-page frontend
│
├── sample_data/
│   └── sample_transactions.csv
│
├── tests/                  # pytest test suite
│   ├── test_crypto.py
│   ├── test_fraud.py
│   └── test_api.py
│
└── docs/
    ├── API.md              # Full API reference
    └── SETUP.md            # Local setup guide
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/your-username/trustgrid.git
cd trustgrid

# 2. Install dependencies
pip install -r requirements.txt

# 3. Pull the AI model (optional — needed for PDF reports)
ollama pull gemma4:e4b

# 4. Start backend
python app.py

# 5. Open frontend/index.html in your browser
```

Full setup instructions → [`docs/SETUP.md`](docs/SETUP.md)

---

## API Reference

Full documentation → [`docs/API.md`](docs/API.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Register a new node |
| POST | `/login` | Login to existing node |
| POST | `/reset_key` | Reset key using company name |
| POST | `/upload` | Upload CSV dataset |
| POST | `/analyze` | Run fraud detection |
| GET | `/results` | Per-node fraud summary |
| GET | `/global_analysis` | Collaborative fraud decision |
| GET | `/logs` | Recent hashed activity |
| GET | `/nodes` | All registered nodes |
| GET | `/outcomes` | Past fraud decisions |
| GET | `/report` | Download PDF report |

---

## Running Tests

```bash
pytest tests/ -v
```

Tests use a temporary in-memory database and do not affect production data.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, Flask-CORS |
| Database | SQLite (via sqlite3) |
| Data processing | pandas |
| Privacy | PyMIFE `FeDamgard` public-key functional encryption |
| PDF generation | ReportLab |
| AI narrative | Ollama + Gemma 4 (gemma4:e4b) |
| Frontend | Vanilla HTML/CSS/JS |

---

## Research Context

TrustGrid is developed as part of the **GraphShield** research project at UPES under the SHODH Research Grant, focused on graph-based cognitive firewalls for real-time fraud and phishing detection.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
