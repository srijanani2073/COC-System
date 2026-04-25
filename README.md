# COC-System
Graph-Based Digital Evidence Chain-of-Custody System With Cryptographic Integrity Verification

[DEMO SITE](https://coc-system.vercel.app/)

A full-stack forensic evidence management platform built for investigative teams. ECMS handles the complete lifecycle of digital and physical evidence — from upload and cryptographic sealing, through every custody transfer, to court-ready reports — while maintaining a tamper-evident audit trail across three independent databases.

---

## What it does

- **Manages cases and evidence** with auto-generated evidence codes (`011D01`, `011P02-v3`)
- **Encrypts every file** on upload using AES-256-CBC with per-item keys derived via HKDF — no key is ever stored
- **Signs every file hash** with RSA-2048 so any tampering is detectable on demand
- **Tracks chain of custody** across PostgreSQL, MongoDB, and Neo4j simultaneously
- **Visualises custody chains** as interactive graphs (vis.js)
- **Detects anomalies** — custody gaps, cycles, suspicious transfer patterns
- **Generates case reports** pulling data from all three databases

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Relational DB | PostgreSQL (via Supabase) |
| Audit / Metadata | MongoDB Atlas |
| Graph / Custody | Neo4j Aura |
| File Storage | Supabase Storage (encrypted blobs) |
| Cryptography | PyCryptodome — AES-256-CBC, RSA-2048, HKDF-SHA256, SHA-256 |
| Auth | bcrypt password hashing, role-based access control |
| Deployment | Vercel (serverless) |

---

## Architecture

The platform uses three databases intentionally — each chosen for what it does best:

**PostgreSQL** — source of truth for structured data: users, roles, cases, evidence records, chain-of-custody logs.

**MongoDB** — append-only audit and metadata store: every action (login, upload, transfer, verification) is logged as a document. Collections include `audit_logs`, `case_activity_logs`, `evidence_metadata`, `evidence_versions`, `login_attempts`, `security_alerts`.

**Neo4j** — graph database for custody chains. Evidence, users, and custody events are nodes; relationships like `HAS_EVIDENCE`, `HAS_CUSTODY_EVENT`, `UPLOADED`, and `CREATED` make complex custody queries trivial and enable anomaly detection that would be expensive in SQL.

---

## Cryptographic pipeline

Every evidence file goes through this pipeline on upload:

```
File bytes
    │
    ▼
SHA-256 hash (streaming, 8 KB chunks)
    │
    ▼
HKDF-SHA256(MASTER_SECRET, salt=evidence_id) → 32-byte AES key
    │
    ▼
AES-256-CBC encrypt (random IV prepended to ciphertext)
    │
    ▼
RSA-2048 sign the SHA-256 hash (PKCS#1 v1.5)
    │
    ├──▶ Encrypted bytes → Supabase Storage
    ├──▶ Hash + Signature → PostgreSQL
    └──▶ Metadata → MongoDB
```

**Key insight:** no AES key is ever stored. Keys are re-derived deterministically on demand from `MASTER_SECRET + evidence_id`. Verification re-downloads the encrypted blob, re-derives the key, decrypts, recomputes the hash, and checks the RSA signature. A single tampered byte anywhere in the chain causes verification to fail.

---

## Features

### Evidence management
- Digital and physical evidence types
- Auto-versioning — re-uploading a file creates a new version (`-v2`, `-v3`) rather than overwriting
- Duplicate detection via SHA-256 before storage
- Seal / unseal workflow — sealed evidence cannot be transferred
- Time-limited signed download URLs via Supabase Storage

### Chain of custody
- Every transfer written to PostgreSQL, MongoDB, and Neo4j simultaneously
- Interactive graph visualisation per evidence item
- Gap detection (evidence with no custody record for a period)
- Cycle detection (evidence returned to a prior holder without explanation)

### Analytics
- Evidence statistics by type, case, time period
- Transfer frequency analysis
- Suspicious pattern detection
- Activity heatmap by user and hour
- Risk profiles per case and user

### Access control

| Role | Access |
|---|---|
| Admin | Full access — user management, all cases, system alerts |
| Investigator | Case creation, evidence upload/seal, custody transfer, analytics |
| Viewer | Read-only — cases, evidence, custody chains, reports |

---

## Project structure

```
ecms/
├── app.py                        # Flask app, template filters, decorators
├── vercel.json                   # Vercel deployment config
├── requirements.txt
│
├── routes/
│   ├── auth.py                   # Login / logout (bcrypt + legacy migration)
│   ├── cases.py                  # Case CRUD, access grants
│   ├── evidence.py               # Upload pipeline, seal, verify, versioning
│   ├── custody.py                # Custody transfers, graph API
│   ├── analytics.py              # Analytics REST endpoints
│   ├── other.py                  # Dashboard, timeline, reports, alerts, users
│   ├── neo4j_explorer.py         # Raw Cypher query interface
│   ├── evidence_versioning.py    # MongoDB version helpers
│   ├── new_routes.py             # Crypto pipeline UI
│   ├── experiments.py            # Simulation runner
│   └── demo_guard.py             # Read-only demo middleware
│
├── cyber/
│   ├── crypto_pipeline.py        # AES-256, RSA-2048, HKDF, SHA-256
│   ├── integrity_engine.py       # Verification engine (on-demand + bulk)
│   ├── analytics.py              # Graph analytics, anomaly detection, risk scoring
│   └── query_interface.py        # Multi-model query interface (SQL + graph)
│
├── dbs/
│   ├── sql_db.py                 # PostgreSQL connection
│   ├── mongo_db.py               # MongoDB client and helpers
│   ├── neo4j_db.py               # Neo4j driver, node/edge helpers
│   └── supabase_storage.py       # Encrypted file upload/download
│
├── templates/                    # Jinja2 HTML templates
├── static/                       # CSS
└── keys/                         # RSA key pair — never committed
```

---

## Local setup

**Prerequisites:** Python 3.10+, active PostgreSQL, MongoDB Atlas, Neo4j Aura, and Supabase project.

```bash
git clone <repo-url> && cd ecms
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
DATABASE_URL=your_postgres_connection_string
MONGO_URI=your_mongodb_atlas_uri
NEO4J_URI=your_neo4j_aura_bolt_uri
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_anon_or_service_key
ECMS_MASTER_SECRET=a-long-random-secret-change-this
```

Run:

```bash
python app.py
# → http://localhost:5001
```

The RSA key pair is auto-generated in `keys/` on first run if not present.

---


## The repo ships with a read-only demo mode. All write operations are blocked while the full UI remains visible.

The login page will auto-fill the demo credentials. Visitors can browse everything but cannot modify any data.

For full working project, mail: srijanani.amrita@gmail.com
