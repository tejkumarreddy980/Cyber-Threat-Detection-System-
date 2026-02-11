# Cyber Threat Detection System (Intrusion Detection)

A starter implementation of a **real-time cyber threat detection platform** that inspects network-flow-like events and uses machine learning to flag anomalous behavior.

## Project Goal

Develop a tool that monitors traffic telemetry in near real-time, applies ML-based anomaly detection, and surfaces possible intrusions for investigation.

## Current Stack (MVP)

- **Backend/API:** Python + Flask
- **ML Engine:** scikit-learn (Isolation Forest)
- **Databases:** PostgreSQL + MongoDB (via Docker services)
- **DevOps:** Docker + Docker Compose

> You mentioned Node.js, Go, Django/Flask, React/Next/Flutter, and AWS. This repo now provides a clean Flask-based backend MVP that can be expanded with those technologies incrementally.

## Architecture

```text
[Traffic Source / Flow Collector]
            |
            v
      [Flask API]
         /     \
        v       v
 [ML Detector] [Alert/Metadata Storage]
                    |           |
                    v           v
               PostgreSQL     MongoDB
```

### API Endpoints

- `GET /health` — health probe
- `POST /detect` — classify one flow object
- `POST /detect/batch` — classify multiple flow objects

## Quick Start

### Option 1: Docker Compose (recommended)

```bash
docker compose up --build
```

API is then available at: `http://localhost:8000`

### Option 2: Local Python run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python -m backend.app
```

## Example Requests

### Health

```bash
curl http://localhost:8000/health
```

### Single Detection

```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "flow": {
      "duration": 1.8,
      "src_bytes": 1500,
      "dst_bytes": 830,
      "packets": 22,
      "failed_logins": 0,
      "dst_port": 443
    }
  }'
```

### Batch Detection

```bash
curl -X POST http://localhost:8000/detect/batch \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [
      {"duration": 2.0, "src_bytes": 1800, "dst_bytes": 1200, "packets": 26, "failed_logins": 0, "dst_port": 443},
      {"duration": 0.1, "src_bytes": 5, "dst_bytes": 3, "packets": 5000, "failed_logins": 3, "dst_port": 9999}
    ]
  }'
```

## Data Model (Flow Features)

The detector currently uses these numerical features:

- `duration`
- `src_bytes`
- `dst_bytes`
- `packets`
- `failed_logins`
- `dst_port`

## Roadmap

1. Add packet capture integration (Zeek/Suricata/pcap pipeline).
2. Persist detections and confidence trends to PostgreSQL.
3. Store raw event blobs and enrichment metadata in MongoDB.
4. Add role-based dashboard frontend (React or Next.js).
5. Add streaming support via Kafka or Redis Streams.
6. Deploy to AWS (ECS/Fargate or EKS) with CloudWatch alerts.
7. Add model retraining pipeline and drift monitoring.

## Test

```bash
python -m pytest -q
```

---

If you'd like, I can scaffold the **next layer** too (React dashboard + persistent alerts + AWS-ready deployment manifests).
