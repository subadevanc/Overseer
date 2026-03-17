# OverSeer — Flaggers United
### Adaptive AI-Driven Cybersecurity Architecture
**Version 1.0 · Classification: Confidential**

---

## Overview

OverSeer is an enterprise-grade, fully adaptive AI cybersecurity platform that detects,
analyses, and automatically contains complex multi-stage threats in continuously evolving
network environments. It combines deep learning anomaly detection, graph-based lateral
movement analysis, concept drift adaptation, and real-time global threat intelligence.

---

## Project Structure

```
overseer/
├── main.py                          # Pipeline orchestrator — entry point
├── requirements.txt
│
├── config/
│   └── settings.py                  # All thresholds, weights, API keys, DSNs
│
├── core/
│   ├── models.py                    # Shared typed dataclasses & enums
│   ├── ingestion.py                 # Packet capture + feature extraction
│   └── risk_scoring.py              # Weighted signal aggregation engine
│
├── detection/
│   ├── anomaly_detector.py          # Keras autoencoder (sklearn fallback)
│   ├── drift_detector.py            # ADWIN + auto-retraining manager
│   └── graph_analyzer.py            # Dynamic attack graph + centrality
│
├── intelligence/
│   └── threat_intel.py              # VirusTotal / AbuseIPDB / OTX / GreyNoise
│
├── containment/
│   └── containment_engine.py        # iptables / nftables automated response
│
├── storage/
│   └── storage_layer.py             # Elasticsearch / Neo4j / PostgreSQL / Redis
│
├── dashboard/
│   └── app.py                       # Streamlit real-time security dashboard
│
├── tests/
│   └── test_pipeline.py             # 30 unit tests (pytest)
│
├── models/                          # Saved model checkpoints (auto-created)
└── logs/                            # Rotating log files (auto-created)
```

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set API Keys
```bash
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export OTX_API_KEY="your_key"
export GREYNOISE_API_KEY="your_key"
```

### 3. Configure Storage (optional for demo)
```bash
export ES_HOST="localhost"
export NEO4J_URI="bolt://localhost:7687"
export POSTGRES_DSN="postgresql://user:pass@localhost:5432/overseer_db"
export REDIS_HOST="localhost"
```

### 4. Run the Pipeline
```bash
# Simulate mode (no live capture, no root required)
python main.py --simulate

# Live capture (requires root / CAP_NET_RAW)
sudo python main.py

# Train model only, then exit
python main.py --train-only --warmup 2000

# Dry-run containment (log actions, no firewall changes)
python main.py --simulate --dry-run
```

### 5. Launch the Dashboard
```bash
streamlit run dashboard/app.py --server.port 8501
# Open http://localhost:8501
```

### 6. Run Tests
```bash
pytest tests/ -v
# Expected: 30 passed
```

---

## Architecture Pipeline

```
Network Traffic
      ↓
Packet Capture          (scapy / synthetic fallback)
      ↓
Feature Extraction      (7 features per event window)
      ↓
Anomaly Detection       (Keras Autoencoder / IsolationForest)
      ↓
Drift Detection         (ADWIN → auto-retraining)
      ↓
Graph Attack Analysis   (NetworkX — degree/betweenness/PageRank)
      ↓
Threat Intelligence     (VirusTotal · AbuseIPDB · OTX · GreyNoise)
      ↓
Risk Scoring            (weighted: 40% ML + 20% Graph + 25% VT + 15% Abuse)
      ↓
Automated Containment   (block IP · isolate device · restrict routing)
      ↓
Storage                 (Elasticsearch · Neo4j · PostgreSQL · Redis)
      ↓
Streamlit Dashboard
```

---

## Risk Score Bands

| Score Range | Threat Level | Auto-Actions |
|-------------|-------------|--------------|
| ≥ 0.85      | CRITICAL    | Block IP + Isolate Device + Restrict Routing |
| 0.70 – 0.85 | HIGH        | Block IP |
| 0.45 – 0.70 | MEDIUM      | Alert only |
| 0.20 – 0.45 | LOW         | Log only |
| < 0.20      | SAFE        | — |

---

## Configuration Reference (`config/settings.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `reconstruction_error_threshold` | `0.35` | Autoencoder anomaly threshold |
| `adwin_delta` | `0.002` | ADWIN sensitivity (lower = more sensitive) |
| `retraining_cooldown_seconds` | `300` | Min seconds between retrains |
| `auto_block_threshold` | `0.85` | Risk score to trigger IP block |
| `auto_isolate_threshold` | `0.90` | Risk score to trigger device isolation |
| `weight_ml_anomaly` | `0.40` | ML signal weight in risk score |
| `weight_virustotal` | `0.25` | VirusTotal weight in risk score |
| `dry_run` | `False` | Set True to simulate containment |

---

## Feature Reference

| Feature | Description |
|---------|-------------|
| `connection_count` | Outbound connections per window |
| `packet_rate` | Packets per second |
| `dns_requests` | DNS queries from host |
| `process_spawn_rate` | New processes per minute |
| `login_attempts` | Total auth attempts |
| `failed_logins` | Failed auth count |
| `unique_destinations` | Unique destination IPs |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| Packet Capture | Scapy |
| Feature Processing | Pandas / NumPy |
| ML — Anomaly Detection | TensorFlow/Keras Autoencoder |
| ML — Fallback | Scikit-learn IsolationForest |
| Graph Analysis | NetworkX |
| Drift Detection | ADWIN (pure Python) |
| Threat Intelligence | VirusTotal · AbuseIPDB · OTX · GreyNoise |
| Log Storage | Elasticsearch |
| Graph Storage | Neo4j |
| Feature Storage | PostgreSQL |
| IoC Cache | Redis |
| Dashboard | Streamlit + Plotly |
| Containment | Python + iptables/nftables |

---

## Planned Enhancements (v2.0)

- Graph Neural Networks (GNNs) for richer attack path modelling
- Apache Kafka + Flink for large-scale streaming analytics
- Reinforcement learning for automated attack prediction
- SOAR platform integration (Splunk SOAR, Palo Alto XSOAR)
- Federated learning for multi-tenant threat intelligence sharing

---

*OverSeer Flaggers United · Confidential · v1.0*
