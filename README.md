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
Overseer/
├── overseer_engine.py               # Core AI detection engine — REST API server
│                                    #   · Trains ensemble: Random Forest + Gradient Boost + Autoencoder
│                                    #   · Exposes /predict, /predict_demo, /stats, /health endpoints
│                                    #   · XAI: top-10 feature importance per prediction
│                                    #   · SOAR: automated response actions on high-confidence threats
│
├── overseer_dashboard.html          # Real-time browser dashboard (zero dependencies)
│                                    #   · Live threat feed, attack family breakdown, SOAR action log
│                                    #   · Polls overseer_engine REST API every 2 s
│
├── parrot_bridge.py                 # Live traffic sensor for Parrot OS (attacker VM)
│                                    #   · Scapy packet sniffer on enp0s3 (host-only network)
│                                    #   · Detects: Port Scan, DoS/DDoS, Brute Force,
│                                    #     Root Shell, IP Spoofing, DNS Tunneling
│                                    #   · Real iptables blocking on detection (SOAR)
│                                    #   · Forwards scored flows to overseer_engine via /predict
│
├── pcap_bridge.py                   # Live traffic sensor for Windows host
│                                    #   · Scapy/WinPcap sniffer (hardcoded VirtualBox NIC GUID)
│                                    #   · Mirrors Parrot → Metasploitable traffic
│                                    #   · Forwards KDD99-compatible feature vectors to /predict
│
├── find_iface.py                    # Windows utility — lists all WinPcap interfaces
│                                    #   · Run once to find the correct GUID for pcap_bridge.py
│
├── attack_scripts.sh                # Attack simulation suite (run on Parrot OS)
│                                    #   · Scenarios: dos · scan · brute · sqli · shell · all
│                                    #   · Tools: nmap, hping3, hydra, sqlmap, netcat, Metasploit
│
├── overseer_setup.sh                # One-shot environment setup script
│                                    #   · Installs Python deps + attack tools via apt
│                                    #   · Auto-detects host-only NIC, starts tcpdump capture
│
├── kdd99_10percent.csv              # KDD Cup 99 dataset (10 % subset, ~494 K records)
│                                    #   · Training data for the ensemble models
│                                    #   · Auto-generated synthetically if download fails
│
└── overseer_models.pkl              # Serialised trained models (auto-created by --train)
                                     #   · Contains: RF, GB, Autoencoder, family classifier, scaler
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
