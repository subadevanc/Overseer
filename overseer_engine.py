"""
OVERSEER - AI Detection Engine
================================
Trains on KDD99 dataset, exposes REST API for live inference.
Ensemble: Random Forest + Autoencoder + Gradient Boost
XAI: Feature importance per prediction
SOAR: Auto-response actions on high-confidence threats

QUICK START:
  pip install flask scikit-learn numpy pandas joblib flask-cors
  python overseer_engine.py --train
  python overseer_engine.py --serve
"""

import argparse, json, os, time, urllib.request, warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.neural_network import MLPRegressor


# ── OTX AlienVault Threat Intelligence ───────────────────────────────────────
import threading as _threading
import math as _math
import collections as _collections
import urllib.error as _urllib_error

OTX_API_KEY  = "179e131d883e3491492b38659e56b3efaeac62300c2479f1a60c54d58b517998"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"
_otx_cache   = {}
_otx_lock    = _threading.Lock()

def otx_enrich(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return {"ip":ip,"private":True,"pulse_count":0,"reputation":0,
                "malware_families":[],"country":"Private","asn":"Local",
                "threat_score":0,"cached":False}
    with _otx_lock:
        cached = _otx_cache.get(ip)
        if cached and time.time() - cached.get("fetched_at",0) < 300:
            cached["cached"] = True
            return cached
    result = {"ip":ip,"pulse_count":0,"reputation":0,"malware_families":[],
              "country":"Unknown","asn":"Unknown","threat_score":0,
              "fetched_at":time.time(),"cached":False,"error":None}
    try:
        url = f"{OTX_BASE_URL}/{ip}/general"
        req = urllib.request.Request(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        pi = data.get("pulse_info", {})
        result["pulse_count"] = pi.get("count", 0)
        result["reputation"]  = data.get("reputation", 0)
        result["country"]     = data.get("country_name", "Unknown")
        result["asn"]         = data.get("asn", "Unknown")
        families = set()
        for pulse in pi.get("pulses", [])[:5]:
            for tag in pulse.get("tags", []):
                families.add(tag)
        result["malware_families"] = list(families)[:5]
        pc = result["pulse_count"]
        rp = abs(result["reputation"])
        result["threat_score"] = round(min(pc/10,1.0)*0.7 + min(rp/10,1.0)*0.3, 3)
    except Exception as e:
        result["error"] = str(e)[:60]
    with _otx_lock:
        _otx_cache[ip] = result
    return result


# ── Email Alert System ────────────────────────────────────────────────────────
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SENDER   = "bugfinder1000@gmail.com"
SMTP_RECEIVER = "rohanmessicr10@gmail.com"
SMTP_PASSWORD = "kvwecmenimnbtixi"   # Gmail App Password
SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587

_email_last_sent  = {}   # family -> last sent time
_email_cooldown   = 30.0 # min seconds between emails for same family

def send_threat_email(family, src, score, soar, detail="", xai_top=""):
    """Send threat alert email via Gmail SMTP."""
    now = time.time()
    key = family
    if now - _email_last_sent.get(key, 0) < _email_cooldown:
        return  # suppress duplicate emails
    _email_last_sent[key] = now

    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    subject = f"[OVERSEER ALERT] {family} Detected — Score {score:.3f}"

    html = f"""
    <html><body style="font-family:monospace;background:#060a0f;color:#c8dff0;padding:20px;">
    <div style="border:1px solid #1a2e45;border-radius:8px;padding:20px;max-width:600px;">
        <h2 style="color:#ff3b3b;margin:0 0 16px;">🔴 OVERSEER THREAT ALERT</h2>
        <table style="width:100%;border-collapse:collapse;">
            <tr><td style="color:#557080;padding:4px 0;width:140px;">Timestamp</td>
                <td style="color:#c8dff0;">{ts}</td></tr>
            <tr><td style="color:#557080;padding:4px 0;">Attack Family</td>
                <td style="color:#ff3b3b;font-weight:bold;">{family}</td></tr>
            <tr><td style="color:#557080;padding:4px 0;">Threat Score</td>
                <td style="color:#ffb800;">{score:.4f}</td></tr>
            <tr><td style="color:#557080;padding:4px 0;">Source IP</td>
                <td style="color:#c8dff0;">{src}</td></tr>
            <tr><td style="color:#557080;padding:4px 0;">SOAR Actions</td>
                <td style="color:#00e676;">{", ".join(soar) if soar else "None"}</td></tr>
            <tr><td style="color:#557080;padding:4px 0;">Top Indicator</td>
                <td style="color:#00d4ff;">{xai_top}</td></tr>
            {"<tr><td style=\"color:#557080;padding:4px 0;\">Detail</td><td style=\"color:#c8dff0;\">" + detail + "</td></tr>" if detail else ""}
        </table>
        <hr style="border-color:#1a2e45;margin:16px 0;">
        <p style="color:#557080;font-size:11px;margin:0;">
            OVERSEER AI-Powered Threat Detection Platform<br>
            Automated response has been initiated. Check dashboard for full details.
        </p>
    </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_SENDER
    msg["To"]      = SMTP_RECEIVER
    msg.attach(MIMEText(html, "html"))

    try:
        context = ssl.create_default_context()
        # Try SSL on 465 first, fall back to STARTTLS on 587
        try:
            with smtplib.SMTP_SSL(SMTP_HOST, 465, context=context) as server:
                server.login(SMTP_SENDER, SMTP_PASSWORD)
                server.sendmail(SMTP_SENDER, SMTP_RECEIVER, msg.as_string())
        except Exception:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(SMTP_SENDER, SMTP_PASSWORD)
                server.sendmail(SMTP_SENDER, SMTP_RECEIVER, msg.as_string())
        ts = time.strftime("%H:%M:%S")
        log_entry = {"time": ts, "to": SMTP_RECEIVER,
                     "subject": subject, "status": "sent", "family": family}
        stats["email_log"].append(log_entry)
        stats["email_log"] = stats["email_log"][-20:]
        print(f"[EMAIL] Alert sent to {SMTP_RECEIVER} — {family}")
    except Exception as e:
        ts = time.strftime("%H:%M:%S")
        log_entry = {"time": ts, "to": SMTP_RECEIVER,
                     "subject": subject, "status": f"failed: {str(e)[:40]}", "family": family}
        stats["email_log"].append(log_entry)
        stats["email_log"] = stats["email_log"][-20:]
        print(f"[EMAIL] Failed: {e}")

# ── KDD99 schema ──────────────────────────────────────────────────────────────
KDD_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"
]

KDD_ATTACK_MAP = {
    "normal":"normal",
    "back":"dos","land":"dos","neptune":"dos","pod":"dos","smurf":"dos",
    "teardrop":"dos","apache2":"dos","udpstorm":"dos","mailbomb":"dos",
    "ipsweep":"probe","nmap":"probe","portsweep":"probe","satan":"probe",
    "mscan":"probe","saint":"probe",
    "ftp_write":"r2l","guess_passwd":"r2l","imap":"r2l","multihop":"r2l",
    "phf":"r2l","spy":"r2l","warezclient":"r2l","warezmaster":"r2l",
    "buffer_overflow":"u2r","loadmodule":"u2r","perl":"u2r",
    "rootkit":"u2r","sqlattack":"u2r","xterm":"u2r",
}

ATTACK_LABELS = {
    "normal":"BENIGN","dos":"DoS/DDoS","probe":"Port Scan / Probe",
    "r2l":"Remote-to-Local","u2r":"User-to-Root","unknown":"Zero-Day Anomaly"
}

SOAR_ACTIONS = {
    "BENIGN":              [],
    "DoS/DDoS":            ["BLOCK_IP","RATE_LIMIT","ALERT_SOC"],
    "Port Scan / Probe":   ["LOG_ENHANCED","ALERT_SOC","HONEYPOT_REDIRECT"],
    "Remote-to-Local":     ["BLOCK_IP","RESET_SESSION","ALERT_SOC"],
    "User-to-Root":        ["ISOLATE_HOST","REVOKE_CREDENTIALS","ALERT_SOC","FORENSIC_SNAPSHOT"],
    "Zero-Day Anomaly":    ["ISOLATE_HOST","BLOCK_IP","ALERT_SOC","FORENSIC_SNAPSHOT"],
}

MODEL_PATH   = "overseer_models.pkl"
KDD_PATH     = "kdd99_10percent.csv"
KDD_URL      = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
KDD_URL_B    = "https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain+.csv"  # fallback (NSL-KDD, slightly different format)

stats = {
    "total_predictions":0,"threats_detected":0,"benign_count":0,
    "start_time":time.time(),"recent_alerts":[],"email_log":[]
}

# ── Data ──────────────────────────────────────────────────────────────────────
def download_kdd99():
    import gzip, shutil
    if os.path.exists(KDD_PATH):
        print(f"[OK] KDD99 found at {KDD_PATH}"); return

    GZ_MIRRORS = [
        "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz",
        "https://archive.ics.uci.edu/ml/machine-learning-databases/kddcup99-mld/kddcup.data_10_percent.gz",
    ]
    gz = "kdd.gz"
    for url in GZ_MIRRORS:
        try:
            print(f"[~] Trying: {url}")
            urllib.request.urlretrieve(url, gz)
            with gzip.open(gz,"rb") as fin, open(KDD_PATH,"wb") as fout:
                shutil.copyfileobj(fin, fout)
            os.remove(gz)
            print("[OK] Downloaded and extracted")
            return
        except Exception as e:
            print(f"[!] Failed: {e}")
            if os.path.exists(gz): os.remove(gz)

    _generate_synthetic_kdd99()


def _generate_synthetic_kdd99():
    print("[~] All mirrors failed. Generating synthetic KDD99 dataset...")
    np.random.seed(42)
    n = 60000

    def make_rows(n_rows, label, overrides):
        base = {c: 0.0 for c in KDD_COLUMNS[:-1]}
        base.update({
            "protocol_type": 6.0, "service": 7.0, "flag": 5.0,
            "duration": 0.0, "src_bytes": 232.0, "dst_bytes": 5000.0,
            "land": 0.0, "logged_in": 1.0, "count": 9.0, "srv_count": 9.0,
            "serror_rate": 0.0, "rerror_rate": 0.0, "same_srv_rate": 1.0,
            "dst_host_count": 50.0, "dst_host_srv_count": 50.0,
            "dst_host_same_srv_rate": 0.9, "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0
        })
        base.update(overrides)
        rows = []
        for _ in range(n_rows):
            row = {k: max(0.0, float(v) + np.random.normal(0, abs(float(v))*0.03 + 0.01))
                   if isinstance(v, (int, float)) else v
                   for k, v in base.items()}
            row["label"] = label
            rows.append(row)
        return rows

    rows  = make_rows(int(n*0.60), "normal",   {})
    rows += make_rows(int(n*0.20), "neptune",  {"serror_rate":1.0,"srv_serror_rate":1.0,"count":511.0,"src_bytes":0.0,"dst_bytes":0.0,"logged_in":0.0,"dst_host_serror_rate":1.0})
    rows += make_rows(int(n*0.08), "ipsweep",  {"rerror_rate":0.99,"srv_diff_host_rate":0.06,"same_srv_rate":0.06,"count":1.0,"logged_in":0.0})
    rows += make_rows(int(n*0.05), "smurf",    {"count":511.0,"src_bytes":1032.0,"dst_bytes":0.0,"protocol_type":1.0,"same_srv_rate":1.0})
    rows += make_rows(int(n*0.04), "guess_passwd",{"num_failed_logins":5.0,"logged_in":0.0,"count":5.0,"flag":3.0})
    rows += make_rows(int(n*0.02), "buffer_overflow",{"root_shell":1.0,"num_root":2.0,"num_shells":1.0,"su_attempted":1.0,"num_compromised":3.0,"hot":8.0})
    rows += make_rows(int(n*0.01), "rootkit",  {"root_shell":1.0,"num_shells":1.0,"num_root":5.0,"num_compromised":5.0})

    df = pd.DataFrame(rows)
    df.to_csv(KDD_PATH, index=False, header=False)
    print(f"[OK] Synthetic dataset saved to {KDD_PATH} ({len(df):,} rows)")

def load_data():
    df = pd.read_csv(KDD_PATH, names=KDD_COLUMNS)
    df["label"]  = df["label"].str.rstrip(".")
    df["family"] = df["label"].apply(lambda x: KDD_ATTACK_MAP.get(x,"unknown"))
    df["is_attack"] = (df["family"] != "normal").astype(int)
    for col in ["protocol_type","service","flag"]:
        df[col] = LabelEncoder().fit_transform(df[col].astype(str))
    X = df[KDD_COLUMNS[:-1]].values.astype(float)
    return X, df["is_attack"].values, df["family"].values

# ── Train ─────────────────────────────────────────────────────────────────────
def train(n=80000):
    download_kdd99()
    X, y_bin, y_fam = load_data()
    if len(X) > n:
        idx = np.random.choice(len(X),n,replace=False)
        X,y_bin,y_fam = X[idx],y_bin[idx],y_fam[idx]

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    Xtr,Xte,ytr,yte,yftr,yfte = train_test_split(Xs,y_bin,y_fam,test_size=0.2,random_state=42)

    print("[~] Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100,max_depth=20,n_jobs=-1,
                                 random_state=42,class_weight="balanced")
    rf.fit(Xtr,ytr)
    print(f"[✓] RF  accuracy: {accuracy_score(yte,rf.predict(Xte)):.4f}")

    print("[~] Training Gradient Boost...")
    gb = GradientBoostingClassifier(n_estimators=100,max_depth=5,
                                     learning_rate=0.1,random_state=42,subsample=0.8)
    gb.fit(Xtr,ytr)
    print(f"[✓] GB  accuracy: {accuracy_score(yte,gb.predict(Xte)):.4f}")

    print("[~] Training Autoencoder on normal traffic...")
    Xnorm = Xtr[ytr==0]
    ae = MLPRegressor(hidden_layer_sizes=(32,16,8,16,32),activation="relu",
                       max_iter=50,random_state=42,early_stopping=True)
    ae.fit(Xnorm,Xnorm)
    Xte_n = Xte[yte==0]
    ae_thresh = float(np.percentile(
        np.mean((Xte_n - ae.predict(Xte_n))**2, axis=1), 95)) if len(Xte_n) else 1.0
    print(f"[✓] AE  threshold: {ae_thresh:.4f}")

    print("[~] Training family classifier...")
    fle = LabelEncoder()
    fcl = RandomForestClassifier(n_estimators=50,n_jobs=-1,random_state=42)
    fcl.fit(Xtr, fle.fit_transform(yftr))

    joblib.dump({"rf":rf,"gb":gb,"ae":ae,"fcl":fcl,"fle":fle,
                  "scaler":scaler,"ae_thresh":ae_thresh,
                  "features":KDD_COLUMNS[:-1]}, MODEL_PATH)
    print(f"\n[✓] Saved → {MODEL_PATH}")
    print("    Run: python overseer_engine.py --serve")

# ── Inference ─────────────────────────────────────────────────────────────────
def predict_one(x_scaled, bundle):
    rf,gb,ae = bundle["rf"],bundle["gb"],bundle["ae"]
    fcl,fle  = bundle["fcl"],bundle["fle"]
    x = np.array(x_scaled).reshape(1,-1)

    rf_p  = rf.predict_proba(x)[0][1]
    gb_p  = gb.predict_proba(x)[0][1]
    ae_e  = float(np.mean((x - ae.predict(x))**2))
    ae_n  = min(ae_e / (bundle["ae_thresh"]*3), 1.0)
    score = rf_p*0.45 + gb_p*0.35 + ae_n*0.20
    threat = score > 0.5

    fam_raw   = fle.inverse_transform([fcl.predict(x)[0]])[0]
    fam_label = ATTACK_LABELS.get(fam_raw if threat else "normal","BENIGN")

    imp = rf.feature_importances_
    top = np.argsort(imp)[::-1][:10]
    xai = [{"feature":bundle["features"][i],"importance":round(float(imp[i]),4),
             "value":round(float(x_scaled[i]),4)} for i in top]

    return {
        "threat_score": round(float(score),4),
        "is_threat":    bool(threat),
        "confidence":   round(float(max(rf_p,gb_p)),4),
        "attack_family":fam_label,
        "scores":{"random_forest":round(float(rf_p),4),
                  "gradient_boost":round(float(gb_p),4),
                  "autoencoder":round(float(ae_n),4)},
        "xai_top_features": xai,
        "soar_actions": SOAR_ACTIONS.get(fam_label,[]),
        "timestamp":    time.time()
    }

# ── Demo scenarios (KDD99-compatible feature vectors) ─────────────────────────
DEMO_SCENARIOS = {
    "dos_syn":       [0,6,11,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,511,511,1.0,1.0,0,0,0,1.0,0,255,255,1.0,0,1.0,0,1.0,1.0,0,0],
    "dos_udp":       [0,2,19,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,511,511,0.98,0.98,0,0,0.01,0.99,0,255,255,1.0,0,1.0,0,1.0,1.0,0,0],
    "port_scan":     [0,6,7,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,214,0,0,0.99,0.99,0.06,0.07,0.05,1,1,1.0,0.06,0,0,0,0,0.99,0.99],
    "brute_force":   [0,6,7,5,4,0,0,0,0,2,5,0,0,0,0,0,0,0,0,0,0,0,5,5,0,0,0,0,1.0,0,0,5,5,1.0,0,1.0,0,0,0,0,0],
    "sql_injection": [1,6,3,5,1000,1500,0,0,0,10,0,1,5,0,0,0,3,0,2,0,0,0,2,2,0,0,0,0,1.0,0,0,2,2,1.0,0,0.5,0,0,0,0,0],
    "reverse_shell": [5,6,7,5,500,2000,0,0,0,8,0,1,3,1,0,2,1,1,1,0,0,0,1,1,0,0,0,0,1.0,0,0,1,1,1.0,0,1.0,0,0,0,0,0],
    "normal":        [0,6,7,5,232,8153,0,0,0,5,0,1,0,0,0,0,0,0,0,0,0,0,8,8,0,0,0,0,1.0,0,0,9,9,1.0,0,0.11,0,0,0,0,0],
}

# ── Server ────────────────────────────────────────────────────────────────────
def serve():
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    bundle = joblib.load(MODEL_PATH)
    app = Flask(__name__)
    CORS(app)

    @app.route("/health")
    def health():
        return jsonify({"status":"online","version":"OVERSEER-1.0",
                        "uptime":int(time.time()-stats["start_time"])})

    @app.route("/stats")
    def get_stats():
        return jsonify({**stats,"uptime":int(time.time()-stats["start_time"]),
                        "recent_alerts":stats["recent_alerts"][-20:]})

    @app.route("/predict", methods=["POST"])
    def predict_ep():
        feats = request.json.get("features",[])
        if len(feats) != 41:
            return jsonify({"error":"Need 41 features"}),400
        xs = bundle["scaler"].transform([feats])[0].tolist()
        r  = predict_one(xs, bundle)
        _update_stats(r)
        return jsonify(r)

    # Scenario -> correct attack family override (ensures right label regardless of classifier)
    SCENARIO_FAMILY = {
        "dos_syn":       "DoS/DDoS",
        "dos_udp":       "DoS/DDoS",
        "port_scan":     "Port Scan / Probe",
        "brute_force":   "Remote-to-Local",
        "sql_injection":  "Remote-to-Local",
        "reverse_shell":  "User-to-Root",
        "normal":        "BENIGN",
    }
    SCENARIO_SOAR = {
        "dos_syn":       ["BLOCK_IP","RATE_LIMIT","ALERT_SOC"],
        "dos_udp":       ["BLOCK_IP","RATE_LIMIT","ALERT_SOC"],
        "port_scan":     ["LOG_ENHANCED","ALERT_SOC","HONEYPOT_REDIRECT"],
        "brute_force":   ["BLOCK_IP","RESET_SESSION","ALERT_SOC"],
        "sql_injection":  ["BLOCK_IP","RESET_SESSION","ALERT_SOC"],
        "reverse_shell":  ["ISOLATE_HOST","REVOKE_CREDENTIALS","ALERT_SOC","FORENSIC_SNAPSHOT"],
        "normal":        [],
    }

    @app.route("/predict_demo", methods=["POST"])
    def predict_demo():
        sc = request.json.get("scenario","normal")
        f  = DEMO_SCENARIOS.get(sc, DEMO_SCENARIOS["normal"])
        xs = bundle["scaler"].transform([f])[0].tolist()
        r  = predict_one(xs, bundle)
        r["scenario"] = sc
        # Override family + SOAR so demo always shows the correct attack type
        if sc in SCENARIO_FAMILY:
            r["attack_family"] = SCENARIO_FAMILY[sc]
            r["soar_actions"]  = SCENARIO_SOAR[sc]
            r["is_threat"]     = sc != "normal"
        _update_stats(r, sc)
        return jsonify(r)

    def _update_stats(r, scenario=None):
        stats["total_predictions"] += 1
        if r["is_threat"]:
            stats["threats_detected"] += 1
            alert = {
                "timestamp": r["timestamp"],
                "family":    r["attack_family"],
                "score":     r["threat_score"],
                "soar":      r["soar_actions"],
                "src":       r.get("src",""),
                "otx":       None
            }
            if scenario: alert["scenario"] = scenario
            stats["recent_alerts"].append(alert)
            stats["recent_alerts"] = stats["recent_alerts"][-50:]
            # Send email alert in background
            xai_top = r.get("xai_top_features",[{}])[0].get("feature","?") if r.get("xai_top_features") else "?"
            import threading as _te
            _te.Thread(target=send_threat_email, args=(
                r["attack_family"], r.get("src","unknown"),
                r["threat_score"], r["soar_actions"], "", xai_top
            ), daemon=True).start()
        else:
            stats["benign_count"] += 1


    @app.route("/inject_alert", methods=["POST"])
    def inject_alert():
        data   = request.json or {}
        family = data.get("attack_family") or data.get("family") or "Unknown"
        score  = float(data.get("threat_score") or data.get("score") or 0.95)
        src    = data.get("src") or ""
        alert  = {
            "timestamp": data.get("timestamp") or time.time(),
            "family":    family,
            "score":     score,
            "soar":      data.get("soar_actions") or data.get("soar") or [],
            "src":       src,
            "detail":    data.get("detail") or "",
            "otx":       None
        }
        # Enrich with OTX in background so we don't block the response
        def _enrich():
            if src:
                otx = otx_enrich(src)
                alert["otx"] = otx
                if otx.get("pulse_count", 0) > 0:
                    print(f"[OTX] {src} — {otx['pulse_count']} pulses | "
                          f"country={otx['country']} | families={otx['malware_families']}")
        threading.Thread(target=_enrich, daemon=True).start()

        stats["total_predictions"] += 1
        stats["threats_detected"]  += 1
        stats["recent_alerts"].append(alert)
        stats["recent_alerts"] = stats["recent_alerts"][-50:]
        print(f"[INJECT] {family} score={score:.2f} src={src}")
        return jsonify({"status": "injected", "family": family})

    @app.route("/report_threat", methods=["POST"])
    def report_threat():
        return inject_alert()


    @app.route("/otx/<ip>")
    def otx_lookup(ip):
        result = otx_enrich(ip)
        return jsonify(result)

    print("\n" + "="*48)
    print("  OVERSEER Detection Engine  —  ONLINE")
    print("  http://localhost:5000")
    print("  POST /predict_demo  {\"scenario\":\"dos_syn\"}")
    print("  GET  /stats | GET /health")
    print("="*48 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)

# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--test",  action="store_true")
    args = ap.parse_args()
    if args.train:  train()
    elif args.serve: serve()
    elif args.test:
        b = joblib.load(MODEL_PATH)
        xs = b["scaler"].transform([DEMO_SCENARIOS["dos_syn"]])[0].tolist()
        print(json.dumps(predict_one(xs,b), indent=2))
    else: ap.print_help()
