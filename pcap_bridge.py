"""
OVERSEER — PCAP Bridge v3
==========================
Hardcoded to the correct VirtualBox interface GUID.
Sniffs Parrot → Metasploitable traffic and auto-calls OVERSEER.

USAGE:  python pcap_bridge.py
"""

import time
import threading
import requests
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ── HARDCODED CORRECT INTERFACE ───────────────────────────────────────────────
IFACE    = r"\Device\NPF_{6603132C-7304-4D16-841D-96B52B91138B}"

# ── CONFIG ────────────────────────────────────────────────────────────────────
TARGET   = "192.168.56.101"    # Metasploitable
ATTACKER = "192.168.56.102"    # Parrot OS
SUBNET   = "192.168.56."
API      = "http://localhost:5000/predict"

FLOW_TIMEOUT   = 4.0
MIN_PACKETS    = 2
SCORE_INTERVAL = 0.8

# ── State ─────────────────────────────────────────────────────────────────────
flows      = {}
last_score = {}
lock       = threading.Lock()
stats      = {"pkts": 0, "scored": 0, "threats": 0, "t0": time.time()}

SERVICE_MAP = {
    80:3, 443:3, 8080:3, 8180:3,
    22:7, 21:5, 2121:5, 23:19,
    25:15, 53:4, 3306:20, 5432:21,
    139:12, 445:12, 1524:8, 6667:10,
    512:8, 513:8, 514:8,
}
PROTO_MAP = {"tcp": 6, "udp": 2, "icmp": 1}


def new_flow(proto, dport):
    return {
        "proto": proto, "dport": dport,
        "src_bytes": 0, "dst_bytes": 0,
        "pkts": 0, "t0": time.time(), "t_last": time.time(),
        "syn": 0, "ack": 0, "rst": 0, "fin": 0,
        "hot": 0, "failed_logins": 0,
        "serr": 0, "rerr": 0,
    }


# ── Packet handler ────────────────────────────────────────────────────────────
def handle(pkt):
    try:
        if not pkt.haslayer(IP): return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if SUBNET not in src and SUBNET not in dst: return

        stats["pkts"] += 1

        proto = "tcp"
        dport = 0
        syn = ack = rst = fin = False

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            f     = pkt[TCP].flags
            syn   = bool(f & 0x02)
            ack   = bool(f & 0x10)
            rst   = bool(f & 0x04)
            fin   = bool(f & 0x01)
        elif pkt.haslayer(UDP):
            proto = "udp"
            dport = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "icmp"
            dport = 0
        else:
            return

        key = (src, dst, dport, proto)

        with lock:
            if key not in flows:
                flows[key] = new_flow(proto, dport)
            fl = flows[key]
            fl["pkts"]   += 1
            fl["t_last"]  = time.time()

            plen = len(pkt)
            if src == ATTACKER: fl["src_bytes"] += plen
            else:               fl["dst_bytes"] += plen

            if syn: fl["syn"] += 1
            if ack: fl["ack"] += 1
            if rst: fl["rst"] += 1; fl["serr"] += 1
            if fin: fl["fin"] += 1

            if dport in [22, 23, 1524, 512, 513, 514]: fl["hot"] += 1
            if dport == 22 and syn and not ack:         fl["failed_logins"] += 1

            if fl["pkts"] >= MIN_PACKETS:
                _try_score(key, fl)

    except Exception:
        pass


def _try_score(key, fl):
    now = time.time()
    if now - last_score.get(key, 0) < SCORE_INTERVAL:
        return
    last_score[key] = now
    features = extract(key, fl)
    threading.Thread(target=call_api, args=(key, fl, features), daemon=True).start()


# ── Feature extraction ────────────────────────────────────────────────────────
def extract(key, fl):
    src, dst, dport, proto = key
    pkts     = max(fl["pkts"], 1)
    duration = max(fl["t_last"] - fl["t0"], 0)
    serr     = min(fl["serr"] / pkts, 1.0)
    rerr     = min(fl["rerr"] / pkts, 1.0)
    count    = min(fl["pkts"], 511)

    # SYN flood
    if fl["syn"] > 30 and fl["src_bytes"] < 200:
        count = 511
        serr  = 1.0

    # Port scan
    same_srv = 1.0
    diff_srv = 0.0
    if fl["syn"] > 5 and fl["dst_bytes"] < 100:
        rerr     = 0.99
        same_srv = 0.06
        diff_srv = 0.07

    root_shell = 1 if dport == 1524 else 0
    num_shells = 1 if dport in [1524, 512, 513, 514] else 0
    logged_in  = 1 if fl["ack"] > 0 else 0

    flag = (9 if fl["syn"] > 0 and fl["ack"] == 0
            else (3 if fl["rst"] > 0 else 5))

    return [
        duration,
        PROTO_MAP.get(proto, 6),
        SERVICE_MAP.get(dport, 7),
        flag,
        fl["src_bytes"],
        fl["dst_bytes"],
        0, 0, 0,
        min(fl["hot"], 10),
        min(fl["failed_logins"], 10),
        logged_in,
        root_shell, root_shell, 0, root_shell,
        0, num_shells, 0, 0, 0, 0,
        count, count,
        serr, serr, rerr, rerr,
        same_srv, diff_srv, 0.0,
        min(count, 255), min(count, 255),
        same_srv, diff_srv,
        1.0 if count > 50 else 0.1,
        0.0, serr, serr, rerr, rerr,
    ]


# ── API call ──────────────────────────────────────────────────────────────────
def call_api(key, fl, features):
    src, dst, dport, proto = key
    try:
        r = requests.post(API, json={"features": features}, timeout=2)
        if r.status_code != 200: return

        res    = r.json()
        score  = res.get("threat_score", 0)
        family = res.get("attack_family", "BENIGN")
        threat = res.get("is_threat", False)
        soar   = res.get("soar_actions", [])
        ts     = datetime.now().strftime("%H:%M:%S")
        top    = res.get("xai_top_features", [{}])[0].get("feature", "?")

        stats["scored"] += 1

        if threat:
            stats["threats"] += 1
            print(f"\n{'━'*56}")
            print(f"  🔴 THREAT DETECTED  [{ts}]")
            print(f"  Family : {family}")
            print(f"  Score  : {score:.4f}")
            print(f"  Flow   : {src} → {dst}:{dport} ({proto.upper()})")
            print(f"  SOAR   : {', '.join(soar)}")
            print(f"  XAI    : top indicator = {top}")
            print(f"{'━'*56}\n")
        else:
            print(f"  ✅ [{ts}] BENIGN  {score:.3f}  {src}→{dst}:{dport}")

    except requests.exceptions.ConnectionError:
        print("[!] OVERSEER API offline. Run: python overseer_engine.py --serve")
    except Exception:
        pass


# ── Cleanup thread ────────────────────────────────────────────────────────────
def cleanup():
    while True:
        time.sleep(3)
        now = time.time()
        with lock:
            dead = [k for k, f in flows.items() if now - f["t_last"] > FLOW_TIMEOUT]
            for k in dead:
                del flows[k]
                last_score.pop(k, None)


# ── Stats thread ──────────────────────────────────────────────────────────────
def print_stats():
    while True:
        time.sleep(15)
        up = int(time.time() - stats["t0"])
        print(f"\n  [stats] uptime={up}s | packets={stats['pkts']} | "
              f"scored={stats['scored']} | threats={stats['threats']}\n")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*56)
    print("  OVERSEER — Live PCAP Bridge v3")
    print("  Interface: VirtualBox Host-Only (GUID hardcoded)")
    print("="*56)

    try:
        requests.get("http://localhost:5000/health", timeout=2)
        print("[✓] OVERSEER engine: ONLINE")
    except:
        print("[!] OVERSEER not running!")
        print("    Start it: python overseer_engine.py --serve")
        input("    Press Enter to continue anyway...")

    print(f"[✓] Interface: {IFACE}")
    print(f"[✓] Target   : {TARGET}  (Metasploitable)")
    print(f"[✓] Attacker : {ATTACKER}  (Parrot OS)")
    print(f"[✓] API      : {API}")
    print(f"\n[*] LIVE — run attacks on Parrot now!\n")

    threading.Thread(target=cleanup,     daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()

    try:
        sniff(
            iface=IFACE,
            prn=handle,
            filter=f"host {TARGET} or host {ATTACKER}",
            store=False,
            quiet=True
        )
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"\n[!] Sniff error: {e}")
        print("    Try running as Administrator (right-click → Run as admin)")
