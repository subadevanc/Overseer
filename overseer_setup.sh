#!/bin/bash
# ============================================================
#  OVERSEER — One-shot setup script
#  Run this ONCE on your Linux Mint attacker machine
# ============================================================

set -e
CYN='\033[0;36m'; GRN='\033[0;32m'; YEL='\033[1;33m'; NC='\033[0m'
log() { echo -e "${YEL}[setup]${NC} $1"; }
ok()  { echo -e "${GRN}[✓]${NC} $1"; }

echo -e "${CYN}"
echo "  ╔═══════════════════════════════╗"
echo "  ║   OVERSEER — Environment Setup ║"
echo "  ╚═══════════════════════════════╝"
echo -e "${NC}"

# ── Python deps ───────────────────────────────────────────────────────────────
log "Installing Python dependencies..."
pip install flask scikit-learn numpy pandas joblib flask-cors --quiet
ok "Python deps installed"

# ── Attack tools ──────────────────────────────────────────────────────────────
log "Installing attack tools..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
  nmap \
  hping3 \
  hydra \
  sqlmap \
  netcat-traditional \
  wireshark \
  tcpdump \
  metasploit-framework 2>/dev/null || {
    log "Metasploit not in apt — install manually from https://metasploit.com"
  }
ok "Attack tools installed"

# ── Make scripts executable ───────────────────────────────────────────────────
chmod +x attack_scripts.sh
ok "Scripts ready"

# ── Start PCAP capture ────────────────────────────────────────────────────────
log "Detecting host-only network interface..."
IFACE=$(ip link show | grep -E "vboxnet|eth|enp" | grep -v "lo" | head -1 | awk -F: '{print $2}' | tr -d ' ')
log "Detected interface: $IFACE"

echo ""
echo -e "${CYN}══════════════════════════════════════════${NC}"
echo -e " NEXT STEPS:"
echo ""
echo -e " 1. Train ML models (~5-10 min):"
echo -e "    ${GRN}python overseer_engine.py --train${NC}"
echo ""
echo -e " 2. Start detection engine:"
echo -e "    ${GRN}python overseer_engine.py --serve${NC}"
echo ""
echo -e " 3. Open dashboard:"
echo -e "    Open overseer_dashboard.html in your browser"
echo ""
echo -e " 4. Test with demo scenarios (no VM needed):"
echo -e "    ${GRN}./attack_scripts.sh demo${NC}"
echo ""
echo -e " 5. Real attacks (set your VM IP first):"
echo -e "    ${GRN}export OVERSEER_TARGET=192.168.56.101${NC}"
echo -e "    ${GRN}./attack_scripts.sh all${NC}"
echo -e "${CYN}══════════════════════════════════════════${NC}"
echo ""
echo -e " Ubuntu Server VM setup (run ON the target VM):"
echo -e "    sudo apt install apache2 openssh-server"
echo -e "    sudo ufw allow 22 80 3306 8080 && sudo ufw enable"
echo -e "    sudo systemctl start apache2 ssh"
echo -e "${CYN}══════════════════════════════════════════${NC}"
