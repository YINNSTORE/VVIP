#!/bin/bash
set -euo pipefail

UDP_DIR="/root/udp"
BIN_FILE="$UDP_DIR/udp-custom"
CFG_FILE="$UDP_DIR/config.json"
SERVICE_FILE="/etc/systemd/system/udp-custom.service"
SYSCTL_FILE="/etc/sysctl.d/99-udp-custom-extreme.conf"

BIN_ID="1ixz82G_ruRBnEEp4vLPNF2KZ1k8UfrkV"
CFG_ID="1klXTiKGUd2Cs5cBnH3eK2Q1w50Yx3jbf"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
MAGENTA='\033[1;35m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || { err "Jalankan script sebagai root"; exit 1; }
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Command tidak ditemukan: $1"; exit 1; }
}

spinner() {
  local pid=$1
  local delay=0.07
  local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  while kill -0 "$pid" 2>/dev/null; do
    for ((i=0; i<${#chars}; i++)); do
      printf "\r${MAGENTA}[%s]${NC} Working..." "${chars:$i:1}"
      sleep "$delay"
    done
  done
  printf "\r\033[K"
}

download_gdrive() {
  local file_id="$1"
  local output="$2"
  local cookie="/tmp/gcookie.$$"
  local page="/tmp/gpage.$$"

  rm -f "$cookie" "$page"

  wget --quiet \
    --save-cookies "$cookie" \
    --keep-session-cookies \
    --no-check-certificate \
    "https://docs.google.com/uc?export=download&id=${file_id}" \
    -O "$page"

  local confirm=""
  confirm="$(sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1/p' "$page" | head -n1 || true)"

  if [[ -n "$confirm" ]]; then
    wget -q --show-progress \
      --load-cookies "$cookie" \
      "https://docs.google.com/uc?export=download&confirm=${confirm}&id=${file_id}" \
      -O "$output"
  else
    wget -q --show-progress \
      --no-check-certificate \
      "https://docs.google.com/uc?export=download&id=${file_id}" \
      -O "$output"
  fi

  rm -f "$cookie" "$page"
}

write_extreme_sysctl() {
  cat > "$SYSCTL_FILE" <<'EOF'
# Queue discipline + congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Backlog & accept queue
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 32768
net.core.optmem_max = 8388608

# Socket buffers - sengaja medium, bukan brutal, supaya latency tetap rendah
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
net.ipv4.udp_mem = 32768 65536 131072

# Better burst handling
net.ipv4.ip_local_port_range = 1024 65535

# Faster recovery / path handling
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1

# Security that doesn't hurt performance much
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# Avoid odd reverse-path drops in some tunnel situations
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# Reduce TIME_WAIT pain a bit
net.ipv4.tcp_fin_timeout = 15

# Kernel scheduler-ish network behavior
net.core.dev_weight = 64
net.core.dev_weight_rx_bias = 1
net.core.dev_weight_tx_bias = 1
EOF

  sysctl --system >/dev/null 2>&1 || true
}

tune_limits() {
  mkdir -p /etc/systemd/system/udp-custom.service.d

  cat > /etc/systemd/system/udp-custom.service.d/limits.conf <<'EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
TasksMax=infinity
EOF
}

write_service() {
  local exclude_arg=""
  if [[ -n "${1:-}" ]]; then
    exclude_arg=" -exclude ${1}"
  fi

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=UDP Custom Extreme Low Latency
After=network.target network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=${UDP_DIR}
ExecStart=${BIN_FILE} server${exclude_arg}
Restart=always
RestartSec=0.2
TimeoutStartSec=15
TimeoutStopSec=5
KillMode=process

# Process priority
Nice=-20
OOMScoreAdjust=-1000
CPUSchedulingPolicy=other
IOSchedulingClass=best-effort
IOSchedulingPriority=0

# hard limits
LimitNOFILE=1048576
LimitNPROC=1048576
TasksMax=infinity

# log
StandardOutput=journal
StandardError=journal
SyslogIdentifier=udp-custom

[Install]
WantedBy=multi-user.target
EOF
}

apply_basic_network_tools() {
  if command -v ethtool >/dev/null 2>&1; then
    local iface
    iface="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
    if [[ -n "$iface" ]]; then
      ethtool -K "$iface" gro off gso off tso off >/dev/null 2>&1 || true
      ethtool -C "$iface" rx-usecs 0 tx-usecs 0 >/dev/null 2>&1 || true
      ok "ethtool latency tweak applied on $iface"
    else
      warn "Interface utama tidak terdeteksi, skip ethtool tuning"
    fi
  else
    warn "ethtool tidak ada, skip NIC latency tuning"
  fi
}

maybe_install_tools() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y ethtool >/dev/null 2>&1 || true
  fi
}

show_banner() {
  clear
  echo -e "${BLUE}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "       UDP CUSTOM EXTREME LOW LATENCY MODE"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "${NC}"
  echo
}

main() {
  need_root
  need_cmd wget
  need_cmd sed
  need_cmd systemctl
  need_cmd sysctl
  need_cmd ln
  need_cmd ip

  show_banner

  log "Set timezone Asia/Jakarta"
  ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
  ok "Timezone OK"

  log "Prepare folder"
  rm -rf "$UDP_DIR"
  mkdir -p "$UDP_DIR"
  ok "Folder ready"

  log "Download udp-custom binary"
  (download_gdrive "$BIN_ID" "$BIN_FILE") &
  spinner $!
  wait $!
  chmod +x "$BIN_FILE"
  ok "Binary downloaded"

  log "Download default config"
  (download_gdrive "$CFG_ID" "$CFG_FILE") &
  spinner $!
  wait $!
  chmod 644 "$CFG_FILE"
  ok "Config downloaded"

  log "Install helper tools"
  maybe_install_tools

  log "Apply EXTREME sysctl low latency"
  write_extreme_sysctl
  ok "Sysctl extreme applied"

  log "Apply service limits"
  tune_limits
  ok "Limits applied"

  log "Stop old service"
  systemctl stop udp-custom >/dev/null 2>&1 || true
  systemctl disable udp-custom >/dev/null 2>&1 || true
  ok "Old service stopped"

  log "Create service"
  write_service "${1:-}"
  systemctl daemon-reload
  ok "Service written"

  log "Apply NIC low latency tweak"
  apply_basic_network_tools

  log "Enable service"
  systemctl enable udp-custom >/dev/null 2>&1
  ok "Service enabled"

  log "Start service"
  systemctl restart udp-custom
  sleep 1

  if systemctl is-active --quiet udp-custom; then
    ok "udp-custom running"
  else
    err "udp-custom gagal jalan"
    systemctl status udp-custom --no-pager -l || true
    exit 1
  fi

  clear
  echo
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN} UDP CUSTOM${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo
  systemctl --no-pager --full status udp-custom | sed -n '1,15p'
  echo
  echo "Tes cepat:"
  echo "  ping 1.1.1.1 -c 10"
  echo "  journalctl -u udp-custom -n 30 --no-pager"
  echo
  read -p "Enter To Menu"
  menu
}

main "${1:-}"