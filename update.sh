#!/bin/bash
set -e
clear

REPO="https://raw.githubusercontent.com/YINNSTORE/VVIP/main/"
SBIN_DIR="/usr/local/sbin"

# ===== COLORS =====
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_deps() {
  # unzip & wget wajib
  if ! need_cmd wget || ! need_cmd unzip; then
    echo -e "${YELLOW}Installing dependencies (wget, unzip)...${NC}"
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y wget unzip >/dev/null 2>&1 || true
  fi

  # lolcat optional (kalau gak ada, tetep jalan)
  if ! need_cmd lolcat; then
    # jangan bikin gagal kalau ruby/gem gak ada
    apt-get install -y ruby >/dev/null 2>&1 || true
    gem install lolcat >/dev/null 2>&1 || true
  fi
}

fun_bar() {
  local func="$1"
  (
    [[ -e "$HOME/fim" ]] && rm -f "$HOME/fim"
    $func >/dev/null 2>&1
    touch "$HOME/fim"
  ) >/dev/null 2>&1 &

  tput civis || true
  echo -ne "  ${YELLOW}Please Wait Loading ${NC}- ${YELLOW}[${NC}"
  while true; do
    for ((i=0; i<18; i++)); do
      echo -ne "${GREEN}#${NC}"
      sleep 0.1
    done
    if [[ -e "$HOME/fim" ]]; then
      rm -f "$HOME/fim"
      break
    fi
    echo -e "${YELLOW}]${NC}"
    sleep 0.5
    tput cuu1 || true
    tput dl1 || true
    echo -ne "  ${YELLOW}Please Wait Loading ${NC}- ${YELLOW}[${NC}"
  done
  echo -e "${YELLOW}]${NC} -${GREEN} OK !${NC}"
  tput cnorm || true
}

res_update_menu() {
  ensure_deps

  TMPDIR="$(mktemp -d)"
  cd "$TMPDIR"

  wget -q "${REPO}menu/menu.zip" -O menu.zip
  unzip -qq menu.zip

  # struktur zip harus ada folder "menu"
  if [ ! -d "menu" ]; then
    echo -e "${RED}menu.zip tidak valid (folder 'menu' tidak ada).${NC}"
    cd /
    rm -rf "$TMPDIR"
    exit 1
  fi

  mkdir -p "$SBIN_DIR"

  # backup yang ketimpa
  BACKUP_DIR="/root/backup_menu_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$BACKUP_DIR"

  for f in menu/*; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"

    # backup file lama kalau ada
    if [ -f "$SBIN_DIR/$base" ]; then
      cp -a "$SBIN_DIR/$base" "$BACKUP_DIR/" 2>/dev/null || true
    fi

    # copy file baru
    cp -a "$f" "$SBIN_DIR/$base"

    # normalize CRLF (biar gak ^M)
    sed -i 's/\r$//' "$SBIN_DIR/$base" 2>/dev/null || true

    chmod +x "$SBIN_DIR/$base" 2>/dev/null || true
  done

  cd /
  rm -rf "$TMPDIR"
}

# ===== START =====
netfilter-persistent >/dev/null 2>&1 || true
clear

if command -v lolcat >/dev/null 2>&1; then
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
  echo -e " \e[1;97;101m            UPDATE SCRIPT BY YINN TUNELING               \e[0m" | lolcat
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
else
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "            UPDATE SCRIPT BY YINN TUNELING"
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

echo ""
echo -e "  \033[1;91m Update Script Service\033[1;37m"
fun_bar res_update_menu

echo ""
if command -v lolcat >/dev/null 2>&1; then
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
else
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi
echo ""

read -n 1 -s -r -p "Press [ Enter ] to back on menu"
echo ""
menu