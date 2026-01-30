#!/bin/bash
set -e
clear

fun_bar() {
    CMD[0]="$1"
    CMD[1]="${2:-:}"
    (
        [[ -e $HOME/fim ]] && rm -f $HOME/fim
        bash -c "${CMD[0]}" >/dev/null 2>&1
        bash -c "${CMD[1]}" >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[0;32m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm -f $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}

res_update_menu() {
    REPO="https://raw.githubusercontent.com/YINNSTORE/VVIP/main/"
    TMPDIR="$(mktemp -d)"
    cd "$TMPDIR"

    wget -q "${REPO}menu/menu.zip" -O menu.zip
    unzip -qq menu.zip

    if [ ! -d menu ]; then
        echo "menu.zip tidak valid"
        rm -rf "$TMPDIR"
        exit 1
    fi

    chmod +x menu/* 2>/dev/null || true

    mkdir -p /usr/local/sbin

    # Backup file lama yang ketimpa (biar aman)
    BACKUP_DIR="/root/backup_menu_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    for f in menu/*; do
        base="$(basename "$f")"
        if [ -f "/usr/local/sbin/$base" ]; then
            cp -a "/usr/local/sbin/$base" "$BACKUP_DIR/" 2>/dev/null || true
        fi
        cp -a "$f" "/usr/local/sbin/$base"
        chmod +x "/usr/local/sbin/$base" 2>/dev/null || true
    done

    rm -rf "$TMPDIR"
}

netfilter-persistent >/dev/null 2>&1 || true
clear
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e " \e[1;97;101m            UPDATE SCRIPT BY YINN TUNELING               \e[0m"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
echo -e "  \033[1;91m Update Script Service\033[1;37m"
fun_bar 'res_update_menu'
echo -e ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | lolcat
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to back on menu"
menu