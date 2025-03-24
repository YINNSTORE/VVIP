#!/bin/bash
NS=$(cat /etc/xray/dns)
PUB=$(cat /etc/slowdns/server.pub)
domain=$(cat /etc/xray/domain)
#color
grenbo="\e[92;1m"
NC='\e[0m'
#install
apt update && apt upgrade
apt install python3 python3-pip git -y
cd /usr/bin
wget -q -O bot.zip "https://raw.githubusercontent.com/YINNSTORE/VVIP/main/bot/bot.zip"
unzip bot.zip
mv bot/* /usr/bin
chmod +x /usr/bin/*
rm -rf bot
rm -rf bot.zip
cd

clear

if [[ -d /etc/.cybervpn ]]; then
rm -rf /etc/.cybervpn
fi

mkdir -p /etc/.cybervpn
cd /etc/.cybervpn
wget -q -O cybervpn.zip "https://raw.githubusercontent.com/YINNSTORE/VVIP/main/bot/cybervpn.zip"
unzip cybervpn.zip &>/dev/null

function cekos() {
source /etc/os-release
echo "$ID $VERSION_ID"
}

if [[ $(cekos) == "ubuntu 20.04" || $(cekos) == "ubuntu 22.04" || $(cekos) == "debian 10" || $(cekos) == "debian 11" ]]; then
pip3 install -r cybervpn/requirements.txt
pip install pillow
pip install speedtest-cli
pip3 install aiohttp
pip3 install paramiko
else
pip3 install -r cybervpn/requirements.txt --break-system-packages
pip install pillow --break-system-packages
pip install speedtest-cli --break-system-packages
pip3 install aiohttp --break-system-packages
pip3 install paramiko --break-system-packages
fi

clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1;97;101m             ADD BOT PANEL              \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "${grenbo}Tutorial Creat Bot and ID Telegram${NC}"
echo -e "${grenbo}[*] Creat Bot and Token Bot : @BotFather${NC}"
echo -e "${grenbo}[*] Info Id Telegram : @MissRose_bot , perintah /info${NC}"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
read -e -p "[*] Input your Bot Token : " bottoken
read -e -p "[*] Input Your Id Telegram : " admin
read -e -p "[*] Input username Telegram : " user

cat > /etc/.cybervpn/cybervpn/var.txt << END
ADMIN="$admin"
BOT_TOKEN="$bottoken"
DOMAIN="$domain"
DNS="$NS"
PUB="$PUB"
OWN="$user"
SALDO="100000"
END

clear

if [[ -e /etc/systemd/system/kyt.service ]]; then
systemctl stop kyt
systemctl disable kyt
rm -f /etc/systemd/system/kyt.service
fi

cat > /etc/systemd/system/kyt.service << END
[Unit]
Description=Simple Bot Telegram @yinnstore
After=network.target

[Service]
WorkingDirectory=/etc/.cybervpn/
ExecStart=/usr/bin/python3 -m cybervpn
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl enable kyt.service
systemctl restart kyt.service
cd /root
rm -rf $0
clear
echo "Your Data Bot"
echo -e "==============================="
echo "Token Bot : $bottoken"
echo "Admin    : $admin"
echo "Domain   : $domain"
echo "Pub      : $PUB"
echo "Host     : $NS"
echo -e "==============================="
echo "Setting done"
sleep 2
echo " Installations complete, type /menu on your bot"
