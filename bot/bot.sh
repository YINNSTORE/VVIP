#!/bin/bash
NS=$( cat /etc/xray/dns )
PUB=$( cat /etc/slowdns/server.pub )
domain=$(cat /etc/xray/domain)
grenbo="\e[92;1m"
NC='\e[0m'
repo="https://raw.githubusercontent.com/YINNSTORE/VVIP/main/"

function cekos() {
source /etc/os-release
echo "$ID $VERSION_ID"
}

dirbot="/etc/.telebot"

if [[ -d $dirbot ]] &>/dev/null; then
rm -rf $dirbot
fi
mkdir -p $dirbot

with_virtual() {
apt update
apt install -y wget curl git
apt install -y python3
apt install -y python3-pip
apt install -y python3.11-venv -y
cd $dirbot
python3 -m venv virtual
source virtual/bin/activate
wget -q -O kyt.zip "${repo}bot/kyt.zip"
unzip kyt.zip
pip3 install --upgrade pip
pip3 install -r kyt/requirements.txt
deactivate
}

with_no_virtual() {
apt update
apt install -y wget curl git
apt install -y python3
apt install -y python3-pip
cd /etc/.telebot
wget -q -O kyt.zip "${repo}bot/kyt.zip"
unzip kyt.zip
pip3 install -r kyt/requirements.txt
}

if [[ $(cekos) == "debian 12" || $(cekos) == "ubuntu 24.04" || $(cekos) == "ubuntu 24.10" ]]; then
virtual_path="/etc/.telebot/virtual/bin/python3"
with_virtual
else
virtual_path="/usr/bin/python3"
with_no_virtual
fi

cd /usr/bin
wget -q -O bot.zip "${repo}bot/bot.zip"
unzip bot.zip
chmod +x bot/*
mv bot/* /usr/bin/
rm -rf bot.zip
rm -rf bot
cd


clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1;97;101m             ADD BOT PANEL              \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "${grenbo}Tutorial Create Bot and ID Telegram${NC}"
echo -e "${grenbo}[*] Create Bot and Token Bot : @BotFather${NC}"
echo -e "${grenbo}[*] Info ID Telegram : @MissRose_bot , perintah /info${NC}"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
read -e -p "[*] Input your Bot Token : " bottoken
read -e -p "[*] Input Your ID Telegram :" admin
echo -e BOT_TOKEN='"'$bottoken'"' >> $dirbot/kyt/var.txt
echo -e ADMIN='"'$admin'"' >> $dirbot/kyt/var.txt
echo -e DOMAIN='"'$domain'"' >> $dirbot/kyt/var.txt
echo -e PUB='"'$PUB'"' >> $dirbot/kyt/var.txt
echo -e HOST='"'$NS'"' >> $dirbot/kyt/var.txt

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
WorkingDirectory=/etc/.telebot
ExecStart=$virtual_path -m kyt
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl start kyt
systemctl enable kyt
systemctl restart kyt

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