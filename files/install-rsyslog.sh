#!/bin/bash

# Install rsyslog
apt update
apt install rsyslog -y

# Menampilkan versi OS
cekos() {
source /etc/os-release
echo "$ID $VERSION_ID"
}

# Mengecek apakah OS ubuntu 24 atau debian 12
if [[ $(cekos) == "ubuntu 24.04" || $(cekos) == "ubuntu 24.10" ]]; then
rsyslog_config="/etc/rsyslog.d/50-default.conf"
elif [[ $(cekos) == "debian 12" ]]; then
rsyslog_config="/etc/rsyslog.conf"
fi

if [[ $(cekos) == "ubuntu 24.04" || $(cekos) == "ubuntu 24.10" ||  $(cekos) == "debian 12" ]]; then
if [[ $(cat $rsyslog_config | grep 'if \$programname == "dropbear"') ]] &>/dev/null; then
echo -ne
else
echo 'if $programname == "dropbear" then /var/log/auth.log
& stop' | sudo tee -a $rsyslog_config &>/dev/null
systemctl restart rsyslog
fi
fi

# Set permissions untuk log dropbear
set_permissions() {
log_dropbear=( /var/log/auth.log /var/log/kern.log /var/log/mail.log /var/log/user.log /var/log/cron.log )

# Loop untuk set_permissions
for log_file in "${log_dropbear[@]}"; do
    [[ -f "$log_file" ]] && { chmod 640 "$log_file"; chown syslog:adm "$log_file" 2>/dev/null; }
done
}

set_permissions
rm -f $0