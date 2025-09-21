#!/bin/bash

# Auto Install Multi-VPN with GitHub Whitelist for Ubuntu 20.04/Debian 9/10
# Prioritas: SSH Tunneling, with Bandwidth Reset, Namecheap, V2Ray gRPC
# Jalankan sebagai root

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# GitHub Whitelist Config
GITHUB_TOKEN="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" # Ganti dengan token asli
GITHUB_REPO="sujinwo150/vpn-whitelist"
WHITELIST_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/blob/main/vps-whitelist.txt"

# Log file
LOG_FILE="/var/log/vpn-install.log"

log() {
    echo "$1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}$1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

echo -e "${GREEN}=== Multi-VPN Installer with IP Whitelist ===${NC}"

# Step 1: Check IP Whitelist
log "Checking VPS IP against GitHub whitelist..."
VPS_IP=$(curl -s https://api.ipify.org || error "Failed to get VPS IP!")
log "VPS IP: $VPS_IP"

WHITELIST_CONTENT=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -H "User-Agent: Mozilla/5.0" "$WHITELIST_URL" || error "Failed to fetch whitelist from GitHub! Check token or file.")
if ! echo "$WHITELIST_CONTENT" | grep -Fx "$VPS_IP" > /dev/null; then
    error "Unauthorized VPS IP ($VPS_IP)! Add it to $WHITELIST_URL first."
fi
log "VPS IP Authorized: $VPS_IP"

# Step 2: OS Detection
if command -v lsb_release > /dev/null; then
    OS=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)
else
    OS=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
fi

if [[ "$OS" != "Ubuntu" && "$OS" != "Debian" ]]; then
    error "Unsupported OS: $OS. Only Ubuntu 20.04 or Debian 9/10 supported."
fi

log "Detected OS: $OS $OS_VERSION"

# Step 3: Update System and Install Dependencies
log "Updating system and installing dependencies..."
if [[ "$OS" == "Debian" && "$OS_VERSION" == "9" ]]; then
    apt-get update && apt-get upgrade -y
    apt-get install -y curl wget unzip ufw iptables-persistent net-tools jq certbot python3-certbot-nginx openssh-server dropbear stunnel4 pptpd uuid-runtime
else
    apt update && apt upgrade -y
    apt install -y curl wget unzip ufw iptables-persistent net-tools jq certbot python3-certbot-nginx openssh-server dropbear stunnel4 pptpd uuid-runtime
fi

# Setup firewall dasar
ufw allow OpenSSH
ufw allow 80,443,8443,8080,8444/tcp
ufw allow 51820,1194,500,4500,1701/udp
ufw allow 1723/tcp
ufw --force enable
systemctl enable ufw

# Buat direktori config
mkdir -p /root/vpn-configs /etc/vpn-users

# Step 4: Input for SSH (Prioritas)
echo -e "${YELLOW}Setup SSH Tunneling (Prioritas). Masukkan detail:${NC}"
read -p "Username: " SSH_USER
read -sp "Password: " SSH_PASS
echo
read -p "Masa aktif (hari, default 30): " SSH_DAYS
SSH_DAYS=${SSH_DAYS:-30}
read -p "Batas bandwidth (GB, default 10): " SSH_BANDWIDTH
SSH_BANDWIDTH=${SSH_BANDWIDTH:-10}

# Add SSH user
useradd -m -s /bin/bash "$SSH_USER"
echo "$SSH_USER:$SSH_PASS" | chpasswd
chage -M "$SSH_DAYS" "$SSH_USER"  # Set expiry
log "SSH User '$SSH_USER' added with $SSH_DAYS days expiry and $SSH_BANDWIDTH GB bandwidth."

# Step 5: Install SSH Tunneling (OpenSSH + Dropbear + Stunnel)
log "Installing SSH Tunneling..."
# OpenSSH config
sed -i 's/#Port 22/Port 22\nPort 443/' /etc/ssh/sshd_config
systemctl restart ssh
ufw allow 22,443/tcp

# Dropbear config
sed -i 's/NO_START=1/NO_START=0/' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT="80 442"/' /etc/default/dropbear
systemctl restart dropbear
ufw allow 80,442/tcp

# Stunnel config (TLS for SSH)
cat > /etc/stunnel/stunnel.conf <<EOF
cert = /etc/ssl/certs/ssl-cert-snakeoil.pem
key = /etc/ssl/private/ssl-cert-snakeoil.key
[ssh]
accept = 443
connect = 127.0.0.1:22
EOF
systemctl enable stunnel4
systemctl restart stunnel4

# Bandwidth limit for SSH user (using tc)
UID=$(id -u "$SSH_USER")
tc qdisc add dev eth0 root handle 1: htb default 10 2>/dev/null || true
tc class add dev eth0 parent 1: classid 1:1 htb rate "${SSH_BANDWIDTH}gbit" 2>/dev/null || true
tc filter add dev eth0 protocol ip prio 1 u32 match ip src 0.0.0.0/0 match uid "$UID" 0xffff flowid 1:1 2>/dev/null || true
log "SSH bandwidth limit set for user $SSH_USER."

# Cron for monthly bandwidth reset
(crontab -l 2>/dev/null; echo "0 0 1 * * tc qdisc del dev eth0 root 2>/dev/null; tc qdisc add dev eth0 root handle 1: htb default 10; tc class add dev eth0 parent 1: classid 1:1 htb rate ${SSH_BANDWIDTH}gbit; tc filter add dev eth0 protocol ip prio 1 u32 match ip src 0.0.0.0/0 match uid $UID 0xffff flowid 1:1; echo 'Bandwidth reset for $SSH_USER' >> $LOG_FILE") | crontab -

# Cron for expiry (auto-delete user)
(crontab -l 2>/dev/null; echo "0 0 * * * [ \$(date +\%s) -ge \$(date -d \"+ $((SSH_DAYS * 86400)) seconds\" +\%s) ] && userdel -r $SSH_USER && echo 'User $SSH_USER expired' >> $LOG_FILE") | crontab -

# Generate SSH client config
cat > /root/vpn-configs/ssh-client.txt <<EOF
SSH Tunneling Config for User: $SSH_USER
SOCKS5 Proxy: ssh -D 1080 $SSH_USER@$VPS_IP -p 22
HTTP Proxy: ssh -L 8080:localhost:80 $SSH_USER@$VPS_IP -p 22
TLS Tunneling: ssh -p 443 $SSH_USER@$VPS_IP
Dropbear: ssh -p 80 $SSH_USER@$VPS_IP
EOF
log "SSH config saved to /root/vpn-configs/ssh-client.txt"

# Step 6: Install WireGuard
log "Installing WireGuard..."
curl -O https://raw.githubusercontent.com/hwdsl2/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh <<EOF
1
1
y
EOF
cp /root/wg0.conf /root/vpn-configs/wireguard.conf
rm wireguard-install.sh
ufw allow 51820/udp
log "WireGuard installed. Config: /root/vpn-configs/wireguard.conf"

# Step 7: Install OpenVPN
log "Installing OpenVPN..."
wget https://git.io/vpn -O openvpn-install.sh
chmod +x openvpn-install.sh
./openvpn-install.sh <<EOF
1
1
y
EOF
cp /root/client.ovpn /root/vpn-configs/openvpn.ovpn
rm openvpn-install.sh
ufw allow 1194/udp
log "OpenVPN installed. Config: /root/vpn-configs/openvpn.ovpn"

# Step 8: Install V2Ray/Xray (VMess/VLESS/Trojan/gRPC)
log "Installing Xray (V2Ray/VMess/VLESS/Trojan/gRPC)..."
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": [{ "id": "$(uuidgen)" }], "decryption": "none" },
      "streamSettings": { "network": "ws", "security": "tls" }
    },
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": { "clients": [{ "id": "$(uuidgen)" }] }
    },
    {
      "port": 8080,
      "protocol": "trojan",
      "settings": { "clients": [{ "password": "trojanpass" }] }
    },
    {
      "port": 8444,
      "protocol": "vless",
      "settings": { "clients": [{ "id": "$(uuidgen)" }], "decryption": "none" },
      "streamSettings": { "network": "grpc", "security": "tls", "grpcSettings": { "serviceName": "v2ray-grpc" } }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
systemctl restart xray
ufw allow 443,8443,8080,8444/tcp
cp /usr/local/etc/xray/config.json /root/vpn-configs/xray-config.json
log "Xray installed with gRPC. Config: /root/vpn-configs/xray-config.json"

# Step 9: Install IPsec/L2TP
log "Installing IPsec/L2TP..."
wget https://get.vpnsetup.net -O vpn.sh
chmod +x vpn.sh
./vpn.sh <<EOF
y
EOF
rm vpn.sh
ufw allow 500,4500/udp 1701/udp
log "IPsec/L2TP installed. User: vpnuser, Pass: vpnpass (edit /etc/ppp/chap-secrets)"

# Step 10: Install PPTP (Insecure)
log "Installing PPTP (Insecure)..."
cat > /etc/pptpd.conf <<EOF
localip 192.168.0.1
remoteip 192.168.0.234-238,192.168.0.245
EOF
echo "vpnuser pptpd vpnpass *" >> /etc/ppp/chap-secrets
systemctl restart pptpd
ufw allow 1723/tcp
log "PPTP installed. User: vpnuser, Pass: vpnpass (edit /etc/ppp/chap-secrets)"

# Step 11: Setup Domain (Optional, for V2Ray/TLS)
echo -e "${YELLOW}Setup Domain for V2Ray/TLS? (y/n): ${NC}"
read USE_DOMAIN
if [[ $USE_DOMAIN == "y" ]]; then
    read -p "Domain (e.g., vpn.example.com): " DOMAIN
    read -p "DNS Provider (cloudflare/namecheap/manual): " DNS_PROVIDER
    if [[ "$DNS_PROVIDER" == "cloudflare" ]]; then
        read -p "Cloudflare API Token: " CF_TOKEN
        read -p "Cloudflare Zone ID: " CF_ZONE
        curl -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE/dns_records" \
             -H "Authorization: Bearer $CF_TOKEN" \
             -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"$DOMAIN\",\"content\":\"$VPS_IP\",\"ttl\":120,\"proxied\":false}" || log "Cloudflare API failed; set manual A record."
        log "A record added for $DOMAIN via Cloudflare."
    elif [[ "$DNS_PROVIDER" == "namecheap" ]]; then
        read -p "Namecheap API Key: " NC_API_KEY
        read -p "Namecheap SLD (e.g., example for example.com): " NC_SLD
        read -p "Namecheap TLD (e.g., com for example.com): " NC_TLD
        curl -s "https://api.namecheap.com/xml.response?ApiUser=namecheap&ApiKey=$NC_API_KEY&UserName=namecheap&Command=namecheap.domains.dns.setHosts&ClientIp=$VPS_IP&SLD=$NC_SLD&TLD=$NC_TLD&HostName1=@&RecordType1=A&Address1=$VPS_IP&TTL1=120" | grep -q "CommandResponse" || log "Namecheap API failed; set manual A record."
        log "A record added for $DOMAIN via Namecheap."
    else
        log "Manual setup: Add A record for $DOMAIN to $VPS_IP in your DNS provider."
    fi
    # Nginx + Let's Encrypt
    apt install -y nginx
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@"$DOMAIN"
    cat > /etc/nginx/sites-available/vpn <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8443;
    }
    location /grpc {
        grpc_pass grpc://127.0.0.1:8444;
    }
}
EOF
    ln -s /etc/nginx/sites-available/vpn /etc/nginx/sites-enabled/
    systemctl restart nginx
    log "Domain $DOMAIN setup with TLS and gRPC."
fi

log "All VPNs installed successfully! Reboot recommended: reboot"

# Step 12: Post-Install Menu (Interaktif)
show_menu() {
    while true; do
        echo -e "${GREEN}=== Multi-VPN & Domain Manager for Ubuntu 20.04/Debian 9/10 ===${NC}"
        echo "All VPNs installed successfully! Select an option:"
        echo "1. Manage VPN Users"
        echo "2. Setup Domain (Cloudflare/Namecheap/Manual)"
        echo "3. Monitor & Log VPN"
        echo "4. Backup & Restore Config"
        echo "5. Uninstall VPN"
        echo "6. Reboot VPS / Set Auto Reboot"
        echo "0. Exit"
        read -p "Enter choice (0-6): " choice

        case $choice in
            1)
                manage_users
                ;;
            2)
                setup_domain_menu
                ;;
            3)
                monitor_menu
                ;;
            4)
                backup_menu
                ;;
            5)
                uninstall_menu
                ;;
            6)
                reboot_menu
                ;;
            0)
                exit 0
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

manage_users() {
    while true; do
        echo -e "${YELLOW}=== Manage VPN Users ===${NC}"
        echo "Select protocol:"
        echo "1. SSH Tunneling (OpenSSH, Dropbear, Stunnel)"
        echo "2. WireGuard"
        echo "3. OpenVPN"
        echo "4. V2Ray (VMess/VLESS/Trojan/gRPC)"
        echo "5. IPsec/L2TP"
        echo "6. PPTP"
        echo "7. SETTING"
        echo "0. Back to Main Menu"
        read -p "Enter choice (0-7): " subchoice

        case $subchoice in
            1)
                manage_ssh_users
                ;;
            2)
                bash wireguard-install.sh
                ;;
            3)
                bash openvpn-install.sh
                ;;
            4)
                nano /usr/local/etc/xray/config.json
                systemctl restart xray
                ;;
            5)
                nano /etc/ppp/chap-secrets
                systemctl restart ipsec xl2tpd
                ;;
            6)
                nano /etc/ppp/chap-secrets
                systemctl restart pptpd
                ;;
            7)
                setting_menu
                ;;
            0)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

manage_ssh_users() {
    while true; do
        echo -e "${YELLOW}=== Manage SSH Tunneling Users ===${NC}"
        echo "1. Add User"
        echo "2. Delete User"
        echo "3. List Users"
        echo "4. Extend User Active Period"
        echo "5. Set User Bandwidth Limit"
        echo "6. Generate Client Config"
        echo "7. Reset Bandwidth Manually"
        echo "8. Back"
        read -p "Enter choice (1-8): " sshchoice

        case $sshchoice in
            1)
                read -p "Username: " NEW_USER
                read -sp "Password: " NEW_PASS
                echo
                read -p "Active days: " NEW_DAYS
                read -p "Bandwidth GB: " NEW_BANDWIDTH
                useradd -m -s /bin/bash "$NEW_USER"
                echo "$NEW_USER:$NEW_PASS" | chpasswd
                chage -M "$NEW_DAYS" "$NEW_USER"
                NEW_UID=$(id -u "$NEW_USER")
                tc class add dev eth0 parent 1: classid 1:2 htb rate "${NEW_BANDWIDTH}gbit" 2>/dev/null || true
                tc filter add dev eth0 protocol ip prio 1 u32 match ip src 0.0.0.0/0 match uid "$NEW_UID" 0xffff flowid 1:2 2>/dev/null || true
                (crontab -l 2>/dev/null; echo "0 0 1 * * tc qdisc del dev eth0 root 2>/dev/null; tc qdisc add dev eth0 root handle 1: htb default 10; tc class add dev eth0 parent 1: classid 1:2 htb rate ${NEW_BANDWIDTH}gbit; tc filter add dev eth0 protocol ip prio 1 u32 match ip src 0.0.0.0/0 match uid $NEW_UID 0xffff flowid 1:2; echo 'Bandwidth reset for $NEW_USER' >> $LOG_FILE") | crontab -
                (crontab -l 2>/dev/null; echo "0 0 * * * [ \$(date +\%s) -ge \$(date -d \"+ $((NEW_DAYS * 86400)) seconds\" +\%s) ] && userdel -r $NEW_USER && echo 'User $NEW_USER expired' >> $LOG_FILE") | crontab -
                log "SSH User '$NEW_USER' added."
                ;;
            2)
                read -p "Username to delete: " DEL_USER
                userdel -r "$DEL_USER" 2>/dev/null
                log "SSH User '$DEL_USER' deleted."
                ;;
            3)
                echo "SSH Users:"
                grep '/bin/bash' /etc/passwd | cut -d: -f1
                ;;
            4)
                read -p "Username: " EXT_USER
                read -p "Additional days: " EXT_DAYS
                chage -M -1 "$EXT_USER"
                chage -M "$(( $(chage -l "$EXT_USER" | grep "Maximum number of days" | awk '{print $NF}' ) + EXT_DAYS ))" "$EXT_USER"
                log "Extended $EXT_USER by $EXT_DAYS days."
                ;;
            5)
                read -p "Username: " BW_USER
                read -p "New bandwidth GB: " NEW_BW
                BW_UID=$(id -u "$BW_USER")
                tc class change dev eth0 parent 1: classid 1:2 htb rate "${NEW_BW}gbit" 2>/dev/null || true
                log "Bandwidth updated for $BW_USER."
                ;;
            6)
                cat /root/vpn-configs/ssh-client.txt
                ;;
            7)
                read -p "Username: " RST_USER
                RST_UID=$(id -u "$RST_USER")
                RST_BW=$(tc class show dev eth0 | grep "class htb 1:2" | awk '{print $5}' | head -n1)
                tc qdisc del dev eth0 root 2>/dev/null
                tc qdisc add dev eth0 root handle 1: htb default 10
                tc class add dev eth0 parent 1: classid 1:2 htb rate "$RST_BW" 2>/dev/null || true
                tc filter add dev eth0 protocol ip prio 1 u32 match ip src 0.0.0.0/0 match uid "$RST_UID" 0xffff flowid 1:2 2>/dev/null || true
                log "Bandwidth reset manually for $RST_USER."
                ;;
            8)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

setting_menu() {
    while true; do
        echo -e "${YELLOW}=== SETTING ===${NC}"
        echo "1. Configure Firewall (UFW)"
        echo "2. Change VPN Ports"
        echo "3. Return to Main Menu"
        read -p "Enter choice (1-3): " setchoice

        case $setchoice in
            1)
                echo "UFW Status: $(ufw status)"
                read -p "Command (e.g., ufw allow 1194/udp): " ufw_cmd
                $ufw_cmd
                log "UFW: $ufw_cmd"
                ;;
            2)
                read -p "Port to change (e.g., SSH 22 to 2222): " port_change
                sed -i "s/Port 22/Port $port_change/" /etc/ssh/sshd_config
                systemctl restart ssh
                log "Port changed to $port_change."
                ;;
            3)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

setup_domain_menu() {
    while true; do
        echo -e "${YELLOW}=== Setup Domain ===${NC}"
        echo "1. Manual Domain Setup"
        echo "2. Setup via Cloudflare API"
        echo "3. Setup via Namecheap API"
        echo "4. Install Nginx & Let's Encrypt"
        echo "5. Back to Main Menu"
        read -p "Enter choice (1-5): " domchoice
        case $domchoice in
            1)
                echo "Manual setup: Add A record for your domain to $VPS_IP in your DNS provider."
                ;;
            2)
                read -p "Domain: " DOMAIN
                read -p "Cloudflare API Token: " CF_TOKEN
                read -p "Cloudflare Zone ID: " CF_ZONE
                curl -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE/dns_records" \
                     -H "Authorization: Bearer $CF_TOKEN" \
                     -H "Content-Type: application/json" \
                     --data "{\"type\":\"A\",\"name\":\"$DOMAIN\",\"content\":\"$VPS_IP\",\"ttl\":120,\"proxied\":false}"
                log "A record added for $DOMAIN via Cloudflare."
                ;;
            3)
                read -p "Domain: " DOMAIN
                read -p "Namecheap API Key: " NC_API_KEY
                read -p "Namecheap SLD (e.g., example for example.com): " NC_SLD
                read -p "Namecheap TLD (e.g., com for example.com): " NC_TLD
                curl -s "https://api.namecheap.com/xml.response?ApiUser=namecheap&ApiKey=$NC_API_KEY&UserName=namecheap&Command=namecheap.domains.dns.setHosts&ClientIp=$VPS_IP&SLD=$NC_SLD&TLD=$NC_TLD&HostName1=@&RecordType1=A&Address1=$VPS_IP&TTL1=120" | grep -q "CommandResponse" || log "Namecheap API failed; set manual A record."
                log "A record added for $DOMAIN via Namecheap."
                ;;
            4)
                read -p "Domain: " DOMAIN
                apt install -y nginx
                certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@"$DOMAIN"
                cat > /etc/nginx/sites-available/vpn <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8443;
    }
    location /grpc {
        grpc_pass grpc://127.0.0.1:8444;
    }
}
EOF
                ln -s /etc/nginx/sites-available/vpn /etc/nginx/sites-enabled/
                systemctl restart nginx
                log "Nginx and Let's Encrypt installed for $DOMAIN with gRPC."
                ;;
            5)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

monitor_menu() {
    while true; do
        echo -e "${YELLOW}=== Monitor & Log VPN ===${NC}"
        echo "1. Check VPN Service Status"
        echo "2. View VPN Logs"
        echo "3. Monitor Active Users"
        echo "4. View Bandwidth Usage"
        echo "5. Back to Main Menu"
        read -p "Enter choice (1-5): " monchoice
        case $monchoice in
            1)
                systemctl status ssh dropbear stunnel4 wg-quick@wg0 openvpn xray pptpd
                ;;
            2)
                journalctl -u ssh -n 10
                ;;
            3)
                who
                ;;
            4)
                tc -s class show dev eth0
                ;;
            5)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

backup_menu() {
    while true; do
        echo -e "${YELLOW}=== Backup & Restore Config ===${NC}"
        echo "1. Backup All Configs"
        echo "2. Restore Configs"
        echo "3. Back to Main Menu"
        read -p "Enter choice (1-3): " backchoice
        case $backchoice in
            1)
                tar -czf "/root/vpn-configs/backup-$(date +%Y%m%d).tar.gz" /root/vpn-configs /etc/vpn-users /usr/local/etc/xray /etc/openvpn /etc/ipsec.d /etc/pptpd.conf /etc/ppp/chap-secrets
                log "Backup created."
                ;;
            2)
                read -p "Backup file: " restore_file
                tar -xzf "$restore_file" -C /
                log "Restored from $restore_file."
                ;;
            3)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

uninstall_menu() {
    while true; do
        echo -e "${YELLOW}=== Uninstall VPN ===${NC}"
        echo "1. Uninstall SSH Tunneling"
        echo "2. Uninstall WireGuard"
        echo "3. Uninstall OpenVPN"
        echo "4. Uninstall V2Ray (VMess/VLESS/Trojan/gRPC)"
        echo "5. Uninstall IPsec/L2TP"
        echo "6. Uninstall PPTP"
        echo "7. Uninstall All"
        echo "8. Back to Main Menu"
        read -p "Enter choice (1-8): " unchoice
        case $unchoice in
            1)
                userdel -r "$SSH_USER" 2>/dev/null
                systemctl stop ssh dropbear stunnel4
                apt purge -y openssh-server dropbear stunnel4
                ufw delete allow 22,443,80,442/tcp
                log "SSH uninstalled."
                ;;
            2)
                wg-quick down wg0 2>/dev/null
                apt purge -y wireguard
                ufw delete allow 51820/udp
                log "WireGuard uninstalled."
                ;;
            3)
                systemctl stop openvpn
                apt purge -y openvpn
                ufw delete allow 1194/udp
                log "OpenVPN uninstalled."
                ;;
            4)
                systemctl stop xray
                bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove
                ufw delete allow 443,8443,8080,8444/tcp
                log "Xray uninstalled."
                ;;
            5)
                systemctl stop ipsec xl2tpd
                apt purge -y strongswan xl2tpd
                ufw delete allow 500,4500/udp 1701/udp
                log "IPsec/L2TP uninstalled."
                ;;
            6)
                systemctl stop pptpd
                apt purge -y pptpd
                ufw delete allow 1723/tcp
                log "PPTP uninstalled."
                ;;
            7)
                userdel -r "$SSH_USER" 2>/dev/null
                systemctl stop ssh dropbear stunnel4 wg-quick@wg0 openvpn xray pptpd
                apt purge -y openssh-server dropbear stunnel4 wireguard openvpn strongswan xl2tpd pptpd
                bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove
                ufw delete allow 22,443,80,442,51820,1194,500,4500,1701/udp 1723,8443,8080,8444/tcp
                log "All VPNs uninstalled."
                ;;
            8)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

reboot_menu() {
    while true; do
        echo -e "${YELLOW}=== Reboot VPS / Set Auto Reboot ===${NC}"
        echo "1. Reboot VPS Now"
        echo "2. Set Auto Reboot Schedule"
        echo "3. Back to Main Menu"
        read -p "Enter choice (1-3): " rebchoice
        case $rebchoice in
            1)
                reboot
                ;;
            2)
                read -p "Schedule (e.g., '0 3 * * *' for daily at 3 AM): " schedule
                (crontab -l 2>/dev/null; echo "$schedule reboot") | crontab -
                log "Auto reboot set: $schedule"
                ;;
            3)
                return
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

# Launch Menu
show_menu
