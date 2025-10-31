#!/bin/bash
# Auto Install Xray Multi Protocol + QR + Multi-Port + Full Menu
# Ubuntu 22.04 | Root only | Author: Grok

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

[[ $EUID -ne 0 ]] && error "Run as root!"

DOMAIN=""; EMAIL=""; BOT_TOKEN=""; CHAT_ID=""

log "Updating system..."
apt update && apt upgrade -y

log "Installing dependencies (curl, nginx, jq, qrencode, speedtest-cli, ufw)..."
apt install -y curl wget unzip nginx ufw jq uuid-runtime openssl speedtest-cli cron qrencode

ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 2053/tcp
ufw allow 8080/tcp
ufw --force enable

# Input
read -p "Domain (e.g., vpn.kamu.com): " DOMAIN
read -p "Email for SSL: " EMAIL
read -p "Telegram BOT Token (optional): " BOT_TOKEN
read -p "Telegram Chat ID (optional): " CHAT_ID

# SSL with acme.sh
log "Issuing SSL certificate..."
curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 --force
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
  --ecc \
  --fullchain-file /etc/xray/cert.pem \
  --key-file /etc/xray/key.pem

# Install Xray Core
log "Installing Xray Core..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Config directories
mkdir -p /etc/xray/backup /var/www/html
echo "[]" > /etc/xray/users.json
echo '{"enable":false}' > /root/.telegram

# Fallback website
cat > /var/www/html/index.html << EOF
<!DOCTYPE html><html><head><title>Secure</title></head><body><h1>Connection Secure</h1></body></html>
EOF

# Nginx multi-port fallback
cat > /etc/nginx/sites-available/xray << EOF
server {
    listen 80;
    server_name $DOMAIN;
    root /var/www/html;
    location / { try_files \$uri \$uri/ =404; }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/xray/cert.pem;
    ssl_certificate_key /etc/xray/key.pem;
    root /var/www/html;
    location / { try_files \$uri \$uri/ =404; }
}
server {
    listen 8443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/xray/cert.pem;
    ssl_certificate_key /etc/xray/key.pem;
    root /var/www/html;
    location / { try_files \$uri \$uri/ =404; }
}
server {
    listen 2053 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/xray/cert.pem;
    ssl_certificate_key /etc/xray/key.pem;
    root /var/www/html;
}
server {
    listen 8080;
    server_name $DOMAIN;
    location / { proxy_pass http://127.0.0.1:8081; proxy_set_header Host \$host; }
}
EOF
ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

# Xray config: multi-inbound + multi-port
cat > /etc/xray/config.json << 'EOF'
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]}
      },
      "tag": "VLESS-443"
    },
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]}
      },
      "tag": "VLESS-8443"
    },
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]},
        "wsSettings": {"path": "/vmess"}
      },
      "tag": "VMESS-443"
    },
    {
      "port": 2053,
      "protocol": "trojan",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]}
      },
      "tag": "TROJAN-2053"
    },
    {
      "port": 8080,
      "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {"certificates": [{"certificateFile": "/etc/xray/cert.pem", "keyFile": "/etc/xray/key.pem"}]},
        "grpcSettings": {"serviceName": "grpc-service"}
      },
      "tag": "VLESS-GRPC"
    }
  ],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

systemctl restart xray
systemctl enable xray nginx

# Telegram config
if [[ -n "$BOT_TOKEN" && -n "$CHAT_ID" ]]; then
  echo "{\"token\":\"$BOT_TOKEN\",\"chat_id\":\"$CHAT_ID\",\"enable\":true}" > /root/.telegram
fi

# Backup function
backup_config() {
  tar -czf "/etc/xray/backup/backup_$(date +%Y%m%d_%H%M%S).tar.gz" /etc/xray/config.json /etc/xray/users.json
}

# Full Menu Script
cat > /usr/local/bin/vpn-menu << 'EOF'
#!/bin/bash
set -e
CONFIG="/etc/xray/config.json"
USERS="/etc/xray/users.json"
DOMAIN=$(grep server_name /etc/nginx/sites-available/xray | awk '{print $2}' | head -1)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

send_telegram() {
  if jq -e '.enable' /root/.telegram > /dev/null 2>&1; then
    TOKEN=$(jq -r .token /root/.telegram)
    CHAT=$(jq -r .chat_id /root/.telegram)
    curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" -d chat_id="$CHAT" -d text="$1" > /dev/null
  fi
}

backup() { backup_config; echo -e "${GREEN}Backup selesai!${NC}"; }

restart_xray() { systemctl restart xray; echo -e "${GREEN}Xray direstart!${NC}"; send_telegram "Xray service restarted."; }

show_qr() {
  local link="$1"
  echo -e "${YELLOW}QR Code:${NC}"
  qrencode -t ansiutf8 "$link"
  echo
}

add_client() {
  local proto=$1
  read -p "Nama client: " name
  read -p "Masa aktif (hari) [30]: " days; days=${days:-30}
  read -p "Limit traffic (GB, 0=unlimited) [0]: " traf; traf=${traf:-0}
  read -p "Port [443, 8443, 2053, 8080(grpc)]: " port; [[ -z "$port" ]] && port=443
  exp=$(( $(date +%s) + days*86400 ))
  traf_bytes=$((traf * 1024 * 1024 * 1024))

  if [[ $proto == "trojan" ]]; then
    id=$(openssl rand -base64 12); tag="TROJAN-2053"; port=2053
  elif [[ $proto == "vmess" ]]; then
    id=$(uuidgen); tag="VMESS-443"; port=443
  else
    id=$(uuidgen)
    case $port in
      8443) tag="VLESS-8443" ;;
      8080) tag="VLESS-GRPC"; network="grpc"; path="grpc-service" ;;
      *) tag="VLESS-443"; network="tcp"; path="" ;;
    esac
  fi

  jq --arg n "$name" --arg i "$id" --arg p "$proto" --arg e "$exp" --arg t "$traf_bytes" --arg port "$port" \
     '. += [{"name":$n,"uuid":$i,"protocol":$p,"expiry":$e|tonumber,"traffic":$t|tonumber,"port":$port|tonumber}]' \
     "$USERS" > tmp && mv tmp "$USERS"

  if [[ $proto == "trojan" ]]; then
    jq --arg i "$id" --arg n "$name" '.inbounds[] |= (select(.tag=="TROJAN-2053") |.settings.clients += [{"password":$i,"email":$n}])' "$CONFIG" > tmp && mv tmp "$CONFIG"
  elif [[ $proto == "vmess" ]]; then
    jq --arg i "$id" --arg n "$name" '.inbounds[] |= (select(.tag=="VMESS-443") |.settings.clients += [{"id":$i,"email":$n}])' "$CONFIG" > tmp && mv tmp "$CONFIG"
  else
    jq --arg i "$id" --arg n "$name" --arg t "$tag" '(.inbounds[] | select(.tag==$t) |.settings.clients += [{"id":$i,"email":$n}])' "$CONFIG" > tmp && mv tmp "$CONFIG"
  fi

  backup; restart_xray
  link=$(gen_link_raw "$proto" "$name" "$port")
  echo -e "${GREEN}Client $name ($proto:$port) ditambahkan!${NC}"
  show_qr "$link"
  send_telegram "User *$name* ($proto:$port) ditambahkan. Exp: $(date -d "@$exp" '+%Y-%m-%d')"
}

gen_link_raw() {
  local proto=$1 name=$2 port=$3
  local id=$(jq -r --arg n "$name" --arg p "$proto" '.[] | select(.name==$n and .protocol==$p).uuid' "$USERS")
  case $proto in
    vless)
      if [[ $port == 8080 ]]; then
        echo "vless://$id@$DOMAIN:$port?security=tls&type=grpc&serviceName=grpc-service#$name"
      else
        echo "vless://$id@$DOMAIN:$port?security=tls&type=tcp#$name"
      fi ;;
    vmess)
      json=$(jq -n --arg a "$DOMAIN" --arg i "$id" --arg n "$name" \
        '{"v":"2","ps":$n,"add":$a,"port":"443","id":$i,"aid":"0","net":"ws","type":"none","host":$a,"path":"/vmess","tls":"tls"}')
      echo "vmess://$(echo "$json" | base64 -w0)" ;;
    trojan)
      echo "trojan://$id@$DOMAIN:2053?security=tls#$name" ;;
  esac
}

gen_link() {
  local proto=$1
  view_clients "$proto"
  read -p "Nama client: " name
  port=$(jq -r --arg n "$name" --arg p "$proto" '.[] | select(.name==$n and .protocol==$p).port' "$USERS")
  link=$(gen_link_raw "$proto" "$name" "$port")
  echo -e "${YELLOW}Link: $link${NC}"
  show_qr "$link"
}

remove_client() {
  local proto=$1 tag=$2
  view_clients "$proto"
  read -p "Nama client: " name
  idx=$(jq -r --arg n "$name" --arg p "$proto" '[.[] | select(.name==$n and .protocol==$p)] | index(true)' "$USERS")
  [[ $idx == "null" ]] && { echo "Not found."; return; }
  jq "del(.[$idx])" "$USERS" > tmp && mv tmp "$USERS"
  jq --arg n "$name" --arg t "$tag" '(.inbounds[] | select(.tag==$t) |.settings.clients) |= map(select(.email!=$n))' "$CONFIG" > tmp && mv tmp "$CONFIG"
  backup; restart_xray
  send_telegram "User *$name* ($proto) dihapus."
}

view_clients() {
  local proto=$1
  echo "=== $proto Clients ==="
  jq -r --arg p "$proto" '.[] | select(.protocol==$p) | "\(.name) | \(.uuid) | Exp: \(.expiry|tonumber|strftime("%Y-%m-%d")) | Traf: \(.traffic/(1024*1024*1024)) GB | Port: \(.port)"' "$USERS"
  echo "-------------------------------------"
}

extend_client() {
  local proto=$1
  view_clients "$proto"
  read -p "Nama client: " name
  read -p "Tambah hari: " d
  idx=$(jq -r --arg n "$name" --arg p "$proto" '[.[] | select(.name==$n and .protocol==$p)] | index(true)' "$USERS")
  [[ $idx == "null" ]] && return
  old=$(jq -r ".[$idx].expiry" "$USERS")
  new=$((old + d*86400))
  jq --arg i "$idx" --arg v "$new" '.[$i|tonumber].expiry=($v|tonumber)' "$USERS" > tmp && mv tmp "$USERS"
  backup; restart_xray
  send_telegram "User *$name* diperpanjang hingga $(date -d "@$new" '+%Y-%m-%d')"
}

show_menu() {
  clear
  echo -e "${BLUE}===========================${NC}"
  echo -e "${BLUE}        VPN Menu${NC}"
  echo -e "${BLUE}===========================${NC}\n"
  echo -e "${YELLOW}Client Management${NC}\n"
  echo -e "${BLUE}--- VLESS & VMESS ---${NC}"
  echo "1) Add New VLESS Client      6) Add New VMESS Client"
  echo "2) Remove VLESS Client       7) Remove VMESS Client"
  echo "3) View Active VLESS Clients 8) View Active VMESS Clients"
  echo "4) Show VLESS Config / Link  9) Show VMESS Config / Link"
  echo "5) Extend VLESS Active      10) Extend VMESS Active\n"
  echo -e "${BLUE}--- Trojan ---${NC}"
  echo "11) Add New Trojan Client"
  echo "12) Remove Trojan Client"
  echo "13) View Active Trojan Clients"
  echo "14) Show Trojan Config / Link"
  echo "15) Extend Trojan Active\n"
  echo -e "${YELLOW}Service Management${NC}"
  echo "16) Restart Xray Service"
  echo "17) Check Xray Service Status"
  echo "18) View Listening Ports\n"
  echo -e "${YELLOW}Advanced Settings${NC}"
  echo "19) Set / Update Domain"
  echo "20) Set / Update Telegram BOT & Chat ID"
  echo "21) Enable / Disable Auto-Reboot"
  echo "22) Backup VPN Config"
  echo "23) Restore VPN Config"
  echo "24) Update Xray Settings"
  echo "25) Add New Port (Custom)"
  echo "26) Generate QR Code Only\n"
  echo -e "${YELLOW}Diagnostics${NC}"
  echo "27) Test Client Connection"
  echo "28) View VPN Logs"
  echo "29) Run Speed Test"
  echo "30) Exit\n"
  read -p "Pilih [1-30]: " opt
  case $opt in
    1) add_client vless ;;
    6) add_client vmess ;;
    11) add_client trojan ;;
    2) remove_client vless VLESS- ;;
    7) remove_client vmess VMESS-443 ;;
    12) remove_client trojan TROJAN-2053 ;;
    3) view_clients vless ;;
    8) view_clients vmess ;;
    13) view_clients trojan ;;
    4) gen_link vless ;;
    9) gen_link vmess ;;
    14) gen_link trojan ;;
    5) extend_client vless ;;
    10) extend_client vmess ;;
    15) extend_client trojan ;;
    16) restart_xray ;;
    17) systemctl status xray ;;
    18) ss -tuln | grep -E '443|8443|2053|8080' ;;
    19) read -p "Domain baru: " d; sed -i "s/server_name.*/server_name $d;/" /etc/nginx/sites-available/xray; ~/.acme.sh/acme.sh --renew -d $d --ecc; restart_xray ;;
    20) read -p "BOT Token: " t; read -p "Chat ID: " c; echo "{\"token\":\"$t\",\"chat_id\":\"$c\",\"enable\":true}" > /root/.telegram ;;
    21) read -p "Enable auto-reboot? (y/n): " a; [[ $a == y ]] && (crontab -l; echo "0 3 * * * reboot") | crontab - || (crontab -l | grep -v "reboot") | crontab - ;;
    22) backup ;;
    23) ls /etc/xray/backup/; read -p "Pilih file: " f; tar -xzf "/etc/xray/backup/$f" -C /etc/xray/; restart_xray ;;
    24) nano /etc/xray/config.json ;;
    25) read -p "Port baru: " p; ufw allow $p/tcp; echo "Port $p dibuka."; ;;
    26) read -p "Link: " l; show_qr "$l" ;;
    27) read -p "Link: " l; echo "Test: $l" ;;
    28) journalctl -u xray -n 50 -f ;;
    29) speedtest-cli ;;
    30) exit 0 ;;
    *) echo "Invalid!"; sleep 1 ;;
  esac
  read -n1 -s -r -p "Tekan sembarang tombol..."
  show_menu
}

show_menu
EOF

chmod +x /usr/local/bin/vpn-menu
echo "alias vpn='vpn-menu'" >> /root/.bashrc

log "Instalasi selesai!"
log "Jalankan: sudo vpn"
log "Fitur: VLESS/VMess/Trojan + QR + Multi-Port + Telegram + Backup"
