#!/bin/bash

# Script Name: Universal Cloud-Based VPN Setup Script
# Author: Shaan
# Description: Automated setup for V2Ray, SSH WebSocket, OpenVPN, WireGuard, and Nginx with SSL, compatible with any cloud CDN
# Version: 2.5
# Date: April 07, 2025
# GitHub: github.com/shaa2020/vpn-setup-universal
# License: MIT

# Exit on any error
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script as root (e.g., with sudo)."
    exit 1
fi

# Configurable variables
V2RAY_WS_PATH="/ray"                  # V2Ray WebSocket path
SSH_WS_PATH="/ssh"                    # SSH WebSocket path
V2RAY_PORT="10000"                    # V2Ray WebSocket port
WEBSOCAT_PORT="8080"                  # Websocat port for SSH
OVPN_PORT="1194"                      # OpenVPN port (UDP)
WG_PORT="51820"                       # WireGuard port
EXPIRE_DATE="2025-04-11"              # Expiration date
LOG_FILE="/var/log/vpn_setup.log"     # Log file
CONFIG_DIR="/var/www/configs"         # Directory for config files

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Get server public IP
IP=$(curl -s ifconfig.me || curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
if [ -z "$IP" ]; then
    echo -e "${RED}Error: Could not determine server IP${NC}"
    exit 1
fi
LOCATION=$(curl -s "http://ipinfo.io/$IP" | jq -r '.city + ", " + .region + ", " + .country' || echo "Unknown")

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Trap for cleanup on error
cleanup() {
    echo -e "${RED}Script terminated. Cleaning up...${NC}"
    log "Script terminated, cleaning up"
    [ -f /tmp/websocat ] && rm -f /tmp/websocat
}
trap cleanup EXIT

# Function to validate domain and email inputs
validate_inputs() {
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid domain format${NC}"
        log "Invalid domain: $DOMAIN"
        exit 1
    fi
    if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid email format${NC}"
        log "Invalid email: $EMAIL"
        exit 1
    fi
    if [ -z "$CDN_DOMAIN" ]; then
        echo -e "${RED}Error: CDN domain not provided${NC}"
        log "CDN domain not provided"
        exit 1
    fi
}

# Function to check if port is available
check_port() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        echo -e "${RED}Error: Port $port is already in use${NC}"
        log "Port $port already in use"
        exit 1
    fi
}

# Function to verify service status
verify_service() {
    local service=$1
    if ! systemctl is-active --quiet "$service"; then
        echo -e "${RED}Error: $service failed to start${NC}"
        log "$service failed to start"
        exit 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    log "Checking prerequisites"
    for cmd in curl jq systemctl netstat wg openssl nginx; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Error: Required command $cmd not found${NC}"
            log "Missing command: $cmd"
            exit 1
        fi
    done
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        echo -e "${RED}Error: No internet connectivity${NC}"
        log "No internet connectivity"
        exit 1
    fi
}

# Function to configure firewall (universal)
configure_firewall() {
    echo "Configuring firewall..."
    log "Configuring firewall"
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow "$OVPN_PORT"/udp
        ufw allow "$WG_PORT"/udp
        ufw allow "$V2RAY_PORT"/tcp
        ufw allow "$WEBSOCAT_PORT"/tcp
        ufw --force enable
    else
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        iptables -A INPUT -p udp --dport "$OVPN_PORT" -j ACCEPT
        iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        iptables -A INPUT -p tcp --dport "$V2RAY_PORT" -j ACCEPT
        iptables -A INPUT -p tcp --dport "$WEBSOCAT_PORT" -j ACCEPT
        iptables -A INPUT -j DROP
        iptables-save > /etc/iptables/rules.v4
    fi
    log "Firewall configured"
}

# Function to update system and install dependencies
install_dependencies() {
    echo "Updating system and installing dependencies..."
    log "Installing dependencies"
    apt update -y && apt upgrade -y
    apt install -y curl nginx certbot python3-certbot-nginx unzip socat openvpn easy-rsa uuid-runtime jq wireguard
}

# Function to install Websocat
install_websocat() {
    echo "Installing Websocat..."
    log "Installing Websocat"
    wget -O /tmp/websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl
    chmod +x /tmp/websocat
    mv /tmp/websocat /usr/local/bin/websocat
}

# Function to install and configure V2Ray
configure_v2ray() {
    echo "Installing V2Ray..."
    log "Installing V2Ray"
    curl -L -s https://raw.githubusercontent.com/v2fly/v2ray-core/master/install-release.sh | bash
    V2RAY_UUID=$(uuidgen)
    cat > /etc/v2ray/config.json <<EOF
{
  "inbounds": [{
    "port": $V2RAY_PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [{ "id": "$V2RAY_UUID", "alterId": 0 }]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": { "path": "$V2RAY_WS_PATH" }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
    chmod 644 /etc/v2ray/config.json
    systemctl enable v2ray
    systemctl restart v2ray
    verify_service "v2ray"
    log "V2Ray configured successfully"
}

# Function to set up SSL with Certbot
setup_ssl() {
    echo "Obtaining SSL certificate with Certbot..."
    log "Setting up SSL"
    certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive --redirect
    echo "0 0,12 * * * root certbot renew --quiet" > /etc/cron.d/certbot-renew
    chmod 644 /etc/cron.d/certbot-renew
    log "SSL configured with auto-renewal"
}

# Function to configure Nginx (CDN-compatible)
configure_nginx() {
    echo "Configuring Nginx..."
    log "Configuring Nginx"
    mkdir -p "$CONFIG_DIR"
    cat > /etc/nginx/sites-available/v2ray <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location $V2RAY_WS_PATH {
        proxy_pass http://127.0.0.1:$V2RAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 300s;
    }

    location $SSH_WS_PATH {
        proxy_pass http://127.0.0.1:$WEBSOCAT_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 300s;
    }

    location /configs/ {
        alias $CONFIG_DIR/;
        autoindex on;
        expires 1d;
    }
}
EOF
    chmod 644 /etc/nginx/sites-available/v2ray
    ln -sf /etc/nginx/sites-available/v2ray /etc/nginx/sites-enabled/
    nginx -t
    systemctl restart nginx
    verify_service "nginx"
    log "Nginx configured successfully"
}

# Function to configure OpenVPN
configure_openvpn() {
    echo "Setting up OpenVPN..."
    log "Setting up OpenVPN"
    cd /etc/openvpn
    if [ ! -d "easy-rsa" ]; then
        make-cadir easy-rsa
    fi
    cd easy-rsa
    ./easyrsa init-pki
    echo "ca" | ./easyrsa build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass

    cat > /etc/openvpn/server.conf <<EOF
port $OVPN_PORT
proto udp
dev tun
ca easy-rsa/pki/ca.crt
cert easy-rsa/pki/issued/server.crt
key easy-rsa/pki/private/server.key
dh easy-rsa/pki/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF
    chmod 600 /etc/openvpn/server.conf
    systemctl enable openvpn@server
    systemctl restart openvpn@server
    verify_service "openvpn@server"
    log "OpenVPN configured successfully"
}

# Function to configure WireGuard
configure_wireguard() {
    echo "Installing WireGuard..."
    log "Installing WireGuard"
    check_port "$WG_PORT"
    WG_PRIVATE_KEY=$(wg genkey)
    WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
    WG_IP="10.9.0.1"

    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $WG_PRIVATE_KEY
Address = $WG_IP/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = #CLIENT_PUBLIC_KEY#
AllowedIPs = 10.9.0.2/32
EOF
    chmod 600 /etc/wireguard/wg0.conf
    systemctl enable wg-quick@wg0
    systemctl restart wg-quick@wg0
    verify_service "wg-quick@wg0"

    WG_CLIENT_PRIVATE_KEY=$(wg genkey)
    WG_CLIENT_PUBLIC_KEY=$(echo "$WG_CLIENT_PRIVATE_KEY" | wg pubkey)
    sed -i "s/#CLIENT_PUBLIC_KEY#/$WG_CLIENT_PUBLIC_KEY/" /etc/wireguard/wg0.conf
    systemctl restart wg-quick@wg0

    cat > /etc/wireguard/client.conf <<EOF
[Interface]
PrivateKey = $WG_CLIENT_PRIVATE_KEY
Address = 10.9.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = $WG_PUBLIC_KEY
Endpoint = $DOMAIN:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 644 /etc/wireguard/client.conf
    log "WireGuard configured successfully"
}

# Function to create OpenVPN client
create_openvpn_client() {
    echo "Creating OpenVPN account..."
    log "Creating OpenVPN client"
    OVPN_USER="user_$(openssl rand -hex 4)"
    OVPN_PASS=$(openssl rand -base64 12)
    echo "Generated Username: $OVPN_USER"
    echo "Generated Password: $OVPN_PASS"

    cd /etc/openvpn/easy-rsa
    ./easyrsa build-client-full "$OVPN_USER" nopass

    cat > /etc/openvpn/"$OVPN_USER".ovpn <<EOF
client
dev tun
proto udp
remote $DOMAIN $OVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
cipher AES-256-CBC
verb 3
<ca>
$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/easy-rsa/pki/issued/"$OVPN_USER".crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/pki/private/"$OVPN_USER".key)
</key>
EOF
    chmod 644 /etc/openvpn/"$OVPN_USER".ovpn
    cp /etc/openvpn/"$OVPN_USER".ovpn "$CONFIG_DIR/"
    log "OpenVPN client $OVPN_USER created"
}

# Function to start Websocat
start_websocat() {
    echo "Starting Websocat for SSH WebSocket..."
    log "Starting Websocat"
    nohup websocat -s "$WEBSOCAT_PORT" ws-l:127.0.0.1:22 > /var/log/websocat.log 2>&1 &
    echo $! > /var/run/websocat.pid
}

# Function to display results
display_results() {
    echo -e "${GREEN}Setup completed successfully!${NC}"
    log "Setup completed successfully"
    echo "───────────────────────────"
    echo "     SSH OVPN Account     "
    echo "───────────────────────────"
    echo "Username         : $OVPN_USER"
    echo "Password         : $OVPN_PASS"
    echo "───────────────────────────"
    echo "IP               : $IP"
    echo "Host             : $DOMAIN"
    echo "Location         : $LOCATION"
    echo "Port OpenSSH     : 22"
    echo "Port SSH WS      : $WEBSOCAT_PORT"
    echo "Port SSL/TLS     : 443"
    echo "Port OVPN UDP    : $OVPN_PORT"
    echo "WireGuard Port   : $WG_PORT"
    echo "───────────────────────────"
    echo "Payload WSS      : GET wss://$DOMAIN/ HTTP/1.1[crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]"
    echo "───────────────────────────"
    echo "OpenVPN Link     : https://$CDN_DOMAIN/configs/$OVPN_USER.ovpn"
    echo "WireGuard Client : Copy /etc/wireguard/client.conf to your device"
    echo "───────────────────────────"
    echo "Expired          : $EXPIRE_DATE"
    echo "───────────────────────────"
    echo -e "${GREEN}Notes:${NC}"
    echo "1. Download .ovpn file from your CDN: https://$CDN_DOMAIN/configs/$OVPN_USER.ovpn"
    echo "2. For SSH WS, use ws://$DOMAIN:$WEBSOCAT_PORT$SSH_WS_PATH or wss:// if CDN supports WebSockets."
    echo "3. For V2Ray, use UUID ($V2RAY_UUID) and path ($V2RAY_WS_PATH) with wss:// if CDN supports WebSockets."
    echo "4. Ensure your CDN proxies $DOMAIN/configs/ to this server and supports WebSockets for WS paths."
}

# Main execution
main() {
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    log "Script started"
    echo "Universal Cloud-Based VPN Setup Script"
    read -p "Enter your domain (e.g., example.com): " DOMAIN
    read -p "Enter your email for SSL (e.g., user@example.com): " EMAIL
    read -p "Enter your CDN domain (e.g., cdn.example.com): " CDN_DOMAIN
    log "User provided domain: $DOMAIN, email: $EMAIL, CDN: $CDN_DOMAIN"

    check_prerequisites
    validate_inputs
    configure_firewall
    check_port "$V2RAY_PORT"
    check_port "$WEBSOCAT_PORT"
    check_port "$OVPN_PORT"
    check_port "$WG_PORT"
    install_dependencies
    install_websocat
    configure_v2ray
    setup_ssl
    configure_nginx
    configure_openvpn
    configure_wireguard
    create_openvpn_client
    start_websocat
    display_results
    trap - EXIT
}

# Run the script
main
