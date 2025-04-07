# Universal Cloud-Based VPN Setup Script

![GitHub release (latest by date)](https://img.shields.io/github/v/release/shaa2020/vpn-setup-universal)
![GitHub license](https://img.shields.io/github/license/shaa2020/vpn-setup-universal)
![GitHub last commit](https://img.shields.io/github/last-commit/shaa2020/vpn-setup-universal)

## Overview

This script automates the setup of a VPN server with **V2Ray**, **SSH WebSocket**, **OpenVPN**, **WireGuard**, and **Nginx with SSL**, designed to work with **any cloud CDN** (e.g., Cloudflare, Amazon CloudFront, Google Cloud CDN, Azure CDN, Akamai).

- **Version**: 2.5
- **Author**: Shaan
- **Date**: April 07, 2025
- **License**: MIT

## Features

- **Universal CDN Support**: Compatible with any CDN that can proxy HTTPS and WebSocket traffic.
- **Multi-Protocol VPN**: V2Ray (VMess over WS), OpenVPN (UDP), WireGuard, SSH WebSocket.
- **SSL/TLS**: Uses Certbot for HTTPS with auto-renewal.
- **File Distribution**: Serves `.ovpn` files via Nginx, proxied by your CDN.

## Prerequisites

- A Linux server (e.g., Ubuntu/Debian) on any cloud provider (AWS EC2, Google Compute Engine, Azure VM, etc.) or VPS.
- A domain name pointing to your server’s public IP.
- A CDN configured to proxy your server’s HTTPS traffic (e.g., `https://<your-domain>/configs/`).
- Ports open: 22 (SSH), 80 (HTTP), 443 (HTTPS), 1194 (OpenVPN UDP), 51820 (WireGuard UDP), 10000 (V2Ray), 8080 (SSH WS).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/shaa2020/vpn-setup-universal.git
   cd vpn-setup-universal
