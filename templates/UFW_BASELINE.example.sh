#!/usr/bin/env bash
# EXAMPLE ONLY — review locally before running.
# Replace YOUR_PUBLIC_IP before use.
set -euo pipefail
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from YOUR_PUBLIC_IP/32 to any port 22 proto tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 3000/tcp
sudo ufw deny 5555/tcp
sudo ufw deny 5432/tcp
sudo ufw deny 6379/tcp
sudo ufw deny 8000/tcp
sudo ufw deny 2375/tcp
sudo ufw deny 2376/tcp
sudo ufw enable
sudo ufw status verbose
