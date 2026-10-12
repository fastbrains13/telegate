#!/usr/bin/env bash
set -e

MASTER_URL="${1:-http://your-master:8080}"
NODE_TOKEN="${2:-secret-token}"
NODE_NAME="${3:-node-$(hostname)}"

echo "=== [TeleGate] Установка агента на сервер ==="

if ! command -v sing-box &> /dev/null; then
    echo "-> Установка ядра Sing-box..."
    bash -c "$(curl -fsSL https://sing-box.app/install.sh)"
fi

echo "-> Настройка демона TeleGate Agent..."
mkdir -p /etc/telegate
cat << SYSTEMD > /etc/systemd/system/telegate-agent.service
[Unit]
Description=TeleGate Node Agent
After=network.target sing-box.service

[Service]
Type=simple
ExecStart=/usr/local/bin/telegate-agent -master "${MASTER_URL}" -token "${NODE_TOKEN}" -id "${NODE_NAME}"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

echo "=== Нода успешно готова и ожидает команд от панели! ==="
