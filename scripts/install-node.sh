#!/usr/bin/env bash
set -e

MASTER_URL="${1:-http://your-master:8080}"
NODE_TOKEN="${2:-secret-token}"
NODE_NAME="${3:-node-$(hostname)}"

echo "=== [TeleGate] Установка агента на сервер ==="

# Sing-box (Web Proxy / VLESS / routing)
if ! command -v sing-box &> /dev/null; then
    echo "-> Установка ядра Sing-box..."
    bash -c "$(curl -fsSL https://sing-box.app/install.sh)"
fi

# mtg v2 (MTProto Fake-TLS proxy)
if ! command -v mtg &> /dev/null; then
    echo "-> Установка mtg (MTProto proxy)..."
    MTG_VERSION="2.2.0"
    curl -fsSL "https://github.com/9seconds/mtg/releases/download/v${MTG_VERSION}/mtg-${MTG_VERSION}-amd64.tar.gz" \
      | tar -xz -C /tmp && mv /tmp/mtg /usr/local/bin/mtg && chmod +x /usr/local/bin/mtg
fi

# Скачиваем агент с панели
echo "-> Скачивание бинарника TeleGate Agent..."
curl -fsSL "${MASTER_URL}/agent-bin" -o /usr/local/bin/telegate-agent
chmod +x /usr/local/bin/telegate-agent

# systemd unit для агента
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

# systemd unit для mtg (MTProto)
cat << MTGUNIT > /etc/systemd/system/telegate-mtproto.service
[Unit]
Description=TeleGate MTProto proxy (mtg)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mtg run /etc/telegate/mtg.toml
Restart=always
RestartSec=3
DynamicUser=true
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
MTGUNIT

systemctl daemon-reload
systemctl enable --now telegate-agent
echo "=== Нода успешно готова и ожидает команд от панели! ==="
