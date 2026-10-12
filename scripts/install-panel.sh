#!/usr/bin/env bash
set -e

echo "=== [TeleGate] Установка мастер-панели на сервер ==="

# Проверка и установка Docker
if ! command -v docker &> /dev/null; then
    echo "-> Установка Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi

# Клонирование или обновление репозитория
INSTALL_DIR="/opt/telegate"
if [ -d "$INSTALL_DIR" ]; then
    echo "-> Обновление существующей установки..."
    cd "$INSTALL_DIR" && git pull
else
    echo "-> Клонирование репозитория..."
    git clone https://github.com/fastbrains13/telegate.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Запуск панели в Docker Compose
echo "-> Сборка и запуск контейнеров..."
docker compose -f docker/docker-compose.yml up -d --build

SERVER_IP=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')
echo ""
echo "=========================================================="
echo "🎉 TeleGate Master Panel успешно установлена и запущена!"
echo "👉 Адрес панели: http://${SERVER_IP}:8080"
echo "🔑 Стандартный логин/пароль: admin / admin"
echo "=========================================================="
