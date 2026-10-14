# TeleGate 🚀

**TeleGate** — минималистичная панель управления Telegram-прокси нового поколения с архитектурой Master-Node.

### Особенности
* 🌐 **Telegram Web Proxy** — маскировка трафика под HTTPS / WebSockets (как у Яндекс).
* 🛡️ **MTProto Fake-TLS** — классический TG-прокси с маскировкой под домены SNI.
* 🔀 **VLESS Upstream Chain** — проброс трафика ноды через внешний VLESS + Reality без раскрытия IP.
* 🚫 **Интеллектуальный фильтр** — черный список по одиночным IP, подсетям CIDR и странам (GeoIP).
* ⚡ **Zero-Downtime Reload** — применение изменений конфигурации без обрыва сессий клиентов в Telegram.
* 🔒 **Безопасность** — bcrypt-хеши паролей, CSRF-защита, rate limiting, secure cookies.
* 📡 **SSE Push** — мгновенное уведомление агентов об изменении конфигурации.

---

## 📦 Архитектура

```
┌──────────────────────────────────────┐
│         TeleGate Panel (Master)       │
│  :8080 — Web UI + REST API           │
│  - Авторизация (bcrypt + CSRF)        │
│  - Хранение состояния (JSON, atomic)  │
│  - Генерация конфигов                │
│  - SSE push для агентов               │
└──────────┬───────────────────────────┘
           │  REST API + SSE
           │
    ┌──────┴──────┐
    │  Node Agent  │
    │  (Go binary) │
    └──────┬──────┘
           │
    ┌──────┴───────────┐
    │                  │
 sing-box          mtg v2
 (Web/VLESS)     (MTProto)
```

---

## 🚀 Быстрый старт (Docker Compose)

### Требования
- [Docker](https://docs.docker.com/get-docker/) и [Docker Compose](https://docs.docker.com/compose/install/)

### Развёртывание

```bash
# Клонировать репозиторий
git clone https://github.com/fastbrains13/telegate.git
cd telegate/docker

# Запустить панель
docker compose up -d --build
```

Панель доступна по адресу: `http://localhost:8080`

**Логин по умолчанию:** `admin` / `admin`

### Смена пароля

После первого входа пароль можно изменить через API:

```bash
# Генерируем bcrypt-хеш
go install golang.org/x/crypto/bcrypt/cmd/bcrypt@latest
echo -n "newpassword" | bcrypt
```

Затем обновите файл состояния `/data/telegate_state.json` (в volume контейнера).

---

## 🖥 Ручная установка (systemd)

### Панель (Master)

```bash
# 1. Установить Go 1.22+
# 2. Собрать бинарник
cd ~/telegate
go build -o telegate-panel ./cmd/panel

# 3. Создать systemd unit
sudo tee /etc/systemd/system/telegate-panel.service > /dev/null << 'EOF'
[Unit]
Description=TeleGate Panel
After=network.target

[Service]
Type=simple
ExecStart=/opt/telegate/telegate-panel
Restart=always
RestartSec=5
Environment=TELEGATE_LISTEN_ADDR=:8080
Environment=TELEGATE_STATE_FILE=/opt/telegate/state.json
Environment=TELEGATE_ADMIN_USER=admin
Environment=TELEGATE_ADMIN_PASS=admin
Environment=TELEGATE_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
EOF

# 4. Запустить
sudo systemctl daemon-reload
sudo systemctl enable --now telegate-panel
```

### Нода (Agent)

```bash
# 1. Установить зависимости
sudo bash scripts/install-node.sh "http://YOUR-MASTER-IP:8080" "NODE-TOKEN" "node-name"
```

Или вручную:

```bash
# Sing-box (Web Proxy / VLESS)
bash -c "$(curl -fsSL https://sing-box.app/install.sh)"

# mtg v2 (MTProto)
curl -fsSL "https://github.com/9seconds/mtg/releases/download/v2.2.0/mtg-2.2.0-amd64.tar.gz" \
  | tar -xz -C /tmp && sudo mv /tmp/mtg /usr/local/bin/mtg && sudo chmod +x /usr/local/bin/mtg

# Агент
curl -fsSL "http://MASTER-IP:8080/agent-bin" -o /usr/local/bin/telegate-agent
sudo chmod +x /usr/local/bin/telegate-agent

# systemd unit
sudo tee /etc/systemd/system/telegate-agent.service > /dev/null << 'EOF'
[Unit]
Description=TeleGate Node Agent
After=network.target sing-box.service

[Service]
Type=simple
ExecStart=/usr/local/bin/telegate-agent \
  -master "http://MASTER-IP:8080" \
  -token "NODE-TOKEN" \
  -id "node-name"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now telegate-agent
```

---

## ⚙️ Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `TELEGATE_LISTEN_ADDR` | `:8080` | Адрес и порт для прослушивания |
| `TELEGATE_STATE_FILE` | `/data/telegate_state.json` | Путь к файлу состояния |
| `TELEGATE_ADMIN_USER` | `admin` | Имя администратора |
| `TELEGATE_ADMIN_PASS` | `admin` | Пароль администратора |
| `TELEGATE_LOG_LEVEL` | `info` | Уровень логирования: `debug`, `info`, `warn`, `error` |

---

## 🔧 Настройка TLS (reverse proxy)

Для продакшена рекомендуется поставить Nginx/Caddy перед панелью:

```nginx
server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
```

---

## 🧪 Проверка развёртывания

```bash
# 1. Healthcheck
curl -fsSL http://localhost:8080/api/health

# 2. Метрики
curl -fsSL http://localhost:8080/metrics

# 3. Авторизация
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  -c /tmp/tg_cookies.txt

# 4. Получить состояние
curl -fsSL -b /tmp/tg_cookies.txt http://localhost:8080/api/state

# 5. E2E тесты
sudo bash scripts/test-e2e.sh http://localhost:8080
```

---

## 📡 API Reference

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/auth/login` | Авторизация, возвращает session + csrf cookie |
| `POST` | `/api/auth/logout` | Завершение сессии |
| `GET`  | `/api/auth/me` | Проверка текущей сессии |
| `GET`  | `/api/state` | Полное состояние (требует auth) |
| `POST` | `/api/nodes/create` | Создать ноду (требует auth + CSRF) |
| `DELETE` | `/api/nodes/delete?id=` | Удалить ноду |
| `POST` | `/api/nodes/save-proxy` | Сохранить конфиг прокси ноды |
| `POST/DELETE` | `/api/blacklist/ip` | Добавить/удалить IP из чёрного списка |
| `POST/DELETE` | `/api/blacklist/country` | Добавить/удалить страну из GeoIP |
| `POST` | `/api/agent/heartbeat` | Heartbeat от агента (токен) |
| `GET` | `/api/agent/config?node_id=` | Получить sing-box + mtg конфиги |
| `GET` | `/api/agent/events?node_id=` | SSE-стрим для push-уведомлений |
| `GET` | `/bootstrap?token=&id=` | Bootstrap-скрипт для новой ноды |
| `GET` | `/agent-bin` | Бинарник агента |
| `GET` | `/api/health` | Healthcheck (public) |
| `GET` | `/metrics` | Prometheus metrics (public) |

---

## 🗂 Структура проекта

```
telegate/
├── cmd/
│   ├── panel/              # Мастер-панель
│   │   ├── main.go         # HTTP-сервер, middleware, SSE
│   │   ├── ui/             # Фронтенд (HTML + JS)
│   │   │   ├── login.html  # Страница входа
│   │   │   ├── index.html  # Дашборд
│   │   │   ├── proxies.html# Конфигуратор прокси
│   │   │   ├── connections.html # Подключения
│   │   │   ├── security.html    # Чёрный список
│   │   │   └── js/common.js   # Общий JS
│   │   └── api_test.go     # Тесты API
│   └── agent/              # Агент ноды
│       └── main.go         # Heartbeat, SSE-подписка, apply config
├── internal/
│   ├── auth/               # bcrypt, rate limiting, sessions
│   ├── state/              # Atomic state persistence
│   ├── graceful/           # Signal handling
│   └── generator/          # Генерация конфигов
│       ├── singbox.go      # Sing-box JSON
│       └── mtproto.go      # MTProto TOML (mtg v2)
├── docker/                 # Docker-конфигурация
│   ├── docker-compose.yml
│   ├── Dockerfile.panel
│   └── Dockerfile.agent
├── scripts/                # Скрипты установки
│   ├── install-panel.sh    # Установка панели
│   ├── install-node.sh     # Установка ноды
│   └── test-e2e.sh         # E2E-тесты
├── Makefile
├── go.mod
└── README.md
```

---

## 🔐 Безопасность

- **Пароли** — bcrypt с автоматической миграцией при первом запуске
- **CSRF** — `X-CSRF-Token` header + cookie для всех мутающих API
- **Rate Limiting** — 5 попыток входа за 15 минут, далее 429
- **Cookies** — `HttpOnly`, `SameSite=Strict`, `Secure` (для HTTPS)
- **State file** — атомарная запись (tmp + rename), права 0600
- **Агент-токены** — криптографически стойкие, проверяются при каждом heartbeat

---

## 🛠 Разработка

```bash
# Собрать все бинарники
make build

# Запустить тесты
make test

# Собрать и запустить Docker
make docker-run
```

```bash
# Либо вручную
CGO_ENABLED=0 go build -o bin/panel ./cmd/panel
CGO_ENABLED=0 go build -o bin/agent ./cmd/agent
go test -v ./...
```

---

## 📝 Лицензия

MIT
