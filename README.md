# TeleGate 🚀

**TeleGate** — минималистичная панель управления Telegram-прокси нового поколения с архитектурой Master-Node.

### Особенности
* 🌐 **Telegram Web Proxy** — маскировка трафика под HTTPS / WebSockets (как у Яндекс).
* 🛡️ **MTProto Fake-TLS** — классический TG-прокси с маскировкой под домены SNI.
* 🔀 **VLESS Upstream Chain** — проброс трафика ноды через внешний VLESS + Reality без раскрытия IP.
* 🚫 **Интеллектуальный фильтр** — черный список по одиночным IP, подсетям CIDR и странам (GeoIP).
* ⚡ **Zero-Downtime Reload** — применение изменений конфигурации без обрыва сессий клиентов в Telegram.

### Быстрый старт панели (Master)
\`\`\`bash
cd docker
docker compose up -d
\`\`\`
Панель будет доступна по адресу \`http://localhost:8080\`.
