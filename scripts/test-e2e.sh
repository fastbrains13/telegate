#!/usr/bin/env bash
set -e

HOST="${1:-http://localhost:8888}"
echo "========================================="
echo "🧪 Запуск сквозных E2E тестов TeleGate"
echo "🎯 Цель: $HOST"
echo "========================================="

echo -n "1. Проверка доступности главной страницы... "
curl -fsSL -o /dev/null "$HOST/"
echo "✅ OK"

echo -n "2. Проверка отдачи бинарника агента (/agent-bin)... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/agent-bin")
if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✅ OK (200)"
else
    echo "❌ Ошибка: HTTP $HTTP_CODE"
    exit 1
fi

echo -n "3. Проверка генерации bootstrap скрипта... "
BOOTSTRAP_OUTPUT=$(curl -fsSL "$HOST/bootstrap?token=test_tok&id=test_node")
if echo "$BOOTSTRAP_OUTPUT" | grep -q "telegate-agent"; then
    echo "✅ OK"
else
    echo "❌ Ошибка генерации bootstrap"
    exit 1
fi

echo -n "4. Проверка защиты приватных API (без авторизации)... "
UNAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/api/state")
if [ "$UNAUTH_CODE" -eq 401 ]; then
    echo "✅ OK (Защищено 401)"
else
    echo "❌ Уязвимость: API ответил кодом $UNAUTH_CODE вместо 401"
    exit 1
fi

echo -n "5. Проверка авторизации админа (/api/auth/login)... "
LOGIN_RESP=$(curl -s -c /tmp/telegate_cookie.txt -X POST "$HOST/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}')
if echo "$LOGIN_RESP" | grep -q "ok"; then
    echo "✅ OK"
else
    echo "❌ Ошибка авторизации: $LOGIN_RESP"
    exit 1
fi

echo -n "6. Проверка защищенного API с сессией (/api/state)... "
STATE_CODE=$(curl -s -b /tmp/telegate_cookie.txt -o /dev/null -w "%{http_code}" "$HOST/api/state")
if [ "$STATE_CODE" -eq 200 ]; then
    echo "✅ OK (200)"
else
    echo "❌ Ошибка сессии: HTTP $STATE_CODE"
    exit 1
fi

echo ""
echo "🎉 ВСЕ АВТОТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!"
echo "========================================="
