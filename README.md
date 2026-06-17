# NFC Визитка — Платформа

## Быстрый запуск

### Локально
```bash
pip install flask
python server.py
```
Открой: http://localhost:5000

### Деплой на Railway (бесплатно)
1. Зайди на railway.app
2. New Project → Deploy from GitHub
3. Загрузи эту папку
4. Переменные окружения:
   - SECRET_KEY = любая_длинная_строка
   - ADMIN_EMAIL = твой@email.com
   - ADMIN_PASS = твой_пароль

## Использование
1. Войди на /admin
2. Создай коды карт (кнопка «Генерировать»)
3. Напечатай QR с кодом на вкладыш
4. Клиент сканирует QR → активирует карту

## iOS Shortcut
Создай по инструкции в shortcut-инструкция.md
API endpoint для Shortcut: GET /api/setup?code=XXX&name=...
