# partnerka.io — лендинг раннего доступа

Лендинг сервиса партнёрских программ и воронка смоук-теста:
регистрация с паролем → код подтверждения на почту → кабинет-заглушка `/app`
с размытым дашбордом и формой контакта в Telegram или MAX.

Каждая подтверждённая регистрация, оставленный контакт и обращение из форм
сохраняются в SQLite и отправляются в канал Mattermost.

## Устройство

| Путь | Что это |
|---|---|
| `server.js` | Сервер на Express: API, сессии, отправка писем, вебхук Mattermost |
| `public/index.html` | Лендинг |
| `public/app.html` | Кабинет-заглушка, доступен только после подтверждения почты |
| `public/privacy.html`, `public/consent.html` | Юридические страницы, пока заглушки |
| `public/logos.html`, `public/logo/` | Варианты логотипа |
| `data/partnerka.db` | База SQLite, создаётся при первом запуске (в Docker — том `/data`) |

API: `POST /api/signup`, `/api/verify`, `/api/resend`, `/api/login`, `/api/logout`,
`/api/lead`, `/api/request`, `GET /api/me`, `GET /healthz`.

## Локальный запуск

Нужен Node.js 22.13 или новее.

```bash
npm install
npm run dev
```

Без настроек SMTP и Mattermost коды подтверждения и сообщения печатаются в лог сервера.

## Деплой в Coolify

1. **New Resource → Public/Private Repository**, репозиторий `serjnsk/partnerka_io`, ветка `main`.
2. **Build Pack: Dockerfile**. Порт приложения `3000`.
3. **Environment Variables** — из `.env.example`: `SMTP_*`, `MATTERMOST_WEBHOOK_URL`, `NODE_ENV=production`.
4. **Storages → Volume Mount** с путём назначения `/data`. Без тома база пропадёт при каждом деплое.
5. **Domains**: `https://partnerka.io` (и при желании `https://www.partnerka.io`). Coolify сам выпустит сертификат Let's Encrypt.
6. DNS у регистратора: A-запись домена на IP сервера Coolify.
7. Включите автодеплой по push в `main`.

### Почта

Для доставки писем с кодом в домене нужны SPF, DKIM и DMARC от выбранного SMTP-провайдера.
Без них письма будут попадать в спам.

### Mattermost

Integrations → Incoming Webhooks → Add → выберите канал и скопируйте URL в `MATTERMOST_WEBHOOK_URL`.

### Выгрузка лидов

```bash
sqlite3 /data/partnerka.db "SELECT created_at, kind, email, channel, contact, plan, utm FROM leads ORDER BY id DESC;"
```

## Перед запуском смоук-теста

- Опубликовать тексты политики конфиденциальности и согласия на обработку ПДн.
- Заменить ссылку на Telegram `https://t.me/partnerka_support` в `public/index.html`.
- Вписать номер счётчика Яндекс Метрики в `YM_ID` в `public/index.html`.
