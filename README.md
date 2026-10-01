# partnerka.io — лендинг

Лендинг сервиса партнёрских программ.
Регистрация: почта, пароль, контакт в Telegram или MAX и название продукта →
кабинет `/app`: на фоне размытый дашборд, поверх сообщение, что менеджер свяжется в течение суток.

Каждая регистрация и обращение из форм сохраняются в SQLite и отправляются в канал Mattermost.

## Устройство

| Путь | Что это |
|---|---|
| `server.js` | Сервер на Express: API, сессии, вебхук Mattermost |
| `public/index.html` | Лендинг |
| `public/app.html` | Кабинет после регистрации, доступен только с сессией |
| `public/privacy.html`, `public/consent.html` | Юридические страницы, пока заглушки |
| `public/logos.html`, `public/logo/` | Варианты логотипа |
| `private/admin.html` | Страница `/admin`: лиды и выгрузка в CSV, отдаётся только сервером |
| `data/partnerka.db` | База SQLite, создаётся при первом запуске (в Docker — том `/data`) |

API: `POST /api/signup`, `/api/login`, `/api/logout`, `/api/request`, `GET /api/me`, `GET /healthz`.
Админка: `POST /api/admin/login`, `/api/admin/logout`, `GET /api/admin/leads`, `/api/admin/leads.csv?kind=&q=`.

## Локальный запуск

Нужен Node.js 22.13 или новее.

```bash
npm install
npm run dev
```

Без `MATTERMOST_WEBHOOK_URL` сообщения для Mattermost печатаются в лог сервера.
Чтобы открыть `/admin` локально, положите в `.env` строку `ADMIN_PASSWORD=...`: `npm run dev` подхватит её сам.

## Деплой в Coolify

1. **New Resource → Public/Private Repository**, репозиторий `serjnsk/partnerka_io`, ветка `main`.
2. **Build Pack: Dockerfile**. Порт приложения `3000`.
3. **Environment Variables** — из `.env.example`: `MATTERMOST_WEBHOOK_URL`, `ADMIN_PASSWORD`, `NODE_ENV=production`.
4. **Storages → Volume Mount** с путём назначения `/data`. Без тома база пропадёт при каждом деплое.
5. **Domains**: `https://partnerka.io` (и при желании `https://www.partnerka.io`). Coolify сам выпустит сертификат Let's Encrypt.
6. DNS у регистратора: A-запись домена на IP сервера Coolify.
7. Включите автодеплой по push в `main`.

### Mattermost

Integrations → Incoming Webhooks → Add → выберите канал и скопируйте URL в `MATTERMOST_WEBHOOK_URL`.

### Лиды

Все лиды — на странице `https://partnerka.io/admin`, вход по паролю из `ADMIN_PASSWORD`. Там же фильтр по типу, поиск и кнопка «Скачать CSV» (Excel, разделитель «;», время московское). Пока переменная не задана, страница отключена и отвечает 404. После смены пароля все входы сбрасываются.

Запасной вариант — из терминала контейнера в Coolify:

```bash
node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/data/partnerka.db',{readOnly:true});console.table(db.prepare('select * from leads order by id desc').all())"
```

## Перед запуском смоук-теста

- Опубликовать тексты политики конфиденциальности и согласия на обработку ПДн.
- Заменить ссылку на Telegram `https://t.me/partnerka_support` в `public/index.html`.
- Вписать номер счётчика Яндекс Метрики в `YM_ID` в `public/index.html`.
