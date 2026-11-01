# FF CheckID Panel

Free Fire player-UID checker with a white-theme admin panel and a ready-to-use REST API.

## Features
- Admin panel: dashboard, live tester, settings, API keys, request logs, setup guide
- Change the Garena cookie / User-Agent / proxy from the browser (no restart)
- Quick "datadome only" update when the cookie expires
- Auto-pause after repeated captchas (protects you from deeper blocks)
- Optional fallback: return `unverified` so your site keeps accepting registrations
- Telegram alert when the cookie dies
- Per-site API keys with per-minute limits, enable/disable/regenerate
- Public Developer Docs at `/docs`, admin Setup guide at `/admin/setup`

## Run on Windows
1. Install Python 3.12 (tick "Add python.exe to PATH")
2. Copy `.env.example` to `.env`, set `ADMIN_USER` / `ADMIN_PASS`
3. Double-click `run_windows.bat`
4. Open http://127.0.0.1:5000/admin and sign in
5. Settings: paste cookie and User-Agent, then use Tester

## Deploy on VPS
See `/admin/setup` inside the panel (section C) or run:
```
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp ffpanel.service /etc/systemd/system/ && systemctl enable --now ffpanel
```
then add the OpenLiteSpeed reverse-proxy block from the Setup page.

## API
`GET /api/v1/check?uid=8412833300` with header `X-API-Key: ffk_...`
Full reference: `/docs`.

## Notes
- Unofficial endpoint protected by Datadome; the cookie must be refreshed by hand when it expires.
- Keep `.env` and `data/` private. `data/panel.db` holds the cookie and API keys.
