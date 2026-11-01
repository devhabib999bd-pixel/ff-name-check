import os
import sqlite3
import time

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE, "data", "panel.db"))

DEFAULTS = {
    "cookie": "",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
    "proxy_url": "",
    "timeout": "15",
    "api_url": "https://shop.garena.my/api/auth/player_id_login",
    "app_id": "100067",
    "cache_ttl": "300",
    "fallback_mode": "off",      # off = return 503 when unavailable | allow = return "unverified"
    "captcha_threshold": "3",    # consecutive captchas before cooldown
    "cooldown_minutes": "10",
    "telegram_token": "",
    "telegram_chat": "",
    "cookie_status": "unknown",  # unknown | ok | expired
    "cookie_updated": "0",
    "last_ok": "0",
    "last_captcha": "0",
    "consec_captcha": "0",
    "cooldown_until": "0",
    "default_pw": "0",
}


def conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init():
    with conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT);
            CREATE TABLE IF NOT EXISTS api_keys(
                id INTEGER PRIMARY KEY, name TEXT, key TEXT UNIQUE,
                rate_limit INTEGER DEFAULT 30, active INTEGER DEFAULT 1,
                created INTEGER, total INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS logs(
                id INTEGER PRIMARY KEY, ts INTEGER, uid TEXT, status TEXT,
                key_id INTEGER, key_name TEXT, ip TEXT, ms INTEGER, cached INTEGER, http INTEGER);
            CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
            CREATE INDEX IF NOT EXISTS idx_logs_key ON logs(key_id, ts);
            CREATE TABLE IF NOT EXISTS cache(uid TEXT PRIMARY KEY, ts INTEGER, result TEXT);
            """
        )
        for k, v in DEFAULTS.items():
            c.execute("INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)", (k, v))


def all_settings():
    with conn() as c:
        rows = c.execute("SELECT k,v FROM settings").fetchall()
    d = dict(DEFAULTS)
    d.update({r["k"]: r["v"] for r in rows})
    return d


def get(k):
    return all_settings().get(k, DEFAULTS.get(k, ""))


def put(**kw):
    with conn() as c:
        for k, v in kw.items():
            c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def now():
    return int(time.time())


def cache_get(uid):
    with conn() as c:
        return c.execute("SELECT ts,result FROM cache WHERE uid=?", (uid,)).fetchone()


def cache_put(uid, result_json):
    with conn() as c:
        c.execute("INSERT INTO cache(uid,ts,result) VALUES(?,?,?) ON CONFLICT(uid) DO UPDATE SET ts=excluded.ts, result=excluded.result",
                  (uid, now(), result_json))
        c.execute("DELETE FROM cache WHERE ts < ?", (now() - 86400,))


def add_log(uid, status, key_id, key_name, ip, ms, cached, http):
    with conn() as c:
        c.execute("INSERT INTO logs(ts,uid,status,key_id,key_name,ip,ms,cached,http) VALUES(?,?,?,?,?,?,?,?,?)",
                  (now(), uid, status, key_id, key_name, ip, ms, 1 if cached else 0, http))
        if key_id:
            c.execute("UPDATE api_keys SET total = total + 1 WHERE id=?", (key_id,))
        c.execute("DELETE FROM logs WHERE id < (SELECT MAX(id) FROM logs) - 20000")
