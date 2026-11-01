import json
import time

import requests

import db


def clean_cookie(raw):
    raw = (raw or "").replace("\r", " ").replace("\n", " ").strip()
    if raw.lower().startswith("cookie:"):
        raw = raw[7:].strip()
    return " ".join(raw.split())


def set_datadome(cookie, value):
    value = (value or "").strip().strip(";").strip()
    if value.lower().startswith("datadome="):
        value = value[9:]
    parts = [p.strip() for p in (cookie or "").split(";") if p.strip()]
    parts = [p for p in parts if not p.lower().startswith("datadome=")]
    parts.append("datadome=" + value)
    return "; ".join(parts)


def mask_cookie(cookie):
    out = []
    for p in (cookie or "").split(";"):
        p = p.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            out.append(f"{k}={v[:6]}..." if len(v) > 6 else p)
    return "; ".join(out)


def telegram(text):
    s = db.all_settings()
    if not s["telegram_token"] or not s["telegram_chat"]:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{s['telegram_token']}/sendMessage",
            json={"chat_id": s["telegram_chat"], "text": text}, timeout=10)
        return r.ok
    except requests.RequestException:
        return False


def _upstream(s, uid):
    """Raw call. Returns dict: status = success | invalid_id | captcha | error"""
    if not s["cookie"]:
        return {"status": "error", "message": "Cookie not configured in admin panel"}
    headers = {
        "User-Agent": s["user_agent"],
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json",
        "Referer": f"https://shop.garena.my/?app={s['app_id']}",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": s["cookie"],
    }
    proxy = s["proxy_url"] or None
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = requests.post(s["api_url"], data=json.dumps({"app_id": int(s["app_id"]), "login_id": uid}),
                          headers=headers, proxies=proxies, timeout=int(s["timeout"]))
    except requests.RequestException as e:
        return {"status": "error", "message": f"network error: {e.__class__.__name__}"}
    try:
        data = r.json()
    except ValueError:
        low = r.text.lower()
        if "captcha" in low or "datadome" in low:
            return {"status": "captcha"}
        return {"status": "error", "message": f"non-JSON response (HTTP {r.status_code})"}
    if isinstance(data, dict) and "url" in data and "captcha" in str(data["url"]):
        return {"status": "captcha"}
    if isinstance(data, dict) and data.get("error"):
        if data["error"] == "invalid_id":
            return {"status": "invalid_id"}
        return {"status": "error", "message": str(data["error"])[:120]}
    if isinstance(data, dict) and data.get("nickname"):
        return {"status": "success", "data": {
            "nickname": data.get("nickname"), "region": data.get("region"),
            "open_id": data.get("open_id"), "img_url": data.get("img_url")}}
    return {"status": "error", "message": "unexpected upstream response"}


def _unavailable(s, reason):
    if s["fallback_mode"] == "allow":
        return {"ok": True, "status": "unverified", "data": None, "cached": False,
                "message": "Verification temporarily unavailable. Accept the UID and verify manually."}, 200
    return {"ok": False, "status": "unavailable", "data": None, "cached": False,
            "message": f"Verification service unavailable ({reason}). Try again later."}, 503


def check(uid):
    """Returns (result_dict, http_code, from_cache)."""
    s = db.all_settings()
    uid = str(uid or "").strip()
    if not uid.isdigit() or not (5 <= len(uid) <= 15):
        return {"ok": False, "status": "bad_request", "data": None, "cached": False,
                "message": "uid must be 5-15 digits"}, 400, False

    row = db.cache_get(uid)
    if row and db.now() - row["ts"] < int(s["cache_ttl"]):
        r = json.loads(row["result"])
        r["cached"] = True
        return r, 200, True

    if int(s["cooldown_until"]) > db.now():
        r, code = _unavailable(s, "cooling down after block")
        return r, code, False

    up = _upstream(s, uid)
    st = up["status"]

    if st in ("success", "invalid_id"):
        db.put(cookie_status="ok", last_ok=db.now(), consec_captcha=0, cooldown_until=0)
        if st == "success":
            res = {"ok": True, "status": "success", "data": up["data"], "cached": False, "message": ""}
        else:
            res = {"ok": True, "status": "invalid_id", "data": None, "cached": False,
                   "message": "No player found for this UID"}
        db.cache_put(uid, json.dumps(res))
        return res, 200, False

    if st == "captcha":
        n = int(s["consec_captcha"]) + 1
        updates = {"consec_captcha": n, "last_captcha": db.now()}
        if n >= int(s["captcha_threshold"]):
            updates.update(cookie_status="expired",
                           cooldown_until=db.now() + int(s["cooldown_minutes"]) * 60)
            if s["cookie_status"] != "expired":
                telegram("FF CheckID: cookie expired or blocked (captcha). "
                         "Open the admin panel > Settings and paste a fresh datadome cookie.")
        db.put(**updates)
        r, code = _unavailable(s, "captcha challenge")
        return r, code, False

    r, code = _unavailable(s, up.get("message", "upstream error"))
    return r, code, False
