import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import checker
import db

BASE = os.path.dirname(os.path.abspath(__file__))


def load_env(path=os.path.join(BASE, ".env")):
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()
db.init()

app = Flask(__name__)
app.json.ensure_ascii = False
app.json.sort_keys = False


def _secret():
    if os.getenv("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    p = os.path.join(BASE, "data", "secret.key")
    if not os.path.exists(p):
        open(p, "w").write(secrets.token_hex(32))
    return open(p).read().strip()


app.secret_key = _secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=12))

# ---------- first admin ----------
with db.conn() as c:
    if not c.execute("SELECT 1 FROM admins").fetchone():
        user = os.getenv("ADMIN_USER", "admin")
        pw = os.getenv("ADMIN_PASS", "ChangeMe123!")
        c.execute("INSERT INTO admins(username,pw_hash) VALUES(?,?)", (user, generate_password_hash(pw)))
        c.execute("UPDATE settings SET v='1' WHERE k='default_pw'")

BD = timezone(timedelta(hours=6))


@app.template_filter("dt")
def fmt_dt(ts):
    ts = int(ts or 0)
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, BD).strftime("%d %b %Y, %I:%M %p")


@app.template_filter("ago")
def fmt_ago(ts):
    ts = int(ts or 0)
    if not ts:
        return "never"
    d = db.now() - ts
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


# ---------- CSRF + auth ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST" and not request.path.startswith("/api/"):
        tok = session.get("csrf")
        if not tok or request.form.get("csrf") != tok:
            abort(400, "CSRF check failed. Reload the page and try again.")


def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return w


_attempts = {}


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        rec = [t for t in _attempts.get(ip, []) if time.time() - t < 600]
        if len(rec) >= 8:
            flash("Too many attempts. Wait 10 minutes.", "err")
            return render_template("login.html"), 429
        with db.conn() as c:
            row = c.execute("SELECT * FROM admins WHERE username=?", (request.form.get("username", "").strip(),)).fetchone()
        if row and check_password_hash(row["pw_hash"], request.form.get("password", "")):
            session.clear()
            session.permanent = True
            session["admin"] = row["username"]
            return redirect(request.args.get("next") or url_for("dashboard"))
        rec.append(time.time())
        _attempts[ip] = rec
        flash("Wrong username or password.", "err")
    return render_template("login.html")


@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- admin pages ----------
@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("admin") else url_for("docs"))


@app.route("/admin")
@login_required
def dashboard():
    s = db.all_settings()
    since = db.now() - 86400
    with db.conn() as c:
        tot = c.execute("SELECT COUNT(*) n, AVG(ms) a FROM logs WHERE ts>?", (since,)).fetchone()
        by = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM logs WHERE ts>? GROUP BY status", (since,))}
        cached = c.execute("SELECT COUNT(*) FROM logs WHERE ts>? AND cached=1", (since,)).fetchone()[0]
        days = []
        for i in range(6, -1, -1):
            start = int((datetime.now(BD).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)).timestamp())
            n = c.execute("SELECT COUNT(*) FROM logs WHERE ts>=? AND ts<?", (start, start + 86400)).fetchone()[0]
            days.append((datetime.fromtimestamp(start, BD).strftime("%a"), n))
        keys = c.execute("SELECT COUNT(*) FROM api_keys WHERE active=1").fetchone()[0]
    peak = max([n for _, n in days] + [1])
    cooldown_left = max(0, int(s["cooldown_until"]) - db.now())
    return render_template("dashboard.html", s=s, total=tot["n"], avg=int(tot["a"] or 0), by=by,
                           cached=cached, days=days, peak=peak, keys=keys, cooldown_left=cooldown_left)


@app.post("/admin/reset-cooldown")
@login_required
def reset_cooldown():
    db.put(cooldown_until=0, consec_captcha=0)
    flash("Cooldown cleared. Next request will try Garena again.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/tester", methods=["GET", "POST"])
@login_required
def tester():
    result = None
    uid = ""
    if request.method == "POST":
        uid = request.form.get("uid", "").strip()
        t0 = time.time()
        result, code, cached = checker.check(uid)
        ms = int((time.time() - t0) * 1000)
        db.add_log(uid, result["status"], None, "admin-tester", request.remote_addr, ms, cached, code)
        result["_ms"] = ms
    return render_template("tester.html", result=result, uid=uid)


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def settings():
    s = db.all_settings()
    if request.method == "POST":
        f = request.form
        action = f.get("action")
        if action == "cookie":
            ck = s["cookie"]
            dd = f.get("datadome", "").strip()
            full = checker.clean_cookie(f.get("cookie", ""))
            if full:
                ck = full
            if dd:
                ck = checker.set_datadome(ck, dd)
            if ck != s["cookie"]:
                db.put(cookie=ck, cookie_updated=db.now(), cookie_status="unknown",
                       consec_captcha=0, cooldown_until=0)
                flash("Cookie updated. Open the Tester and run one UID to confirm.", "ok")
            else:
                flash("Nothing changed.", "err")
            ua = f.get("user_agent", "").strip()
            if ua:
                db.put(user_agent=ua)
            db.put(proxy_url=f.get("proxy_url", "").strip())
        elif action == "behavior":
            def num(k, lo, hi, d):
                try:
                    return str(min(hi, max(lo, int(f.get(k, d)))))
                except ValueError:
                    return str(d)
            db.put(cache_ttl=num("cache_ttl", 0, 86400, 300), timeout=num("timeout", 3, 60, 15),
                   captcha_threshold=num("captcha_threshold", 1, 20, 3),
                   cooldown_minutes=num("cooldown_minutes", 1, 1440, 10),
                   fallback_mode="allow" if f.get("fallback_mode") == "allow" else "off")
            flash("Behavior settings saved.", "ok")
        elif action == "telegram":
            db.put(telegram_token=f.get("telegram_token", "").strip(), telegram_chat=f.get("telegram_chat", "").strip())
            flash("Telegram settings saved.", "ok")
        elif action == "telegram_test":
            sent = checker.telegram("FF CheckID panel: Telegram alerts are working.")
            flash("Test message sent." if sent else "Could not send. Check bot token and chat id.", "ok" if sent else "err")
        elif action == "advanced":
            db.put(api_url=f.get("api_url", "").strip() or db.DEFAULTS["api_url"],
                   app_id=f.get("app_id", "").strip() or db.DEFAULTS["app_id"])
            flash("Advanced settings saved.", "ok")
        return redirect(url_for("settings"))
    return render_template("settings.html", s=s, masked=checker.mask_cookie(s["cookie"]))


@app.route("/admin/keys", methods=["GET", "POST"])
@login_required
def keys():
    if request.method == "POST":
        f = request.form
        a = f.get("action")
        with db.conn() as c:
            if a == "create":
                name = f.get("name", "").strip()[:60] or "Unnamed"
                try:
                    rl = max(1, min(600, int(f.get("rate_limit", 30))))
                except ValueError:
                    rl = 30
                c.execute("INSERT INTO api_keys(name,key,rate_limit,active,created) VALUES(?,?,?,1,?)",
                          (name, "ffk_" + secrets.token_urlsafe(24), rl, db.now()))
                flash(f"Key created for {name}.", "ok")
            elif a == "toggle":
                c.execute("UPDATE api_keys SET active = 1 - active WHERE id=?", (f.get("id"),))
            elif a == "delete":
                c.execute("DELETE FROM api_keys WHERE id=?", (f.get("id"),))
                flash("Key deleted.", "ok")
            elif a == "limit":
                try:
                    c.execute("UPDATE api_keys SET rate_limit=? WHERE id=?", (max(1, min(600, int(f.get("rate_limit")))), f.get("id")))
                    flash("Rate limit updated.", "ok")
                except (ValueError, TypeError):
                    pass
            elif a == "regen":
                c.execute("UPDATE api_keys SET key=? WHERE id=?", ("ffk_" + secrets.token_urlsafe(24), f.get("id")))
                flash("New key generated. Update it in the app that uses it.", "ok")
        return redirect(url_for("keys"))
    with db.conn() as c:
        rows = c.execute("SELECT * FROM api_keys ORDER BY id DESC").fetchall()
    return render_template("keys.html", rows=rows)


@app.route("/admin/logs", methods=["GET", "POST"])
@login_required
def logs():
    if request.method == "POST" and request.form.get("action") == "clear":
        with db.conn() as c:
            c.execute("DELETE FROM logs")
        flash("Logs cleared.", "ok")
        return redirect(url_for("logs"))
    st = request.args.get("status", "")
    q = "SELECT * FROM logs"
    args = []
    if st:
        q += " WHERE status=?"
        args.append(st)
    q += " ORDER BY id DESC LIMIT 150"
    with db.conn() as c:
        rows = c.execute(q, args).fetchall()
    return render_template("logs.html", rows=rows, st=st)


@app.route("/admin/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        f = request.form
        with db.conn() as c:
            row = c.execute("SELECT * FROM admins WHERE username=?", (session["admin"],)).fetchone()
            new = f.get("new", "")
            if not check_password_hash(row["pw_hash"], f.get("current", "")):
                flash("Current password is wrong.", "err")
            elif len(new) < 10:
                flash("New password must be at least 10 characters.", "err")
            elif new != f.get("confirm"):
                flash("Passwords do not match.", "err")
            else:
                nu = f.get("username", "").strip() or row["username"]
                c.execute("UPDATE admins SET pw_hash=?, username=? WHERE id=?", (generate_password_hash(new), nu, row["id"]))
                session["admin"] = nu
                c.execute("UPDATE settings SET v='0' WHERE k='default_pw'")
                flash("Login updated.", "ok")
        return redirect(url_for("account"))
    return render_template("account.html")


@app.route("/admin/setup")
@login_required
def setup():
    return render_template("setup.html", base=request.host_url.rstrip("/"))


@app.route("/docs")
def docs():
    return render_template("docs.html", base=request.host_url.rstrip("/"))


# ---------- public API ----------
def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


@app.get("/api/v1/health")
def api_health():
    s = db.all_settings()
    return jsonify({"ok": True, "upstream": s["cookie_status"],
                    "cooling_down": int(s["cooldown_until"]) > db.now()})


@app.route("/api/v1/check", methods=["GET", "POST"])
def api_check():
    t0 = time.time()
    supplied = request.headers.get("X-API-Key") or request.args.get("key", "")
    with db.conn() as c:
        key = c.execute("SELECT * FROM api_keys WHERE key=?", (supplied,)).fetchone() if supplied else None
        if not key or not key["active"]:
            return jsonify({"ok": False, "status": "unauthorized", "message": "Missing, invalid or disabled API key"}), 401
        used = c.execute("SELECT COUNT(*) FROM logs WHERE key_id=? AND ts>?", (key["id"], db.now() - 60)).fetchone()[0]
    uid = request.args.get("uid") or (request.get_json(silent=True) or {}).get("uid") or request.form.get("uid")
    if used >= key["rate_limit"]:
        db.add_log(uid or "", "rate_limited", key["id"], key["name"], _ip(), 0, False, 429)
        resp = jsonify({"ok": False, "status": "rate_limited", "message": f"Limit is {key['rate_limit']} requests/minute for this key"})
        resp.headers["Retry-After"] = "30"
        return resp, 429
    result, code, cached = checker.check(uid)
    db.add_log(uid or "", result["status"], key["id"], key["name"], _ip(), int((time.time() - t0) * 1000), cached, code)
    return jsonify(result), code


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")))
