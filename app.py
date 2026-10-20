# -*- coding: utf-8 -*-
"""
17内核 · 发卡站 (Flask + SQLite) — 设备管理增强版
------------------------------------------------
- 通用卡密（不绑设备）：machine 固定为 GENERIC，仅校验 HMAC 签名 + 过期。
- 设备锁令牌：首次激活后绑定设备，二进制离线校验令牌内设备码 == 本机。
- 设备管理：绑定设备表（devices）、在线状态（最近 N 分钟有上报/激活即在线）、删卡、封禁/解封卡、加时长（绑定卡重发令牌）。
- 心跳端点 /hb：二进制可选上报（默认关），用于实时在线数与封禁回执。
- 安全：pbkdf2 密码哈希、签名会话、CSRF、登录限流、参数化 SQL、常量时间 HMAC 比较。
- 运行：flask run  或  gunicorn -w 4 -b 0.0.0.0:$PORT app:app
"""
import os
import sys
import time
import hmac
import hashlib
import base64
import sqlite3
import secrets
from datetime import datetime, timedelta

from flask import (Flask, request, session, render_template_string, redirect,
                   url_for, jsonify, g)

# ----------------------------- 配置 -----------------------------
# 卡密 HMAC 密钥：必须与 inmyfeelings/src/core/Auth.cpp 的 kLicenseSecret 完全一致！
CARD_SECRET = os.environ.get("CARD_SECRET", "84ca1fb19e20a7da73035a8bdd3ca406a422b7414145487cc7be9c658bc9ec78dce4b24cb8c0bbfd")
# Flask 会话签名密钥：生产环境务必用环境变量覆盖（随机长串）。
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
# 首次启动管理员密码（请尽快在后台修改）。生产环境用环境变量 ADMIN_PASSWORD 覆盖。
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "g0ehu2RZEwMRWWhmDigj1sP8iy0")
# 卡密机器字段（通用卡统一值）
MACHINE = "GENERIC"
# 默认卡密有效期档位（天）
DEFAULT_EXPIRY_DAYS = 30
# “在线”判定窗口：最近这么久内有上报/激活视为在线（秒）
ONLINE_WINDOW = int(os.environ.get("ONLINE_WINDOW", 15 * 60))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("CARD_DB", os.path.join(BASE_DIR, "cards.db"))

app = Flask(__name__)
app.secret_key = SESSION_SECRET

# ----------------------------- 数据库 -----------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        card TEXT UNIQUE NOT NULL,
        machine TEXT NOT NULL,
        expiry INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        note TEXT,
        status TEXT DEFAULT 'unused',
        bound_device TEXT,
        activated_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device TEXT UNIQUE NOT NULL,
        card TEXT,
        first_seen INTEGER,
        last_seen INTEGER,
        banned INTEGER DEFAULT 0,
        note TEXT
    );
    """)
    # 兼容旧库：补列
    for col, typ in (("bound_device", "TEXT"), ("activated_at", "INTEGER")):
        try:
            db.execute("ALTER TABLE cards ADD COLUMN %s %s" % (col, typ))
        except Exception:
            pass
    # 首次启动种植管理员
    cur = db.execute("SELECT COUNT(*) AS c FROM admins")
    if cur.fetchone()["c"] == 0:
        salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac("sha256", ADMIN_PASSWORD.encode(),
                                      salt.encode(), 200000).hex()
        db.execute("INSERT INTO admins (username, pw_hash, salt, created_at) VALUES (?,?,?,?)",
                   ("admin", pw_hash, salt, int(time.time())))
        sys.stderr.write(
            "\n[INIT] 默认管理员 admin / 密码: %s  （请尽快在后台修改）\n" % ADMIN_PASSWORD)
    db.commit()
    db.close()

# ----------------------------- 卡密 / 令牌算法 -----------------------------
def make_card(secret, expiry_unix, machine=MACHINE):
    """与 licensing.cpp signLicense 字节级一致（3 段通用卡）。"""
    exp = str(expiry_unix)
    mac_in = machine + "\n" + exp
    mac = hmac.new(secret.encode("utf-8"), mac_in.encode("utf-8"),
                  hashlib.sha256).hexdigest()
    payload = machine + "\n" + exp + "\n" + mac
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")

def verify_card(secret, token):
    """校验 3 段通用卡：只验签名 + 过期。返回 (ok, info)。"""
    try:
        payload = base64.b64decode(token.strip(), validate=False).decode("utf-8")
    except Exception:
        return False, "卡密格式错误"
    parts = payload.split("\n")
    if len(parts) != 3:
        return False, "卡密格式错误"
    machine, exp, mac_hex = parts
    mac_in = machine + "\n" + exp
    expected = hmac.new(secret.encode("utf-8"), mac_in.encode("utf-8"),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac_hex):
        return False, "卡密签名无效"
    try:
        expiry = int(exp)
    except ValueError:
        return False, "卡密格式错误"
    if time.time() > expiry:
        return False, "卡密已过期"
    return True, str(expiry)

def make_token(secret, expiry_unix, device):
    """设备锁令牌（4 段）：base64("GENERIC\n<exp>\n<dev>\n<HMAC(secret,前三段)>")。"""
    exp = str(expiry_unix)
    mac_in = MACHINE + "\n" + exp + "\n" + device
    mac = hmac.new(secret.encode("utf-8"), mac_in.encode("utf-8"),
                  hashlib.sha256).hexdigest()
    payload = MACHINE + "\n" + exp + "\n" + device + "\n" + mac
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")

def verify_token(secret, token):
    """校验 4 段设备锁令牌：签名 + 过期，返回 (ok, info, device)。"""
    try:
        payload = base64.b64decode(token.strip(), validate=False).decode("utf-8")
    except Exception:
        return False, "令牌格式错误", None
    parts = payload.split("\n")
    if len(parts) != 4:
        return False, "令牌格式错误（不是设备锁令牌）", None
    machine, exp, device, mac_hex = parts
    mac_in = machine + "\n" + exp + "\n" + device
    expected = hmac.new(secret.encode("utf-8"), mac_in.encode("utf-8"),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac_hex):
        return False, "令牌签名无效", None
    try:
        expiry = int(exp)
    except ValueError:
        return False, "令牌格式错误", None
    if time.time() > expiry:
        return False, "令牌已过期", None
    return True, str(expiry), device

# ----------------------------- 设备管理辅助 -----------------------------
def record_activation(device, card):
    """激活时登记设备（首次写入 first_seen / last_seen）。"""
    now = int(time.time())
    db = get_db()
    row = db.execute("SELECT * FROM devices WHERE device=?", (device,)).fetchone()
    if row is None:
        db.execute("INSERT INTO devices (device, card, first_seen, last_seen, banned) "
                   "VALUES (?,?,?,?,0)", (device, card, now, now))
    else:
        db.execute("UPDATE devices SET card=?, last_seen=? WHERE device=?",
                   (card, now, device))
    db.commit()

def touch_device(device, card):
    """心跳上报：更新 last_seen，并在不存在时登记。"""
    now = int(time.time())
    db = get_db()
    row = db.execute("SELECT * FROM devices WHERE device=?", (device,)).fetchone()
    if row is None:
        db.execute("INSERT INTO devices (device, card, first_seen, last_seen, banned) "
                   "VALUES (?,?,?,?,0)", (device, card, now, now))
    else:
        db.execute("UPDATE devices SET last_seen=? WHERE device=?", (now, device))
    db.commit()

def is_online(last_seen):
    return bool(last_seen) and (int(time.time()) - int(last_seen)) <= ONLINE_WINDOW

def fmt_ts(ts):
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "—"

# ----------------------------- 安全辅助 -----------------------------
LOGIN_FAIL = {}  # ip -> [fail_count, lock_until]

def login_allowed(ip):
    rec = LOGIN_FAIL.get(ip)
    if rec and rec[1] > time.time():
        return False
    return True

def login_fail(ip):
    rec = LOGIN_FAIL.get(ip, [0, 0])
    rec[0] += 1
    if rec[0] >= 5:
        rec[1] = time.time() + 60
        rec[0] = 0
    LOGIN_FAIL[ip] = rec

def login_ok(ip):
    LOGIN_FAIL.pop(ip, None)

def gen_csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]

def csrf_ok():
    return request.form.get("_csrf") and \
           hmac.compare_digest(request.form.get("_csrf", ""), session.get("_csrf", ""))

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def deco(*a, **k):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*a, **k)
    return deco

# ----------------------------- 页面模板 -----------------------------
LOGIN_HTML = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>17内核 · 登录</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;
height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#1a1d24;padding:28px 32px;border-radius:12px;width:320px;
box-shadow:0 8px 30px rgba(0,0,0,.5)}
h2{margin:0 0 16px;font-size:18px}
input{width:100%;padding:10px;margin:8px 0;background:#0f1115;border:1px solid #2a2e38;
border-radius:8px;color:#e6e6e6;box-sizing:border-box}
button{width:100%;padding:10px;margin-top:10px;background:#3b82f6;border:0;
border-radius:8px;color:#fff;font-weight:600;cursor:pointer}
.err{color:#ff6b6b;font-size:13px;min-height:16px;margin-top:6px}
</style></head><body><div class=box>
<h2>17内核 · 管理员登录</h2>
<form method=post>
<input name=_csrf value="{{csrf}}" type=hidden>
<input name=username placeholder=用户名 value=admin>
<input name=password type=password placeholder=密码>
<button>登录</button>
</form><div class=err>{{err}}</div>
</div></body></html>"""

NAV = """<div class=bar><h1>17内核 · 发卡后台</h1>
<a href=/ >卡密</a><a href=/devices>设备</a><a href=/check>验证</a><a href=/activate>激活</a>
<span class=muted>管理员 {{user}}</span><a href=/logout>退出</a></div>"""

DASH_HTML = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>17内核 · 发卡后台</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;margin:0}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px}a{color:#3b82f6;text-decoration:none;margin-right:14px}
.bar{display:flex;gap:12px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.card{background:#1a1d24;border:1px solid #2a2e38;border-radius:12px;padding:20px;margin-bottom:20px}
.summary{display:flex;gap:14px;flex-wrap:wrap}
.stat{background:#0f1115;border:1px solid #2a2e38;border-radius:10px;padding:14px 18px;min-width:120px}
.stat b{display:block;font-size:22px;margin-top:4px}
.stat.green b{color:#4ade80}.stat.red b{color:#ff6b6b}.stat.blue b{color:#3b82f6}
label{display:block;margin:10px 0 4px;font-size:13px;color:#9aa0ac}
input,select{width:100%;padding:9px;background:#0f1115;border:1px solid #2a2e38;
border-radius:8px;color:#e6e6e6;box-sizing:border-box}
button{margin-top:12px;background:#3b82f6;border:0;border-radius:8px;color:#fff;
padding:10px 16px;font-weight:600;cursor:pointer}
.btn-sm{padding:4px 8px;font-size:12px;margin:0 2px 0 0;border-radius:6px}
.btn-del{background:#ef4444}.btn-ban{background:#f59e0b}.btn-ext{background:#10b981}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #2a2e38;vertical-align:middle}
.code{font-family:monospace;word-break:break-all}
.muted{color:#9aa0ac;font-size:12px}
.on{color:#4ade80}.off{color:#9aa0ac}.banned{color:#ff6b6b}
.token{margin-top:10px;padding:10px;background:#0f1115;border:1px dashed #10b981;
border-radius:8px;font-family:monospace;font-size:12px;word-break:break-all;white-space:pre-wrap}
</style></head><body><div class=wrap>
{{nav}}
{% if flash %}<div class=token>{{flash}}</div>{% endif %}

<div class=summary>
<div class=stat><span class=muted>总卡数</span><b>{{s_total}}</b></div>
<div class=stat blue><span class=muted>已激活</span><b>{{s_activated}}</b></div>
<div class=stat green><span class=muted>在线设备(近{{win}}分)</span><b>{{s_online}}</b></div>
<div class=stat red><span class=muted>已封禁卡</span><b>{{s_banned}}</b></div>
</div>

<div class=card>
<h3>批量生成通用卡密</h3>
<form method=post>
<input name=_csrf value="{{csrf}}" type=hidden>
<label>数量</label><input name=qty type=number min=1 max=500 value=10>
<label>有效期（天）</label>
<select name=days>
<option value=1>1 天</option><option value=3>3 天</option>
<option value=7>7 天</option><option value=30 selected>30 天</option>
<option value=90>90 天</option><option value=365>365 天</option>
</select>
<label>备注（可选）</label><input name=note placeholder=批次/渠道>
<button>生成</button>
</form>
{% if new_cards %}<div class=muted style="margin-top:14px">本次生成 {{new_cards|length}} 张（已复制可用）：</div>
{% for c in new_cards %}<div class=code>{{c}}</div>{% endfor %}{% endif %}
</div>

<div class=card>
<h3>卡密库存（最近 200 条）</h3>
<table><tr><th>#</th><th>卡密</th><th>过期</th><th>状态</th><th>绑定设备</th><th>在线</th><th>备注</th><th>操作</th></tr>
{% for r in rows %}<tr><td>{{loop.index}}</td>
<td class=code>{{r.card}}</td><td>{{r.expiry_fmt}}</td>
<td>{% if r.status=='banned' %}<span class=banned>已封禁</span>{% elif r.status=='activated' %}已激活{% else %}未使用{% endif %}</td>
<td class=code>{% if r.bound_device %}{{r.bound_device}}{% else %}—{% endif %}</td>
<td>{% if r.online %}<span class=on>在线</span>{% else %}<span class=off>离线</span>{% endif %}</td>
<td>{{r.note or ''}}</td>
<td>
{% if r.status!='banned' %}<form method=post style="display:inline"><input name=_csrf value="{{csrf}}" type=hidden><input name=card value="{{r.card}}" type=hidden><button class="btn-sm btn-ban" name=act value=ban>封禁</button></form>{% else %}<form method=post style="display:inline"><input name=_csrf value="{{csrf}}" type=hidden><input name=card value="{{r.card}}" type=hidden><button class="btn-sm btn-ext" name=act value=unban>解封</button></form>{% endif %}
<form method=post style="display:inline"><input name=_csrf value="{{csrf}}" type=hidden><input name=card value="{{r.card}}" type=hidden><input name=days value=30 size=2 style="width:42px;display:inline;padding:3px"><button class="btn-sm btn-ext" name=act value=extend>加时长</button></form>
{% if r.status=='unused' %}<form method=post style="display:inline"><input name=_csrf value="{{csrf}}" type=hidden><input name=card value="{{r.card}}" type=hidden><button class="btn-sm btn-del" name=act value=delete>删卡</button></form>{% endif %}
</td></tr>{% endfor %}
</table>
</div>
<div class=muted>操作说明：封禁=作废该卡（已激活设备若开启了心跳上报会被强制退出）；加时长=延长有效期，若已绑定设备会同时重发一枚新设备令牌（把下方令牌发给买家替换）；删卡仅限未使用卡。在线=该卡绑定设备近 {{win}} 分钟内有激活/心跳上报。</div>
</div></body></html>"""

DEVICES_HTML = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>17内核 · 设备管理</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;margin:0}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px}a{color:#3b82f6;text-decoration:none;margin-right:14px}
.bar{display:flex;gap:12px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.card{background:#1a1d24;border:1px solid #2a2e38;border-radius:12px;padding:20px;margin-bottom:20px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #2a2e38;vertical-align:middle}
.code{font-family:monospace;word-break:break-all}
.muted{color:#9aa0ac;font-size:12px}
.on{color:#4ade80}.off{color:#9aa0ac}.banned{color:#ff6b6b}
button{margin-top:0;background:#3b82f6;border:0;border-radius:8px;color:#fff;
padding:5px 10px;font-weight:600;cursor:pointer}
.btn-sm{padding:4px 8px;font-size:12px;border-radius:6px}
.btn-ban{background:#f59e0b}.btn-del{background:#ef4444}
.summary{display:flex;gap:14px;flex-wrap:wrap}
.stat{background:#0f1115;border:1px solid #2a2e38;border-radius:10px;padding:14px 18px;min-width:120px}
.stat b{display:block;font-size:22px;margin-top:4px}
.stat.green b{color:#4ade80}.stat.red b{color:#ff6b6b}
</style></head><body><div class=wrap>
{{nav}}
<div class=summary>
<div class=stat><span class=muted>设备总数</span><b>{{s_dev_total}}</b></div>
<div class=stat green><span class=muted>在线(近{{win}}分)</span><b>{{s_dev_online}}</b></div>
<div class=stat red><span class=muted>已封禁设备</span><b>{{s_dev_banned}}</b></div>
</div>
<div class=card>
<h3>设备列表（最近 300 条）</h3>
<table><tr><th>#</th><th>设备码</th><th>绑定卡密</th><th>首见</th><th>最近活跃</th><th>状态</th><th>操作</th></tr>
{% for d in rows %}<tr><td>{{loop.index}}</td>
<td class=code>{{d.device}}</td>
<td class=code>{% if d.card %}{{d.card}}{% else %}—{% endif %}</td>
<td>{{d.first}}</td><td>{{d.last}}</td>
<td>{% if d.banned %}<span class=banned>已封禁</span>{% elif d.online %}<span class=on>在线</span>{% else %}<span class=off>离线</span>{% endif %}</td>
<td>{% if d.banned %}<form method=post style="display:inline"><input name=_csrf value="{{csrf}}" type=hidden><input name=device value="{{d.device}}" type=hidden><button class="btn-sm btn-ban" name=act value=unban>解封</button></form>{% else %}<form method=post style="display:inline"><input name=_csrf value="{{csrf}}" type=hidden><input name=device value="{{d.device}}" type=hidden><button class="btn-sm btn-ban" name=act value=ban>封禁</button></form>{% endif %}</td>
</tr>{% endfor %}
</table>
</div>
<div class=muted>设备=买家首次激活时上报的本机设备码。在线=近 {{win}} 分钟内有激活或心跳上报（需在二进制侧启用心跳：设备放 /sdcard/storm2_hb.txt 写发卡站地址）。封禁设备=其心跳会被服务端判 banned，启用心跳的客户端会强制退出。</div>
</div></body></html>"""

ACTIVATE_HTML = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>17内核 · 卡密激活</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;
height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#1a1d24;padding:28px 32px;border-radius:12px;width:380px;
box-shadow:0 8px 30px rgba(0,0,0,.5)}
h2{margin:0 0 8px;font-size:18px}
.steps{font-size:12px;color:#9aa0ac;line-height:1.7;margin-bottom:14px}
input{width:100%;padding:10px;margin:8px 0;background:#0f1115;border:1px solid #2a2e38;
border-radius:8px;color:#e6e6e6;box-sizing:border-box}
button{width:100%;padding:10px;margin-top:10px;background:#3b82f6;border:0;
border-radius:8px;color:#fff;font-weight:600;cursor:pointer}
.err{color:#ff6b6b;font-size:13px;min-height:16px;margin-top:6px}
.ok{color:#4ade80;font-size:14px;margin-top:12px;word-break:break-all}
.token{margin-top:10px;padding:10px;background:#0f1115;border:1px dashed #3b82f6;
border-radius:8px;font-family:monospace;font-size:12px;word-break:break-all}
</style></head><body><div class=box>
<h2>17内核 · 卡密激活（绑设备）</h2>
<div class=steps>① 在程序里复制“本机设备码” → ② 在此粘贴卡密+设备码 →
③ 点激活 → ④ 把下方令牌粘贴回程序。</div>
<form method=post>
<input name=card placeholder=卡密（通用卡）>
<input name=device placeholder=本机设备码>
<button>激活并获取令牌</button>
</form>
<div class=err>{{err}}</div>
{% if token %}<div class=ok>激活成功！把下面这串令牌粘贴回程序：</div>
<div class=token>{{token}}</div>{% endif %}
</div></body></html>"""

CHECK_HTML = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>17内核 · 卡密验证</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;
height:100vh;align-items:center;justify-content:center;margin:0}
.box{background:#1a1d24;padding:28px 32px;border-radius:12px;width:340px}
h2{margin:0 0 14px;font-size:18px}
input{width:100%;padding:10px;margin:8px 0;background:#0f1115;border:1px solid #2a2e38;
border-radius:8px;color:#e6e6e6;box-sizing:border-box}
button{width:100%;padding:10px;margin-top:10px;background:#3b82f6;border:0;
border-radius:8px;color:#fff;font-weight:600;cursor:pointer}
.msg{font-size:14px;margin-top:12px;min-height:20px}
.ok{color:#4ade80}.bad{color:#ff6b6b}
</style></head><body><div class=box>
<h2>卡密验证</h2>
<form method=post><input name=card placeholder=粘贴卡密>
<button>验证</button></form>
<div class="msg {{cls}}">{{msg}}</div>
</div></body></html>"""

# ----------------------------- 路由 -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_HTML, csrf=gen_csrf(), err="")
    ip = request.remote_addr
    if not login_allowed(ip):
        return render_template_string(LOGIN_HTML, csrf=gen_csrf(),
                                     err="尝试过多，请 60 秒后再试")
    if not csrf_ok():
        return render_template_string(LOGIN_HTML, csrf=gen_csrf(), err="CSRF 校验失败")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    row = db.execute("SELECT * FROM admins WHERE username=?",
                     (username,)).fetchone()
    if row:
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), row["salt"].encode(), 200000)
        if hmac.compare_digest(h.hex(), row["pw_hash"]):
            login_ok(ip)
            session["admin"] = username
            session["_csrf"] = secrets.token_hex(16)
            return redirect(url_for("dashboard"))
    login_fail(ip)
    return render_template_string(LOGIN_HTML, csrf=gen_csrf(), err="用户名或密码错误")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@auth_required
def dashboard():
    db = get_db()
    flash = ""
    if request.method == "POST":
        if not csrf_ok():
            return redirect(url_for("dashboard"))
        act = request.form.get("act", "")
        card = (request.form.get("card", "") or "").strip()
        if act in ("ban", "unban", "delete", "extend") and card:
            row = db.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
            if row:
                if act == "ban":
                    if row["status"] != "banned":
                        db.execute("UPDATE cards SET status='banned' WHERE card=?", (card,))
                        # 同步封禁其绑定设备（心跳会强制退出）
                        if row["bound_device"]:
                            db.execute("UPDATE devices SET banned=1 WHERE device=?",
                                       (row["bound_device"],))
                        flash = "已封禁该卡（含其绑定设备）"
                elif act == "unban":
                    db.execute("UPDATE cards SET status='unused' WHERE card=?", (card,))
                    if row["bound_device"]:
                        db.execute("UPDATE devices SET banned=0 WHERE device=?",
                                   (row["bound_device"],))
                    flash = "已解封该卡"
                elif act == "delete":
                    if row["status"] == "unused":
                        db.execute("DELETE FROM cards WHERE card=?", (card,))
                        flash = "已删除未使用卡"
                    else:
                        flash = "仅未使用卡可删（已激活/封禁请先解封或保留）"
                elif act == "extend":
                    try:
                        days = max(1, min(3650, int(request.form.get("days", 30))))
                    except ValueError:
                        days = 30
                    new_expiry = int(row["expiry"]) + days * 86400
                    db.execute("UPDATE cards SET expiry=? WHERE card=?", (new_expiry, card))
                    dev = row["bound_device"]
                    if dev:
                        # 绑定卡：重发一枚新设备锁令牌给买家替换
                        flash = ("已加 %d 天。新设备令牌（发给买家替换旧令牌）：\n%s"
                                 % (days, make_token(CARD_SECRET, new_expiry, dev)))
                    else:
                        flash = "已加 %d 天（未绑定设备，买家下次激活即生效）"
                db.commit()
        elif not act:
            # 批量生成通用卡（无 act 的生成表单）
            try:
                qty = max(1, min(500, int(request.form.get("qty", 10))))
            except ValueError:
                qty = 10
            days = int(request.form.get("days", DEFAULT_EXPIRY_DAYS))
            note = (request.form.get("note", "") or "")[:64]
            expiry = int(time.time()) + days * 86400
            now = int(time.time())
            inserted = 0
            for i in range(qty):
                # 同秒同过期会生成完全相同的令牌（被 UNIQUE 去重），故每张加 i 秒偏移，
                # 二进制只校验 now<expiry，偏移对其无影响，却能让批量卡密各不相同。
                tok = make_card(CARD_SECRET, expiry + i)
                try:
                    db.execute("INSERT INTO cards (card, machine, expiry, created_at, note) "
                               "VALUES (?,?,?,?,?)", (tok, MACHINE, expiry + i, now, note))
                    inserted += 1
                except sqlite3.IntegrityError:
                    pass
            db.commit()
            flash = "已生成 %d 张卡密" % inserted
    # 汇总
    s_total = db.execute("SELECT COUNT(*) c FROM cards").fetchone()["c"]
    s_activated = db.execute("SELECT COUNT(*) c FROM cards WHERE status='activated'").fetchone()["c"]
    s_banned = db.execute("SELECT COUNT(*) c FROM cards WHERE status='banned'").fetchone()["c"]
    # 在线设备数 = 近窗口内有上报且未封禁的去重设备数（避免一张卡多次计数）
    s_online = db.execute(
        "SELECT COUNT(*) c FROM (SELECT DISTINCT device FROM devices "
        "WHERE banned=0 AND last_seen IS NOT NULL AND last_seen>?)",
        (int(time.time()) - ONLINE_WINDOW,)).fetchone()["c"]
    rows = db.execute(
        "SELECT * FROM cards ORDER BY id DESC LIMIT 200").fetchall()
    out = []
    for r in rows:
        online = False
        if r["bound_device"]:
            d = db.execute("SELECT last_seen FROM devices WHERE device=?",
                           (r["bound_device"],)).fetchone()
            if d and is_online(d["last_seen"]):
                online = True
        out.append({
            "card": r["card"],
            "expiry_fmt": fmt_ts(r["expiry"]),
            "status": r["status"],
            "note": r["note"],
            "bound_device": r["bound_device"] or "",
            "activated_fmt": fmt_ts(r["activated_at"]),
            "online": online,
        })
    nav_html = render_template_string(NAV, user=session["admin"])
    return render_template_string(DASH_HTML, nav=nav_html,
                                 csrf=gen_csrf(), user=session["admin"], rows=out, flash=flash,
                                 s_total=s_total, s_activated=s_activated,
                                 s_online=s_online, s_banned=s_banned,
                                 win=ONLINE_WINDOW // 60, new_cards=[])

@app.route("/devices")
@auth_required
def devices():
    db = get_db()
    s_dev_total = db.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    s_dev_banned = db.execute("SELECT COUNT(*) c FROM devices WHERE banned=1").fetchone()["c"]
    s_dev_online = db.execute(
        "SELECT COUNT(*) c FROM devices WHERE banned=0 AND last_seen>? AND last_seen IS NOT NULL",
        (int(time.time()) - ONLINE_WINDOW,)).fetchone()["c"]
    rows = db.execute(
        "SELECT * FROM devices ORDER BY last_seen DESC LIMIT 300").fetchall()
    out = []
    for d in rows:
        out.append({
            "device": d["device"],
            "card": d["card"] or "",
            "first": fmt_ts(d["first_seen"]),
            "last": fmt_ts(d["last_seen"]),
            "online": (not d["banned"]) and is_online(d["last_seen"]),
            "banned": bool(d["banned"]),
        })
    return render_template_string(DEVICES_HTML, nav=render_template_string(NAV, user=session["admin"]),
                                 csrf=gen_csrf(), user=session["admin"], rows=out,
                                 s_dev_total=s_dev_total, s_dev_online=s_dev_online,
                                 s_dev_banned=s_dev_banned, win=ONLINE_WINDOW // 60)

@app.route("/device/ban", methods=["POST"])
@auth_required
def device_ban():
    if not csrf_ok():
        return redirect(url_for("devices"))
    device = (request.form.get("device", "") or "").strip()
    act = request.form.get("act", "")
    db = get_db()
    if device:
        cur = db.execute("SELECT banned FROM devices WHERE device=?", (device,)).fetchone()
        if cur is not None:
            b = 0 if act == "unban" else 1
            db.execute("UPDATE devices SET banned=? WHERE device=?", (b, device))
            db.commit()
    return redirect(url_for("devices"))

@app.route("/check", methods=["GET", "POST"])
def check():
    msg, cls = "", ""
    if request.method == "POST":
        tok = request.form.get("card", "")
        ok, info = verify_card(CARD_SECRET, tok)
        if ok:
            exp = datetime.utcfromtimestamp(int(info)).strftime("%Y-%m-%d %H:%M UTC")
            msg = "有效，过期时间：%s" % exp
            cls = "ok"
        else:
            msg = "无效：%s" % info
            cls = "bad"
    return render_template_string(CHECK_HTML, msg=msg, cls=cls)

@app.route("/activate", methods=["GET", "POST"])
def activate():
    err, token = "", ""
    if request.method == "POST":
        card = (request.form.get("card", "") or "").strip()
        device = (request.form.get("device", "") or "").strip()
        if not card or not device:
            err = "卡密和设备码都不能为空"
        else:
            ok, info = verify_card(CARD_SECRET, card)
            if not ok:
                err = "卡密无效：" + info
            else:
                expiry = int(info)
                db = get_db()
                row = db.execute("SELECT * FROM cards WHERE card=?",
                                 (card,)).fetchone()
                if row and row["bound_device"]:
                    err = "该卡密已绑定设备（%s），不能重复激活" % row["bound_device"]
                else:
                    now = int(time.time())
                    db.execute(
                        "UPDATE cards SET bound_device=?, activated_at=?, status='activated' "
                        "WHERE card=?", (device, now, card))
                    db.commit()
                    token = make_token(CARD_SECRET, expiry, device)
                    record_activation(device, card)
    return render_template_string(ACTIVATE_HTML, err=err, token=token)

@app.route("/hb", methods=["POST"])
def hb():
    """二进制心跳上报（可选，默认关）。返回 banned:true 时客户端应退出。"""
    j = request.get_json(silent=True) or {}
    device = (j.get("device") or request.form.get("device") or "").strip()
    token = (j.get("token") or request.form.get("token") or "").strip()
    if not device or not token:
        return jsonify({"ok": False, "error": "missing"}), 400
    ok, info, dev = verify_token(CARD_SECRET, token)
    if not ok or dev != device:
        return jsonify({"ok": False, "error": "bad token"}), 403
    db = get_db()
    card_row = db.execute("SELECT * FROM cards WHERE bound_device=?", (device,)).fetchone()
    banned = False
    if card_row is None:
        # 未登记激活（理论上 activate 先建），仍记录一次
        touch_device(device, "")
    else:
        if card_row["status"] == "banned":
            banned = True
        touch_device(device, card_row["card"])
    dev_row = db.execute("SELECT banned FROM devices WHERE device=?", (device,)).fetchone()
    if dev_row and dev_row["banned"]:
        banned = True
    return jsonify({"ok": True, "banned": banned, "expiry": int(info)})

# 健康检查（部署平台探活用）
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
