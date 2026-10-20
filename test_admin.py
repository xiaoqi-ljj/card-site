# -*- coding: utf-8 -*-
import os, sys, time, json, re, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as site_app

c = site_app.app.test_client()
site_app.init_db()

# 隔离：清掉历史遗留的测试数据
_db = sqlite3.connect(site_app.DB_PATH)
_db.execute("DELETE FROM cards WHERE note='adm-test'")
_db.execute("DELETE FROM devices WHERE device='DEV-AAA'")
_db.commit(); _db.close()

def login():
    r = c.get("/login")
    csrf = r.get_data(as_text=True).split('name=_csrf value="')[1].split('"')[0]
    r = c.post("/login", data={"username": "admin", "password": site_app.ADMIN_PASSWORD, "_csrf": csrf})
    assert r.status_code == 302
    r = c.get("/")
    return r.get_data(as_text=True).split('name=_csrf value="')[1].split('"')[0]

def post_dash(csrf, act, card, days=None):
    data = {"_csrf": csrf, "act": act, "card": card}
    if days is not None: data["days"] = str(days)
    return c.post("/", data=data)

import sqlite3
db = sqlite3.connect(site_app.DB_PATH); db.row_factory = sqlite3.Row
db.isolation_level = None  # autocommit：每次读都看到最新已提交数据，避免快照陈旧

# 1) 登录
csrf = login()
print("[1] login ok")

# 2) 生成两张卡
r = c.post("/", data={"_csrf": csrf, "qty": "2", "days": "30", "note": "adm-test"})
body = r.get_data(as_text=True)
import sqlite3
db = sqlite3.connect(site_app.DB_PATH); db.row_factory = sqlite3.Row
db.isolation_level = None  # autocommit：每次读都看到最新已提交数据，避免快照陈旧
cards = [x["card"] for x in db.execute("SELECT card FROM cards WHERE note='adm-test' ORDER BY id DESC LIMIT 2")]
assert len(cards) == 2, cards
print("[2] generated 2 cards")

# 3) 激活第一张卡 -> 设备出现
r = c.post("/activate", data={"card": cards[0], "device": "DEV-AAA"})
assert "令牌" in r.get_data(as_text=True)
dev = db.execute("SELECT * FROM devices WHERE device='DEV-AAA'").fetchone()
assert dev and dev["card"] == cards[0] and dev["last_seen"]
print("[3] activate -> device DEV-AAA recorded")

# 4) 加时长：第一张已绑定 -> 应重发新令牌
csrf = login()
r = post_dash(csrf, "extend", cards[0], days=60)
body = r.get_data(as_text=True)
m = re.search(r'新设备令牌（发给买家替换旧令牌）：\s*([^\s<]+)', body)
assert m, "extend should reissue token"
new_tok = m.group(1).strip()
ok, info, dev2 = site_app.verify_token(site_app.CARD_SECRET, new_tok)
assert ok and dev2 == "DEV-AAA"
print("[4] extend bound card -> reissued token, expiry+60d:", info)

# 5) 加时长：第二张未绑定 -> 仅延长
csrf = login()
old_exp = db.execute("SELECT expiry FROM cards WHERE card=?", (cards[1],)).fetchone()["expiry"]
r = post_dash(csrf, "extend", cards[1], days=30)
body = r.get_data(as_text=True)
new_exp = db.execute("SELECT expiry FROM cards WHERE card=?", (cards[1],)).fetchone()["expiry"]
assert new_exp == old_exp + 30*86400, (old_exp, new_exp)
assert "发给买家替换旧令牌" not in body, "unbound extend must NOT reissue token"
print("[5] extend unbound card -> expiry +30d, no reissue")

# 6) 封禁第一张卡 -> /hb 返回 banned:true
csrf = login()
post_dash(csrf, "ban", cards[0])
st = db.execute("SELECT status FROM cards WHERE card=?", (cards[0],)).fetchone()["status"]
assert st == "banned"
r = c.post("/hb", json={"device": "DEV-AAA", "token": new_tok})
jb = r.get_json()
assert jb["banned"] is True, jb
print("[6] ban card -> /hb reports banned=True")

# 7) 解封 -> /hb 不再 banned
csrf = login()
post_dash(csrf, "unban", cards[0])
r = c.post("/hb", json={"device": "DEV-AAA", "token": new_tok})
assert r.get_json()["banned"] is False
print("[7] unban -> /hb banned=False")

# 8) 删卡：仅未使用卡可删（第二张未绑定但已是 activated? no, unbound & unused）
#    第二张未激活 -> status unused -> 可删
csrf = login()
r = post_dash(csrf, "delete", cards[1])
assert "已删除" in r.get_data(as_text=True)
gone = db.execute("SELECT 1 FROM cards WHERE card=?", (cards[1],)).fetchone()
assert gone is None
print("[8] delete unbound/unused card ok")

# 9) /hb 更新 last_seen（心跳模拟）
before = db.execute("SELECT last_seen FROM devices WHERE device='DEV-AAA'").fetchone()["last_seen"]
time.sleep(1.1)
r = c.post("/hb", json={"device": "DEV-AAA", "token": new_tok})
after = db.execute("SELECT last_seen FROM devices WHERE device='DEV-AAA'").fetchone()["last_seen"]
assert after >= before + 1, (before, after)
print("[9] /hb updates last_seen:", before, "->", after)

# 10) /devices 页面展示在线设备数与设备行
csrf = login()
r = c.get("/devices")
body = r.get_data(as_text=True)
assert "DEV-AAA" in body and "在线" in body
print("[10] /devices page renders with DEV-AAA")

# 11) 仪表盘汇总：在线设备数=1
csrf = login()
body = c.get("/").get_data(as_text=True)
seg = body.split("在线设备(近15分)</span><b>")[1].split("</b>")[0]
assert int(seg) == 1, ("online count", seg)
print("[11] dashboard online count = 1")

# 清理
db.execute("DELETE FROM cards WHERE note='adm-test'")
db.execute("DELETE FROM devices WHERE device='DEV-AAA'")
db.commit(); db.close()
print("ALL ADMIN TESTS PASSED")
