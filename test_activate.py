# -*- coding: utf-8 -*-
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as site_app

c = site_app.app.test_client()
site_app.init_db()

# 1) 管理员登录
r = c.get("/login")
csrf = r.get_data(as_text=True).split('name=_csrf value="')[1].split('"')[0]
r = c.post("/login", data={"username": "admin",
                           "password": site_app.ADMIN_PASSWORD, "_csrf": csrf})
assert r.status_code == 302, ("login status", r.status_code)

# 2) 登录后拿新 CSRF
r = c.get("/")
d = r.get_data(as_text=True)
csrf = d.split('name=_csrf value="')[1].split('"')[0]

# 3) 生成一张通用卡
r = c.post("/", data={"_csrf": csrf, "qty": "1", "days": "30", "note": "act-test"})
cards = [x for x in r.get_data(as_text=True).split("\n") if "GENERIC" in x or "==" in x]
# 更稳妥：直接从 DB 取
import sqlite3
db = sqlite3.connect(site_app.DB_PATH); db.row_factory = sqlite3.Row
row = db.execute("SELECT card FROM cards WHERE note='act-test' ORDER BY id DESC LIMIT 1").fetchone()
card = row["card"]
print("generated card:", card[:24], "...")

# 4) 用 3 段通用卡直接喂 verify_token -> 应失败（二进制不再受理 3 段）
ok, info, dev = site_app.verify_token(site_app.CARD_SECRET, card)
print("3段卡 verify_token:", ok, info, "-> 期望 False（需先激活）")
assert ok is False

# 5) 激活：卡 + 设备码
r = c.post("/activate", data={"card": card, "device": "TESTDEV01"})
body = r.get_data(as_text=True)
assert "令牌" in body and "token" in body.lower() or "激活成功" in body, body[:200]
# 提取令牌
import re
mt = re.search(r'<div class=token>(.*?)</div>', body)
assert mt, "未返回令牌"
token = mt.group(1).strip()
print("device token:", token[:24], "...")

# 6) verify_token 校验令牌
ok, info, dev = site_app.verify_token(site_app.CARD_SECRET, token)
print("verify_token:", ok, "device=", dev)
assert ok is True and dev == "TESTDEV01"

# 7) 同一张卡再次激活 -> 应被拒（已绑定）
r = c.post("/activate", data={"card": card, "device": "OTHERDEV"})
body = r.get_data(as_text=True)
print("repeat-activate err:", "已绑定" in body)
assert "已绑定" in body

# 8) 校验 DB 状态
row = db.execute("SELECT status,bound_device FROM cards WHERE card=?", (card,)).fetchone()
print("db status:", row["status"], "bound:", row["bound_device"])
assert row["status"] == "activated" and row["bound_device"] == "TESTDEV01"

# 9) 用设备码不匹配的令牌喂 verify_token（模拟二进制设备不符）-> 这里只验签名+过期，设备由二进制比对
#    verify_token 不比对设备，但模拟“错误设备令牌”应由二进制拒绝；此处确认 dev 字段正确解析
ok, info, dev = site_app.verify_token(site_app.CARD_SECRET, token)
assert dev == "TESTDEV01"

print("ALL ACTIVATION TESTS PASSED")
