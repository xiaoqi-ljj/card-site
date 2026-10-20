import os, sys, time, json, sqlite3, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as site_app

DB = site_app.DB_PATH

# 预清理
def reset():
    if os.path.exists(DB):
        os.remove(DB)
    site_app.init_db()

c = site_app.app.test_client()

def login():
    r = c.get("/login")
    csrf = r.get_data(as_text=True).split('name=_csrf value="')[1].split('"')[0]
    c.post("/login", data={"username": "admin", "password": site_app.ADMIN_PASSWORD, "_csrf": csrf})
    r = c.get("/")
    return r.get_data(as_text=True).split('name=_csrf value="')[1].split('"')[0]

def hdr():
    return {"Content-Type": "application/json"}

reset()
csrf = login()

# 1) 生成 1 张卡
r = c.post("/", data={"_csrf": csrf, "qty": "1", "days": "30", "note": "hb-test"})
db = sqlite3.connect(DB); db.row_factory = sqlite3.Row
card = db.execute("SELECT card FROM cards WHERE note='hb-test' ORDER BY id DESC LIMIT 1").fetchone()["card"]
db.close()
assert card, "card not generated"
print("[1] generated card")

# 2) 激活
r = c.post("/activate", data={"card": card, "device": "DEV-HB"})
body = r.get_data(as_text=True)
assert r.status_code == 200 and '激活成功' in body, "activate failed: " + body[:200]
db = sqlite3.connect(DB); db.row_factory = sqlite3.Row
row = db.execute("SELECT bound_device,status,expiry FROM cards WHERE card=?", (card,)).fetchone()
db.close()
assert row["bound_device"] == "DEV-HB" and row["status"] == "activated", dict(row)
# 令牌不落库（可凭 expiry+device 重现），这里复现买受人拿到的令牌
tok = site_app.make_token(site_app.CARD_SECRET, row["expiry"], "DEV-HB")
assert tok
print("[2] activated -> token minted, bound to DEV-HB")

# 3) 心跳上报（device+token JSON）
r = c.post("/hb", data=json.dumps({"device": "DEV-HB", "token": tok}), headers=hdr())
j = r.get_json()
assert j.get("ok") is True and j.get("banned") is False, j
db = sqlite3.connect(DB); db.row_factory = sqlite3.Row
ls = db.execute("SELECT last_seen FROM devices WHERE device=?", ("DEV-HB",)).fetchone()["last_seen"]
db.close()
assert ls and abs(ls - int(time.time())) < 60, ("last_seen not fresh", ls)
print("[3] /hb OK, last_seen updated ->", ls)

# 4) 仪表盘“在线设备”应 =1
csrf = login()
body = c.get("/").get_data(as_text=True)
m = re.search(r"在线设备\(近15分\)</span><b>(\d+)</b>", body)
assert m and int(m.group(1)) == 1, body[body.find("在线设备")-120:body.find("在线设备")+80]
print("[4] dashboard online count = 1")

# 5) 封禁该卡（后台 act=ban）
csrf = login()
r = c.post("/", data={"_csrf": csrf, "act": "ban", "card": card})
body = r.get_data(as_text=True)
assert "已封禁" in body, body
db = sqlite3.connect(DB); db.row_factory = sqlite3.Row
st = db.execute("SELECT status FROM cards WHERE card=?", (card,)).fetchone()["status"]
db.close()
assert st == "banned", st
print("[5] card banned via dashboard")

# 6) 被封禁后 /hb 应返回 banned:true（二进制据此强制退出）
r = c.post("/hb", data=json.dumps({"device": "DEV-HB", "token": tok}), headers=hdr())
j = r.get_json()
assert j.get("banned") is True, j
print("[6] /hb returns banned:true -> 二进制 AuthShouldQuit() 将强制退出")

# 7) 设备管理页能列出该设备且标记离线/在线
csrf = login()
body = c.get("/devices").get_data(as_text=True)
assert "DEV-HB" in body, "device not listed"
print("[7] /devices lists DEV-HB")

# 清理
db = sqlite3.connect(DB); db.row_factory = sqlite3.Row
db.execute("DELETE FROM cards WHERE note='hb-test'")
db.execute("DELETE FROM devices WHERE device='DEV-HB'")
db.commit(); db.close()
print("\nHEARTBEAT + BAN FLOW OK")
