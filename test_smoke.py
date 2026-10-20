# -*- coding: utf-8 -*-
import os, time, base64, hmac, hashlib, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as site_app

SECRET = site_app.CARD_SECRET
client = site_app.app.test_client()

def run():
    site_app.init_db()
    # 1) 登录：先用 GET 触发 CSRF 生成，再从 session_transaction 取出 token
    client.get("/login")  # login GET 内部调用 gen_csrf() 写入 session["_csrf"]
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf")
    r = client.post("/login", data={"username": "admin",
                                   "password": os.environ.get("ADMIN_PASSWORD", "changeme__CHANGE_ME_123"),
                                   "_csrf": csrf})
    assert r.status_code in (302, 200), ("login", r.status_code)
    # 登录成功后服务端会重新生成 CSRF，重新取出最新 token
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf")

    # 2) 生成 3 张 1 天卡
    r = client.post("/", data={"qty": "3", "days": "1", "note": "test", "_csrf": csrf})
    html = r.get_data(as_text=True)
    import re
    cards = re.findall(r"([A-Za-z0-9+/]{20,}={0,2})", html)
    # 只取真正的卡密（长 base64 串），过滤掉 csrf token 等
    real = [c for c in cards if len(c) > 60]
    print("generated candidate tokens:", len(real))
    assert len(real) >= 1, "没有生成到卡密"

    ok = bad = 0
    for tok in real[:1]:
        # 3) 验证有效卡
        r = client.post("/check", data={"card": tok})
        t = r.get_data(as_text=True)
        assert "有效" in t, ("should be valid", t)
        ok += 1
        # 4) 篡改卡密 -> 无效
        tampered = tok[:-4] + ("AAAA" if tok[-1] != "A" else "BBBB")
        r = client.post("/check", data={"card": tampered})
        t = r.get_data(as_text=True)
        assert "无效" in t, ("tampered should be invalid", t)
        bad += 1

    # 5) 算法与 C++ verify 一致：手工解卡并验 HMAC + 过期
    tok = real[0]
    payload = base64.b64decode(tok).decode()
    mc, exp, mac_hex = payload.split("\n")
    assert mc == site_app.MACHINE, ("machine", mc)
    expected = hmac.new(SECRET.encode(), (mc+"\n"+exp).encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, mac_hex), "HMAC mismatch with C++ logic"
    assert int(exp) > time.time(), "expiry should be future"
    print("algorithm parity with C++ verifyLicense: OK")

    # 6) 过期卡拒绝（构造一个已过的卡）
    expired = site_app.make_card(SECRET, int(time.time()) - 10)
    r = client.post("/check", data={"card": expired})
    t = r.get_data(as_text=True)
    assert "已过期" in t or "无效" in t, ("expired", t)

    print("E2E login/gen/verify/tamper/expired: OK (valid=%d, tampered=%d)" % (ok, bad))

if __name__ == "__main__":
    run()
