# -*- coding: utf-8 -*-
"""公益卡端到端测试：生成 / 标记 / 过期时间 / 一机一码。

用临时数据库跑，不碰 cards.db。
"""
import os
import sys
import time
import sqlite3
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_tmp = os.path.join(tempfile.gettempdir(), "promo_test_%d.db" % int(time.time()))
os.environ["CARD_DB"] = _tmp

import app as A  # noqa: E402


def csrf_from(html):
    return html.split('name=_csrf value="')[1].split('"')[0]


def main():
    c = A.app.test_client()

    r = c.get("/login")
    r = c.post("/login", data={"username": "admin", "password": A.ADMIN_PASSWORD,
                               "_csrf": csrf_from(r.get_data(as_text=True))})
    assert r.status_code == 302
    r = c.get("/")
    csrf = csrf_from(r.get_data(as_text=True))

    t0 = int(time.time())
    r = c.post("/", data={"_csrf": csrf, "act": "gen_promo",
                          "qty": "2", "months": "3", "note": "公益测试"})
    body = r.get_data(as_text=True)
    assert "已生成 2 张公益卡（3 个月 / 90 天）" in body
    print("[1] 生成 2 张公益卡")

    db = sqlite3.connect(A.DB_PATH)
    db.row_factory = sqlite3.Row
    rows = db.execute("SELECT * FROM cards WHERE kind='promo' ORDER BY id").fetchall()
    assert len(rows) == 2
    for row in rows:
        days = round((row["expiry"] - t0) / 86400)
        assert 89 <= days <= 91, days
    print("[2] kind=promo，有效期 90 天")

    html = c.get("/?kind=promo").get_data(as_text=True)
    assert "公益" in html and "只看公益卡" in html
    print("[3] 后台标签与筛选正常")

    card1, card2 = rows[0]["card"], rows[1]["card"]
    j = c.post("/api/activate", json={"card": card1, "device": "DEV-PROMO-1"}).get_json()
    assert j.get("ok") is True, j
    ok, _info, dev = A.verify_token(A.CARD_SECRET, j["token"])
    assert ok and dev == "DEV-PROMO-1"
    print("[4] 设备 1 激活成功，令牌可验签")

    r = c.post("/api/activate", json={"card": card1, "device": "DEV-PROMO-2"})
    assert r.status_code == 403 and "已绑定其它设备" in r.get_json()["error"]
    print("[5] 同卡换设备被拒（一机一码）")

    r = c.post("/api/activate", json={"card": card2, "device": "DEV-PROMO-1"})
    assert r.status_code == 403 and "已绑定另一张卡密" in r.get_json()["error"]
    print("[6] 同设备换卡被拒（一机一码）")

    db.close()
    print("ALL PROMO TESTS PASSED")


if __name__ == "__main__":
    try:
        main()
    finally:
        try:
            os.remove(_tmp)
        except OSError:
            pass
