# 17内核 · 发卡站 — 上线与客户使用说明

给很多客户发卡用，需要把站点部署到公网（客户才能访问激活页和后台）。
本目录是一个开箱即用的 Flask 站点，可免费部署到 Render.com。

---

## 一、部署到 Render（免费，拿公网地址，约 5 分钟）

代码已在公开仓库：**https://codeberg.org/xiaoqid/card-site**

> 关键点：Render 不能"直传文件"，但支持从「公共 Git 仓库地址」拉代码。我们用 Codeberg
> 公开仓库，不用再注册 GitHub（也不用连任何 Git 账号到 Render）。

1. 打开 https://dashboard.render.com → 右上角 **New** → **Web Service**。
2. 选 **Public Git Repository**（不是 GitHub/GitLab/Bitbucket 那几个）→ 粘贴：
   `https://codeberg.org/xiaoqid/card-site.git` → **Connect**。
3. 填写表单：
   - **Name**：`17kernel-card`（随便填）
   - **Branch**：`main`
   - **Runtime**：**Python 3**
   - **Build Command**：`pip install -r requirements.txt`
   - **Start Command**：`gunicorn -w 4 -b 0.0.0.0:$PORT app:app`
4. 展开 **Advanced** → **Environment** 添加变量：
   - `CARD_SECRET` = `84ca1fb19e20a7da73035a8bdd3ca406a422b7414145487cc7be9c658bc9ec78dce4b24cb8c0bbfd`（与 17内核 一致，**别改**）
   - `ADMIN_PASSWORD` = 你自己设一个强密码（后台登录用，**务必填**，否则用默认随机密码）
   - `SESSION_SECRET` 不用填（Render 自动生成保管）
5. 点 **Create Web Service** → 等 1–2 分钟构建 → 拿到永久地址 `https://17kernel-card.onrender.com`。

> 因为是「Public Git Repository」方式，render.yaml 不会被自动读取，所以上面的命令/变量要手填。
> 免费档特性：15 分钟无访问会休眠，下次访问约 30 秒冷启动；SQLite 重启清空库存（已发卡密不受影响）。

---

## 二、后续更新代码（可选）

仓库已在 Codeberg：`https://codeberg.org/xiaoqid/card-site`。改完本地文件后：

```bash
cd card_site
git add -A
git commit -m "update"
git push
```

Render 在「Public Git Repository」方式下**不会自动拉新代码**，需到 Render 后台该服务页
点 **Manual Deploy → Deploy latest commit** 手动重新部署。

---

## 三、客户使用流程（发给买家的话术）

1. 你（管理员）在后台 `/` 生成卡密，把卡密发给客户。
2. 客户打开站点 **激活页 `/activate`**，粘贴卡密 + 他手机里程序显示的「本机设备码」，点激活。
3. 激活页返回一串**设备锁令牌**。
4. 客户把令牌粘贴回程序（程序里输入卡密的地方），程序本地校验令牌里的设备码 == 本机，通过即授权。
5. 一张卡只能激活一台设备；被别人先激活，原买家就用不了（防二次传播）。

> 设备码在程序里的「其他/授权」页面显示（由 `AuthDeviceCode()` 提供）。

---

## 四、后台管理功能

登录 `/`（管理员账号 `admin` + 你设的密码）后：

- **生成卡密**：填数量 / 有效天数 / 备注，批量生成通用卡密。
- **库存表**：每张卡的状态（未用 / 已激活 / 已封禁）、绑定设备、激活时间。
- **删卡**：只能删未使用、未绑定的卡。
- **封禁 / 解封**：封禁后该卡失效；若客户开了心跳，程序会收到封禁回执并强制退出。
- **加时长**：已绑定卡延长有效期并**重发新令牌**（客户替换旧令牌）；未绑定卡仅延长。
- **设备页 `/devices`**：查看每台设备、最后在线时间、在线状态（近 15 分钟）、是否封禁，可按设备码搜索。
- **在线设备数**：后台顶部汇总「近 15 分钟在线设备数」（依赖客户开启心跳上报）。

---

## 五、实时在线 / 封禁回执（可选心跳）

默认程序**完全离线**。若你想看客户实时在线数、或封禁卡能即时让程序退出：

让客户在手机上创建文件 `/sdcard/storm2_hb.txt`，内容填你的发卡站地址，例如：

```
https://17kernel-card.onrender.com
```

程序检测到该文件后，每 60 秒向 `<地址>/hb` 上报设备码 + 令牌（纯 HTTP、失败静默、不阻塞游戏）。
后台据此更新在线状态；封禁的卡心跳会收到 `banned:true`，程序立即退出。

> 不配置该文件时，程序绝不联网，与之前完全一致。

---

## 六、安全说明

- 卡密算法：HMAC-SHA256 + Base64，离线校验，无密钥无法伪造、无法篡改有效期。
- 后台：pbkdf2 密码哈希、签名会话、CSRF 防护、登录失败限流、参数化 SQL、常量时间 HMAC 比较。
- 密钥已与分发的 17内核 二进制绑定，修改需两端同步。
- 免费档 SQLite 重启清空库存属正常；已发卡密长期有效。
