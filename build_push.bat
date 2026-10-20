@echo off
REM =========================================================================
REM  card-site 镜像构建 + 推送脚本（在你自己电脑上跑，需先装 Docker Desktop）
REM  用法：
REM    1) 安装 Docker Desktop（https://www.docker.com/products/docker-desktop/）
REM       安装完首次启动会让你启用 WSL2 后端，按提示点完即可。
REM    2) 去 https://hub.docker.com 注册（邮箱即可，不要手机），登录网页。
REM    3) 网页右上角 Account Settings -> Security -> New Access Token
REM       生成一个读写仓库的 token（Access权限勾 Read/Write），复制下来。
REM    4) 把下面的 DH_USER 改成你的 Docker Hub 用户名，DH_TOKEN 改成刚复制的 token。
REM    5) 双击本文件运行，或在 card_site 目录里打开命令行执行 build_push.bat
REM    6) 看到末尾打印出 "PUSHED: 你的用户名/card-site:latest" 就成功了，
REM       把这一行（镜像地址）发给助手，他帮你配 Render。
REM =========================================================================

set DH_USER=你的DockerHub用户名
set DH_TOKEN=你的DockerHub访问令牌
set IMAGE=%DH_USER%/card-site:latest

echo ===== 构建镜像 =====
docker build -t %IMAGE% .

echo ===== 登录 Docker Hub =====
echo %DH_TOKEN% | docker login -u %DH_USER% --password-stdin

echo ===== 推送镜像 =====
docker push %IMAGE%

echo.
echo PUSHED: %IMAGE%
echo 把上面这行发给助手即可。
pause
