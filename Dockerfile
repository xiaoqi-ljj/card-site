# card-site 容器镜像
# 基础镜像已含 Python 3.11，requirements.txt 只有 Flask + gunicorn
FROM python:3.11-slim

WORKDIR /app

# 先装依赖（利用层缓存）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 再拷源码
COPY . .

# 清掉本地专用文件，绝不要把本地密码 / 本地库带进镜像
RUN rm -f .adminpw cards.db server.log && rm -rf __pycache__ .git

# Render 用环境变量 PORT 指定监听端口；gunicorn 在此绑定
EXPOSE 10000
CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:$PORT app:app"]
