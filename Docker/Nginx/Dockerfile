FROM nginx:1.21-alpine

RUN rm /etc/nginx/conf.d/default.conf
COPY Docker/Nginx/nginx.conf /etc/nginx/conf.d/

# 静的ファイルをコピー
COPY ChatApp/static /usr/share/nginx/html/static