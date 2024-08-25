# hackathon-begginers-sample
ハッカソンの初級者コース用のChatAppです。

**起動方法**
### 開発環境
```
docker-compose -f docker-compose.dev.yml up --build
```
### 本番環境
```
docker-compose -f docker-compose.prod.yml up --build
```

### ディレクトリ構成
```
.
├── ChatApp                  # サンプルアプリ用ディレクトリ
│   ├── __init__.py
│   ├── app.py
│   ├── models.py
│   ├── static               # 静的ファイル用ディレクトリ
│   ├── templates            # Template(HTML)用ディレクトリ
│   └── util
├── Docker
│   ├── Flask
│   │   ├── Dockerfile.dev   # Flask(Python)開発用Dockerファイル
│   │   ├── Dockerfile.prod  # Flask(Python)本番用Dockerファイル
│   │   └── uwsgi.ini        # uWSGI設定ファイル
│   ├── MySQL
│   │   ├── Dockerfile       # MySQL用Dockerファイル
│   │   ├── init.sql         # MySQL初期設定ファイル
│   │   └── my.cnf
│   └── Nginx
│       ├── Dockerfile       # Nginx用Dockerファイル
│       └── nginx.conf       # Nginx設定ファイル
├── docker-compose.dev.yml   # 開発用Docker-composeファイル
├── docker-compose.prod.yml  # 本番用Docker-composeファイル
└── requirements.txt         # 使用モジュール記述ファイル
```