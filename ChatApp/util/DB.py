import pymysql

class DB:
    def getConnection():
        try:
            conn = pymysql.connect(
            host=os.getenv('DB_HOST'),
            db=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            charset="utf8",
            cursorclass=pymysql.cursors.DictCursor
        )
            return conn
        except (ConnectionError):
            print("コネクションエラーです")
            conn.close()
