import os
import pymysql

class DB:
    def getConnection():
        try:
            conn = pymysql.connect(
            host=os.getenv('MYSQL_HOST'),
            db=os.getenv('MYSQL_NAME'),
            user=os.getenv('MYSQL_USER'),
            password=os.getenv('MYSQL_PASSWORD'),
            charset="utf8",
            cursorclass=pymysql.cursors.DictCursor
        )
            return conn
        except (ConnectionError):
            print("コネクションエラーです")
            conn.close()
