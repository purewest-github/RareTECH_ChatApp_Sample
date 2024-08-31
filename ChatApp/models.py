import pymysql
from util.DB import DB
from flask import abort

class dbConnect:
    @staticmethod
    def createUser(uid, name, email, password):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "INSERT INTO users (uid, user_name, email, password) VALUES (%s, %s, %s, %s);"
            cur.execute(sql, (uid, name, email, password))
            conn.commit()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def getUser(email):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "SELECT * FROM users WHERE email=%s;"
            cur.execute(sql, [email])
            user = cur.fetchone()
            return user
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def getChannelAll():
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "SELECT * FROM channels;"
            cur.execute(sql)
            channels = cur.fetchall()
            return channels
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def getChannelById(cid):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "SELECT * FROM channels WHERE id=%s;"
            cur.execute(sql, [cid])
            channel = cur.fetchone()
            return channel
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def getChannelByName(channel_name):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "SELECT * FROM channels WHERE name=%s;"
            cur.execute(sql, [channel_name])
            channel = cur.fetchone()
            return channel
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def addChannel(uid, newChannelName, newChannelDescription):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "INSERT INTO channels (uid, name, abstract) VALUES (%s, %s, %s);"
            cur.execute(sql, (uid, newChannelName, newChannelDescription))
            conn.commit()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def updateChannel(uid, newChannelName, newChannelDescription, cid):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "UPDATE channels SET uid=%s, name=%s, abstract=%s WHERE id=%s;"
            cur.execute(sql, (uid, newChannelName, newChannelDescription, cid))
            conn.commit()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def deleteChannel(cid):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "DELETE FROM channels WHERE id=%s;"
            cur.execute(sql, [cid])
            conn.commit()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def getMessageAll(cid):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "SELECT id, u.uid, user_name, message FROM messages AS m INNER JOIN users AS u ON m.uid = u.uid WHERE cid = %s;"
            cur.execute(sql, [cid])
            messages = cur.fetchall()
            return messages
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def createMessage(uid, cid, message):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "INSERT INTO messages(uid, cid, message) VALUES(%s, %s, %s)"
            cur.execute(sql, (uid, cid, message))
            conn.commit()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    @staticmethod
    def deleteMessage(message_id):
        conn = None
        cur = None
        try:
            conn = DB.getConnection()
            cur = conn.cursor()
            sql = "DELETE FROM messages WHERE id=%s;"
            cur.execute(sql, [message_id])
            conn.commit()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            abort(500)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()