from typing import Optional, List, Dict, Any
import logging
from datetime import datetime
import hashlib
import os
import uuid
from util.DB import (
    DB, 
    DatabaseError, 
    ConnectionError,
    TransactionError, 
    QueryError,
    ValidationError,
    RecordNotFoundError,
    UniqueConstraintError
)

# ログ設定
logger = logging.getLogger(__name__)

class ModelBase:
    """モデルの基底クラス"""
    def __init__(self):
        self.db = DB()
        self.created_at = datetime.now()
        self.updated_at = datetime.now()

    def _handle_db_error(self, e: Exception, context: str) -> None:
        """データベースエラーのハンドリング"""
        if isinstance(e, UniqueConstraintError):
            logger.warning(f"Unique constraint violation in {context}: {str(e)}")
            raise DatabaseError(f"一意制約違反: {e.field}が重複しています")
        elif isinstance(e, RecordNotFoundError):
            logger.info(f"Record not found in {context}: {str(e)}")
            raise DatabaseError("指定されたレコードが見つかりません")
        elif isinstance(e, ValidationError):
            logger.warning(f"Validation error in {context}: {str(e)}")
            raise DatabaseError(f"入力値が不正です: {e.field}")
        else:
            logger.error(f"Database error in {context}: {str(e)}")
            raise DatabaseError("データベース操作中にエラーが発生しました")

    def _validate_required_fields(self, data: dict, required_fields: List[str]) -> None:
        """必須フィールドの検証"""
        for field in required_fields:
            if not data.get(field):
                raise ValidationError(f"{field}は必須です", field)

class User(ModelBase):
    """ユーザーモデル"""
    def __init__(self):
        super().__init__()
        self.table_name = 'users'
        self.required_fields = ['name', 'email', 'password']

    def _hash_password(self, password: str) -> str:
        """パスワードをハッシュ化"""
        salt = os.getenv('PASSWORD_SALT', 'default_salt')
        return hashlib.sha256(f"{password}{salt}".encode('utf-8')).hexdigest()

    def _validate_user_data(self, name: str, email: str, password: str) -> None:
        """ユーザーデータの検証"""
        if len(name) < 2 or len(name) > 50:
            raise ValidationError("名前は2文字以上50文字以内で入力してください", "name")
        if not email or '@' not in email:
            raise ValidationError("有効なメールアドレスを入力してください", "email")
        if len(password) < 8:
            raise ValidationError("パスワードは8文字以上で入力してください", "password")

    def create(self, name: str, email: str, password: str) -> str:
        """ユーザーを作成"""
        try:
            self._validate_user_data(name, email, password)
            
            uid = str(uuid.uuid4())
            user_fields = ['uid', 'user_name', 'email', 'password', 'created_at', 'updated_at', 'is_active']
            user_data = (
                uid, 
                name, 
                email.lower(), 
                self._hash_password(password),
                self.created_at,
                self.updated_at,
                True
            )
            
            with self.db.transaction() as (conn, cur):
                # ユーザーの重複チェック
                cur.execute("SELECT id FROM users WHERE email = %s FOR UPDATE", (email.lower(),))
                if cur.fetchone():
                    raise UniqueConstraintError("users", "email", email)

                # ユーザーの作成
                insert_sql = self.db.build_insert_query(self.table_name, user_fields)
                cur.execute(insert_sql, user_data)

                # プロフィールの作成
                profile_fields = ['uid', 'created_at', 'updated_at']
                profile_data = (uid, self.created_at, self.updated_at)
                profile_sql = self.db.build_insert_query('user_profiles', profile_fields)
                cur.execute(profile_sql, profile_data)

            logger.info(f"User created successfully: {email}")
            return uid

        except Exception as e:
            self._handle_db_error(e, "user creation")

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """メールアドレスでユーザーを取得"""
        try:
            return self.db.execute_query("""
                SELECT 
                    u.*, 
                    up.profile_image_url,
                    up.bio
                FROM users u
                LEFT JOIN user_profiles up ON u.uid = up.uid
                WHERE u.email = %s AND u.is_active = TRUE
            """, (email.lower(),))
        except RecordNotFoundError:
            return None
        except Exception as e:
            self._handle_db_error(e, "user retrieval")

    def get_by_id(self, uid: str) -> Optional[Dict[str, Any]]:
        """UIDでユーザーを取得"""
        try:
            return self.db.execute_query("""
                SELECT 
                    u.*, 
                    up.profile_image_url,
                    up.bio
                FROM users u
                LEFT JOIN user_profiles up ON u.uid = u.uid
                WHERE u.uid = %s AND u.is_active = TRUE
            """, (uid,))
        except RecordNotFoundError:
            return None
        except Exception as e:
            self._handle_db_error(e, "user retrieval")

    def update(self, uid: str, update_data: Dict[str, Any]) -> None:
        """ユーザー情報を更新"""
        try:
            with self.db.transaction() as (conn, cur):
                if 'email' in update_data:
                    # メールアドレスの重複チェック
                    cur.execute(
                        "SELECT id FROM users WHERE email = %s AND uid != %s",
                        (update_data['email'].lower(), uid)
                    )
                    if cur.fetchone():
                        raise UniqueConstraintError("users", "email", update_data['email'])

                # パスワードのハッシュ化
                if 'password' in update_data:
                    update_data['password'] = self._hash_password(update_data['password'])

                # 更新データの準備
                update_fields = list(update_data.keys())
                update_values = list(update_data.values())
                update_values.append(uid)  # WHERE句のパラメータ

                update_sql = self.db.build_update_query(
                    self.table_name,
                    update_fields,
                    'uid = %s'
                )
                cur.execute(update_sql, update_values)

            logger.info(f"User updated: {uid}")

        except Exception as e:
            self._handle_db_error(e, "user update")

    def delete(self, uid: str) -> None:
        """ユーザーを論理削除"""
        try:
            with self.db.transaction() as (conn, cur):
                # 論理削除（is_activeをFalseに設定）
                update_sql = "UPDATE users SET is_active = FALSE, updated_at = %s WHERE uid = %s"
                cur.execute(update_sql, (self.updated_at, uid))

            logger.info(f"User deleted: {uid}")

        except Exception as e:
            self._handle_db_error(e, "user deletion")

class Channel(ModelBase):
    """チャンネルモデル"""
    def __init__(self):
        super().__init__()
        self.table_name = 'channels'

    def _validate_channel_data(self, name: str, description: str) -> None:
        """チャンネルデータの検証"""
        if not name or len(name) > 50:
            raise ValidationError("チャンネル名は1文字以上50文字以内で入力してください", "name")
        if description and len(description) > 500:
            raise ValidationError("説明は500文字以内で入力してください", "description")

    def create(self, uid: str, name: str, description: str) -> int:
        """チャンネルを作成"""
        try:
            self._validate_channel_data(name, description)
            
            fields = ['uid', 'name', 'description', 'created_at', 'updated_at', 'is_active']
            data = (uid, name, description, self.created_at, self.updated_at, True)
            
            with self.db.transaction() as (conn, cur):
                # チャンネル名の重複チェック
                cur.execute("SELECT id FROM channels WHERE name = %s AND is_active = TRUE", (name,))
                if cur.fetchone():
                    raise UniqueConstraintError("channels", "name", name)

                sql = self.db.build_insert_query(self.table_name, fields)
                cur.execute(sql, data)
                channel_id = cur.lastrowid

            logger.info(f"Channel created: {name} by {uid}")
            return channel_id

        except Exception as e:
            self._handle_db_error(e, "channel creation")

    def get_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """アクティブなチャンネル一覧を取得"""
        try:
            return self.db.execute_query_many("""
                SELECT 
                    c.*,
                    u.user_name as creator_name,
                    COUNT(DISTINCT m.id) as message_count,
                    MAX(m.created_at) as last_message_at
                FROM channels c
                LEFT JOIN users u ON c.uid = u.uid
                LEFT JOIN messages m ON c.id = m.cid
                WHERE c.is_active = TRUE
                GROUP BY c.id
                ORDER BY c.created_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
        except Exception as e:
            self._handle_db_error(e, "channel retrieval")

    def get_by_id(self, channel_id: int) -> Optional[Dict[str, Any]]:
        """チャンネル詳細を取得"""
        try:
            return self.db.execute_query("""
                SELECT 
                    c.*,
                    u.user_name as creator_name
                FROM channels c
                LEFT JOIN users u ON c.uid = u.uid
                WHERE c.id = %s AND c.is_active = TRUE
            """, (channel_id,))
        except RecordNotFoundError:
            return None
        except Exception as e:
            self._handle_db_error(e, "channel retrieval")

    def update(self, channel_id: int, uid: str, name: str, description: str) -> None:
        """チャンネルを更新"""
        try:
            self._validate_channel_data(name, description)
            
            with self.db.transaction() as (conn, cur):
                # 権限チェック
                cur.execute(
                    "SELECT uid FROM channels WHERE id = %s AND is_active = TRUE",
                    (channel_id,)
                )
                channel = cur.fetchone()
                if not channel or channel['uid'] != uid:
                    raise ValidationError("更新権限がありません", "permission")

                # チャンネル名の重複チェック
                cur.execute(
                    "SELECT id FROM channels WHERE name = %s AND id != %s AND is_active = TRUE",
                    (name, channel_id)
                )
                if cur.fetchone():
                    raise UniqueConstraintError("channels", "name", name)

                # 更新
                update_sql = """
                    UPDATE channels 
                    SET name = %s, description = %s, updated_at = %s 
                    WHERE id = %s AND is_active = TRUE
                """
                cur.execute(update_sql, (name, description, self.updated_at, channel_id))

            logger.info(f"Channel updated: {channel_id} by {uid}")

        except Exception as e:
            self._handle_db_error(e, "channel update")

    def delete(self, channel_id: int, uid: str) -> None:
        """チャンネルを論理削除"""
        try:
            with self.db.transaction() as (conn, cur):
                # 権限チェック
                cur.execute(
                    "SELECT uid FROM channels WHERE id = %s AND is_active = TRUE",
                    (channel_id,)
                )
                channel = cur.fetchone()
                if not channel or channel['uid'] != uid:
                    raise ValidationError("削除権限がありません", "permission")

                # 論理削除
                update_sql = """
                    UPDATE channels 
                    SET is_active = FALSE, updated_at = %s 
                    WHERE id = %s
                """
                cur.execute(update_sql, (self.updated_at, channel_id))

            logger.info(f"Channel deleted: {channel_id} by {uid}")

        except Exception as e:
            self._handle_db_error(e, "channel deletion")

class Message(ModelBase):
    """メッセージモデル"""
    def __init__(self):
        super().__init__()
        self.table_name = 'messages'

    def _validate_message_data(self, content: str) -> None:
        """メッセージデータの検証"""
        if not content or len(content) > 1000:
            raise ValidationError("メッセージは1文字以上1000文字以内で入力してください", "content")

    def create(self, uid: str, channel_id: int, content: str) -> int:
        """メッセージを作成"""
        try:
            self._validate_message_data(content)
            
            with self.db.transaction() as (conn, cur):
                # チャンネルの存在確認
                cur.execute(
                    "SELECT id FROM channels WHERE id = %s AND is_active = TRUE",
                    (channel_id,)
                )
                if not cur.fetchone():
                    raise ValidationError("チャンネルが存在しません", "channel_id")

                # メッセージの作成
                message_fields = ['uid', 'channel_id', 'content', 'created_at', 'updated_at']
                message_data = (uid, channel_id, content, self.created_at, self.updated_at)
                
                insert_sql = self.db.build_insert_query(self.table_name, message_fields)
                cur.execute(insert_sql, message_data)
                message_id = cur.lastrowid

                # チャンネルの最終更新を更新
                update_sql = """
                    UPDATE channels 
                    SET updated_at = %s, last_message_at = %s 
                    WHERE id = %s
                """
                cur.execute(update_sql, (self.updated_at, self.updated_at, channel_id))

                return message_id

        except Exception as e:
            self._handle_db_error(e, "message creation")

    def create_with_file(self, uid: str, channel_id: int, content: str, file_url: str) -> int:
        """ファイル付きメッセージを作成"""
        try:
            self._validate_message_data(content)
            
            with self.db.transaction() as (conn, cur):
                # チャンネルの存在確認
                cur.execute(
                    "SELECT id FROM channels WHERE id = %s AND is_active = TRUE",
                    (channel_id,)
                )
                if not cur.fetchone():
                    raise ValidationError("チャンネルが存在しません", "channel_id")

                # メッセージの作成
                message_fields = [
                    'uid', 'channel_id', 'content', 'file_url', 
                    'created_at', 'updated_at'
                ]
                message_data = (
                    uid, channel_id, content, file_url,
                    self.created_at, self.updated_at
                )
                
                insert_sql = self.db.build_insert_query(self.table_name, message_fields)
                cur.execute(insert_sql, message_data)
                message_id = cur.lastrowid

                # チャンネルの最終更新を更新
                update_sql = """
                    UPDATE channels 
                    SET updated_at = %s, last_message_at = %s 
                    WHERE id = %s
                """
                cur.execute(update_sql, (self.updated_at, self.updated_at, channel_id))

                return message_id

        except Exception as e:
            self._handle_db_error(e, "message creation with file")

    def get_by_channel(
        self, 
        channel_id: int, 
        limit: int = 50, 
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """チャンネルのメッセージを取得"""
        try:
            return self.db.execute_query_many("""
                SELECT 
                    m.*,
                    u.user_name,
                    u.email,
                    up.profile_image_url
                FROM messages m
                INNER JOIN users u ON m.uid = u.uid
                LEFT JOIN user_profiles up ON u.uid = up.uid
                WHERE m.channel_id = %s
                ORDER BY m.created_at DESC
                LIMIT %s OFFSET %s
            """, (channel_id, limit, offset))
        except Exception as e:
            self._handle_db_error(e, "message retrieval")

    def get_by_id(self, message_id: int) -> Optional[Dict[str, Any]]:
        """メッセージを取得"""
        try:
            return self.db.execute_query("""
                SELECT 
                    m.*,
                    u.user_name,
                    u.email
                FROM messages m
                INNER JOIN users u ON m.uid = u.uid
                WHERE m.id = %s
            """, (message_id,))
        except Exception as e:
            self._handle_db_error(e, "message retrieval")

    def delete(self, message_id: int, uid: str) -> None:
        """メッセージを削除"""
        try:
            with self.db.transaction() as (conn, cur):
                # メッセージの存在と権限の確認
                cur.execute(
                    "SELECT uid, channel_id FROM messages WHERE id = %s",
                    (message_id,)
                )
                message = cur.fetchone()
                if not message:
                    raise ValidationError("メッセージが存在しません", "message_id")
                if message['uid'] != uid:
                    raise ValidationError("削除権限がありません", "permission")

                # 削除
                delete_sql = "DELETE FROM messages WHERE id = %s"
                cur.execute(delete_sql, (message_id,))

                # チャンネルの最終更新を更新
                update_sql = """
                    UPDATE channels 
                    SET updated_at = %s 
                    WHERE id = %s
                """
                cur.execute(update_sql, (self.updated_at, message['channel_id']))

            logger.info(f"Message deleted: {message_id} by {uid}")

        except Exception as e:
            self._handle_db_error(e, "message deletion")

    def get_recent_messages(
        self,
        channel_id: int,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """最近のメッセージを取得"""
        try:
            return self.db.execute_query_many("""
                SELECT 
                    m.*,
                    u.user_name,
                    u.email,
                    up.profile_image_url
                FROM messages m
                INNER JOIN users u ON m.uid = u.uid
                LEFT JOIN user_profiles up ON u.uid = up.uid
                WHERE m.channel_id = %s
                ORDER BY m.created_at DESC
                LIMIT %s
            """, (channel_id, limit))
        except Exception as e:
            self._handle_db_error(e, "recent message retrieval")

    def search_messages(
        self,
        channel_id: int,
        query: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """メッセージを検索"""
        try:
            search_query = f"%{query}%"
            return self.db.execute_query_many("""
                SELECT 
                    m.*,
                    u.user_name,
                    u.email,
                    up.profile_image_url
                FROM messages m
                INNER JOIN users u ON m.uid = u.uid
                LEFT JOIN user_profiles up ON u.uid = up.uid
                WHERE m.channel_id = %s
                    AND (m.content LIKE %s OR u.user_name LIKE %s)
                ORDER BY m.created_at DESC
                LIMIT %s OFFSET %s
            """, (channel_id, search_query, search_query, limit, offset))
        except Exception as e:
            self._handle_db_error(e, "message search")

# モデルのインスタンス化
user_model = User()
channel_model = Channel()
message_model = Message()