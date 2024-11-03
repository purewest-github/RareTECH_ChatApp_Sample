# util/DB.py

import os
import logging
from typing import Any, Optional, Type
import pymysql
from pymysql.cursors import DictCursor
from contextlib import contextmanager
from datetime import datetime
from dotenv import load_dotenv

# 環境に応じた.envファイルのロード
env_file = '.env.development' if os.getenv('FLASK_ENV') == 'development' else '.env.production'
load_dotenv(env_file)

def setup_logger(name: str) -> logging.Logger:
    """ロガーの設定"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    os.makedirs('logs', exist_ok=True)
    
    file_handler = logging.FileHandler(
        f'logs/db_{datetime.now().strftime("%Y%m%d")}.log',
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(levelname)s - %(message)s'
    ))
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger(__name__)

class DatabaseError(Exception):
    """データベース操作に関する基本例外クラス"""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

class ConnectionError(DatabaseError):
    """データベース接続に関する例外クラス"""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(
            f"データベース接続エラー: {message}",
            original_error
        )

class TransactionError(DatabaseError):
    """トランザクション処理に関する例外クラス"""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(
            f"トランザクションエラー: {message}",
            original_error
        )

class QueryError(DatabaseError):
    """クエリ実行に関する例外クラス"""
    def __init__(self, message: str, query: str = "", params: tuple = (), 
                 original_error: Optional[Exception] = None):
        self.query = query
        self.params = params
        super().__init__(
            f"クエリ実行エラー: {message}",
            original_error
        )

class ValidationError(DatabaseError):
    """データ検証に関する例外クラス"""
    def __init__(self, message: str, field: str = "", value: Any = None):
        self.field = field
        self.value = value
        super().__init__(f"検証エラー - {field}: {message}")

class RecordNotFoundError(DatabaseError):
    """レコード未検出の例外クラス"""
    def __init__(self, table: str, search_params: dict):
        self.table = table
        self.search_params = search_params
        message = f"レコードが見つかりません - テーブル: {table}, 検索条件: {search_params}"
        super().__init__(message)

class UniqueConstraintError(DatabaseError):
    """一意制約違反の例外クラス"""
    def __init__(self, table: str, field: str, value: Any):
        self.table = table
        self.field = field
        self.value = value
        message = f"一意制約違反 - テーブル: {table}, フィールド: {field}, 値: {value}"
        super().__init__(message)

class DB:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        # 環境変数から設定を読み込み
        self.config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'db': os.getenv('DB_NAME', 'chatapp'),
            'user': os.getenv('DB_USER', 'user'),
            'password': os.getenv('DB_PASSWORD', ''),
            'charset': 'utf8mb4',
            'cursorclass': DictCursor,
            'autocommit': False,
            'port': int(os.getenv('DB_PORT', 3306)),
            'connect_timeout': int(os.getenv('DB_CONNECT_TIMEOUT', 5)),
            'ssl': {
                'ssl_ca': os.getenv('DB_SSL_CA'),
                'ssl_cert': os.getenv('DB_SSL_CERT'),
                'ssl_key': os.getenv('DB_SSL_KEY')
            } if os.getenv('DB_USE_SSL') == 'true' else None
        }
        
        # SSL設定が不要な場合は削除
        if not self.config['ssl']:
            del self.config['ssl']
            
        self._initialized = True
        logger.info("DB class initialized with configuration")

    def _handle_database_error(self, e: Exception, error_class: Type[DatabaseError], 
                             message: str, **kwargs) -> None:
        """データベースエラーを適切な例外クラスでラップして再送出"""
        logger.error(f"{message}: {str(e)}")
        raise error_class(message, original_error=e, **kwargs)

    @contextmanager
    def get_connection(self):
        """データベース接続を管理するコンテキストマネージャー"""
        conn = None
        try:
            conn = pymysql.connect(**self.config)
            logger.debug("Database connection established")
            yield conn
        except pymysql.Error as e:
            self._handle_database_error(
                e, 
                ConnectionError,
                "データベース接続の確立に失敗しました"
            )
        finally:
            if conn:
                try:
                    conn.close()
                    logger.debug("Database connection closed")
                except Exception as e:
                    logger.error(f"Error closing connection: {str(e)}")

    @contextmanager
    def get_cursor(self, conn, cursor_class=None):
        """カーソルを管理するコンテキストマネージャー"""
        cursor = None
        try:
            cursor = conn.cursor(cursor_class) if cursor_class else conn.cursor()
            logger.debug("Database cursor created")
            yield cursor
        finally:
            if cursor:
                cursor.close()
                logger.debug("Database cursor closed")

    @contextmanager
    def transaction(self):
        """トランザクションを管理するコンテキストマネージャー"""
        with self.get_connection() as conn:
            try:
                with self.get_cursor(conn) as cursor:
                    yield conn, cursor
                conn.commit()
                logger.debug("Transaction committed successfully")
            except Exception as e:
                conn.rollback()
                logger.error(f"Transaction rolled back: {str(e)}")
                self._handle_database_error(
                    e,
                    TransactionError,
                    "トランザクションの実行に失敗しました"
                )

    def execute_query(self, sql: str, params: tuple = None) -> Optional[dict]:
        """単一のクエリを実行し、1行の結果を返す"""
        try:
            with self.transaction() as (_, cursor):
                cursor.execute(sql, params or ())
                result = cursor.fetchone()
                if not result:
                    raise RecordNotFoundError(
                        table=self._extract_table_name(sql),
                        search_params=dict(zip(range(len(params or ())), params or ()))
                    )
                return result
        except pymysql.IntegrityError as e:
            if e.args[0] == 1062:  # Duplicate entry error
                field = self._extract_field_from_error(str(e))
                raise UniqueConstraintError(
                    table=self._extract_table_name(sql),
                    field=field,
                    value=params[0] if params else None
                )
            self._handle_database_error(
                e,
                QueryError,
                "クエリの実行に失敗しました",
                query=sql,
                params=params
            )

    def execute_query_many(self, sql: str, params: tuple = None) -> list:
        """単一のクエリを実行し、複数行の結果を返す"""
        try:
            with self.transaction() as (_, cursor):
                cursor.execute(sql, params or ())
                return cursor.fetchall()
        except Exception as e:
            self._handle_database_error(
                e,
                QueryError,
                "クエリの実行に失敗しました",
                query=sql,
                params=params
            )

    def execute_batch(self, sql: str, params_list: list) -> None:
        """バッチ処理でクエリを実行"""
        try:
            with self.transaction() as (_, cursor):
                cursor.executemany(sql, params_list)
        except Exception as e:
            self._handle_database_error(
                e,
                QueryError,
                "バッチ処理の実行に失敗しました",
                query=sql,
                params=params_list
            )

    @staticmethod
    def _extract_table_name(sql: str) -> str:
        """SQLクエリからテーブル名を抽出"""
        sql = sql.lower()
        if "from" in sql:
            parts = sql.split("from")[1].strip().split()
            return parts[0].strip('`')
        if "update" in sql:
            parts = sql.split("update")[1].strip().split()
            return parts[0].strip('`')
        if "insert into" in sql:
            parts = sql.split("insert into")[1].strip().split()
            return parts[0].strip('`')
        return ""

    @staticmethod
    def _extract_field_from_error(error_message: str) -> str:
        """エラーメッセージからフィールド名を抽出"""
        import re
        match = re.search(r"key '(\w+)'", error_message)
        return match.group(1) if match else ""

    def validate_table_name(self, table_name: str) -> None:
        """テーブル名のバリデーション"""
        if not table_name or not isinstance(table_name, str):
            raise ValidationError("無効なテーブル名です", "table_name", table_name)

    def validate_field_names(self, fields: list) -> None:
        """フィールド名のバリデーション"""
        if not fields or not isinstance(fields, list):
            raise ValidationError("フィールドリストが無効です", "fields", fields)
        for field in fields:
            if not isinstance(field, str):
                raise ValidationError("無効なフィールド名です", "field", field)

    def build_insert_query(self, table: str, fields: list) -> str:
        """INSERT文を構築"""
        self.validate_table_name(table)
        self.validate_field_names(fields)
        
        placeholders = ','.join(['%s'] * len(fields))
        columns = ','.join(f'`{field}`' for field in fields)
        return f"INSERT INTO `{table}` ({columns}) VALUES ({placeholders})"

    def build_update_query(self, table: str, fields: list, where_clause: str) -> str:
        """UPDATE文を構築"""
        self.validate_table_name(table)
        self.validate_field_names(fields)
        
        set_clause = ','.join([f"`{field}`=%s" for field in fields])
        return f"UPDATE `{table}` SET {set_clause} WHERE {where_clause}"