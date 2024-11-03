from flask import (
    Flask, 
    request, 
    redirect, 
    render_template, 
    session, 
    flash, 
    abort,
    jsonify,
    make_response,
    url_for,
    send_from_directory
)
from datetime import datetime, timedelta
import logging
import uuid
import re
import os
import html
import bleach
import time
from typing import Optional, Union, Dict, Any, Tuple
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import safe_join
from urllib.parse import urlparse, urljoin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from models import (
    user_model, 
    channel_model, 
    message_model, 
    DatabaseError,
    UniqueConstraintError,
    ValidationError
)

# 環境設定の読み込み
env_file = '.env.development' if os.getenv('FLASK_ENV') == 'development' else '.env.production'
load_dotenv(env_file)

# アプリケーションの初期化
app = Flask(__name__)

# セキュリティ設定
app.secret_key = os.getenv('FLASK_SECRET_KEY', uuid.uuid4().hex)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=int(os.getenv('SESSION_LIFETIME_DAYS', 30))),
    JSON_ESCAPE_FORWARD_SLASHES=True,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    UPLOAD_FOLDER=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads'),
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_PROTECTION='strong',
    SESSION_COOKIE_NAME='secure_session',
    SESSION_REFRESH_EACH_REQUEST=True
)

# CSRF保護の有効化
csrf = CSRFProtect(app)

# レート制限の設定
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv('RATE_LIMIT_STORAGE_URI', "memory://")
)

# XSS対策の設定
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'li', 'code']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'rel'],
    'img': ['alt', 'src'],
}

# 定数
EMAIL_PATTERN = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH', 1000))
MIN_PASSWORD_LENGTH = int(os.getenv('MIN_PASSWORD_LENGTH', 8))
MAX_PASSWORD_LENGTH = int(os.getenv('MAX_PASSWORD_LENGTH', 72))
MAX_CHANNEL_NAME_LENGTH = int(os.getenv('MAX_CHANNEL_NAME_LENGTH', 50))
MAX_CHANNEL_DESCRIPTION_LENGTH = int(os.getenv('MAX_CHANNEL_DESCRIPTION_LENGTH', 200))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_UPLOAD_SIZE = int(os.getenv('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))  # 5MB
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOGIN_TIMEOUT = int(os.getenv('LOGIN_TIMEOUT', 300))  # 5 minutes

# ログ設定
def setup_logger():
    """ロガーの設定"""
    log_dir = os.getenv('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.getLevelName(os.getenv('LOG_LEVEL', 'INFO')))
    
    # ファイルハンドラ
    file_handler = logging.FileHandler(
        os.path.join(log_dir, f'app_{datetime.now().strftime("%Y%m%d")}.log'),
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # コンソールハンドラ
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(levelname)s - %(message)s'
    ))
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()


class SecurityHeaders:
    """セキュリティヘッダーの設定クラス"""
    @staticmethod
    def get_csp_policy():
        """CSPポリシーの取得"""
        return {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", "data:", "https:"],
            'font-src': ["'self'"],
            'form-action': ["'self'"],
            'frame-ancestors': ["'none'"],
            'base-uri': ["'self'"],
            'object-src': ["'none'"],
            'connect-src': ["'self'"],
            'media-src': ["'self'"],
            'worker-src': ["'self'"],
            'manifest-src': ["'self'"],
        }

    @staticmethod
    def apply(response):
        """セキュリティヘッダーを適用"""
        csp = '; '.join(
            f"{k} {' '.join(v)}" 
            for k, v in SecurityHeaders.get_csp_policy().items()
        )
        
        response.headers.update({
            'Content-Security-Policy': csp,
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': (
                'geolocation=(), '
                'microphone=(), '
                'camera=(), '
                'payment=(), '
                'usb=(), '
                'magnetometer=(), '
                'gyroscope=()'
            ),
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Resource-Policy': 'same-origin'
        })
        return response

class XSSProtection:
    """XSS対策クラス"""
    @staticmethod
    def sanitize_input(text: Optional[str]) -> str:
        """入力値のサニタイズ処理"""
        if not text:
            return ''
        # HTMLエスケープ
        escaped_text = html.escape(text)
        # 許可されたタグのみ許可
        sanitized_text = bleach.clean(
            escaped_text,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True,
            protocols=['http', 'https', 'mailto']
        )
        return sanitized_text

    @staticmethod
    def sanitize_dict(data: dict) -> dict:
        """辞書型データのサニタイズ処理"""
        return {k: XSSProtection.sanitize_input(v) if isinstance(v, str) else v
                for k, v in data.items()}

class URLValidator:
    """URL検証クラス"""
    @staticmethod
    def is_safe_url(target: str) -> bool:
        """リダイレクトURLの安全性を確認"""
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc

    @staticmethod
    def is_safe_redirect(target: str) -> bool:
        """リダイレクト先の安全性を確認"""
        if target.startswith('/'):
            return True
        return URLValidator.is_safe_url(target)

class FileUploader:
    """ファイルアップロード処理クラス"""
    def __init__(self):
        self.allowed_extensions = ALLOWED_EXTENSIONS
        self.max_size = MAX_UPLOAD_SIZE
        self.upload_folder = app.config['UPLOAD_FOLDER']

    def allowed_file(self, filename: str) -> bool:
        """ファイル拡張子の確認"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions

    def validate_file(self, file) -> Tuple[bool, str]:
        """ファイルのバリデーション"""
        if not file:
            return False, 'ファイルが選択されていません'
        
        if not self.allowed_file(file.filename):
            return False, '許可されていないファイル形式です'
        
        if len(file.read()) > self.max_size:
            return False, 'ファイルサイズが大きすぎます'
        
        file.seek(0)  # ファイルポインタを先頭に戻す
        return True, ''

    def save_file(self, file, filename: str) -> str:
        """ファイルの保存"""
        secure_name = self._secure_filename(filename)
        file_path = os.path.join(self.upload_folder, secure_name)
        file.save(file_path)
        return secure_name

    def _secure_filename(self, filename: str) -> str:
        """安全なファイル名の生成"""
        # 拡張子の取得
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        # UUIDベースの新しいファイル名を生成
        new_filename = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
        return new_filename

class SecurityUtils:
    """セキュリティユーティリティクラス"""
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """パスワードのバリデーション"""
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f'パスワードは{MIN_PASSWORD_LENGTH}文字以上である必要があります'
        if len(password) > MAX_PASSWORD_LENGTH:
            return False, f'パスワードは{MAX_PASSWORD_LENGTH}文字以下である必要があります'
        if not re.search(r'[A-Z]', password):
            return False, '大文字を含める必要があります'
        if not re.search(r'[a-z]', password):
            return False, '小文字を含める必要があります'
        if not re.search(r'\d', password):
            return False, '数字を含める必要があります'
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, '特殊文字を含める必要があります'
        return True, ''

    @staticmethod
    def validate_email(email: str) -> bool:
        """メールアドレスのバリデーション"""
        return bool(re.match(EMAIL_PATTERN, email))

    @staticmethod
    def generate_csrf_token() -> str:
        """CSRFトークンの生成"""
        if '_csrf_token' not in session:
            session['_csrf_token'] = uuid.uuid4().hex
        return session['_csrf_token']


def login_required(f):
    """ログイン必須のデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' not in session:
            flash('ログインが必要です', 'warning')
            next_url = request.url
            return redirect(url_for('login', next=next_url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """管理者権限必須のデコレータ"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            logger.warning(f"Unauthorized admin access attempt: {session.get('uid')}")
            flash('管理者権限が必要です', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_exceeded_handler(e):
    """レート制限超過時のハンドラ"""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return render_template(
        'errors/429.html',
        retry_after=e.description
    ), 429

def api_rate_limit():
    """APIエンドポイント用のレート制限デコレータ"""
    return limiter.limit("30 per minute")

def upload_rate_limit():
    """ファイルアップロード用のレート制限デコレータ"""
    return limiter.limit("10 per hour")

def rotate_session():
    """セッションIDの定期的な更新"""
    if 'uid' in session and random.random() < 0.1:  # 10%の確率で更新
        session.modified = True
        session.permanent = True
        session['_session_id'] = uuid.uuid4().hex

@app.before_request
def before_request():
    """リクエスト前の共通処理"""
    # HTTPSリダイレクト
    if not request.is_secure and not app.debug:
        if request.url.startswith('http://'):
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

    # セッション設定
    session.permanent = True
    
    # CSRFトークンの確認
    if request.method in ['POST', 'PUT', 'DELETE']:
        token = session.get('_csrf_token')
        if not token or token != request.form.get('_csrf_token'):
            logger.warning(f'CSRF token validation failed: {request.url}')
            abort(403)

    # セッションのアクティビティチェック
    if 'last_active' in session:
        last_active = datetime.fromtimestamp(session['last_active'])
        if datetime.now() - last_active > timedelta(hours=12):
            session.clear()
            flash('セッションの有効期限が切れました。再度ログインしてください。', 'warning')
            return redirect(url_for('login'))

    session['last_active'] = datetime.now().timestamp()
    
    # セッションIDのローテーション
    rotate_session()

@app.after_request
def after_request(response):
    """レスポンス送信前の共通処理"""
    # セキュリティヘッダーの適用
    response = SecurityHeaders.apply(response)
    
    # HSTS設定（本番環境のみ）
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    return response

def handle_error_response(error_message: str, status_code: int = 400) -> Tuple[dict, int]:
    """エラーレスポンスの生成"""
    response = {
        'error': {
            'message': error_message,
            'status_code': status_code,
            'timestamp': datetime.utcnow().isoformat()
        }
    }
    return response, status_code

def create_success_response(data: Any, message: str = 'Success') -> Tuple[dict, int]:
    """成功レスポンスの生成"""
    response = {
        'data': data,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }
    return response, 200

@app.template_filter('datetime_format')
def datetime_format(value, format='%Y-%m-%d %H:%M:%S'):
    """日時フォーマット用のテンプレートフィルター"""
    if value is None:
        return ''
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

@app.context_processor
def utility_processor():
    """テンプレート用のユーティリティ関数"""
    def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
        return datetime_format(value, format)

    def is_admin():
        return session.get('is_admin', False)

    return dict(
        format_datetime=format_datetime,
        is_admin=is_admin,
        csrf_token=SecurityUtils.generate_csrf_token
    )

# 認証関連のルート
@app.route('/signup')
def signup():
    """サインアップページの表示"""
    if 'uid' in session:
        return redirect(url_for('index'))
    return render_template('registration/signup.html')

@app.route('/signup', methods=['POST'])
@limiter.limit("5 per minute")
def user_signup():
    """ユーザー登録処理"""
    try:
        # フォームデータのサニタイズと取得
        name = XSSProtection.sanitize_input(request.form.get('name', '').strip())
        email = request.form.get('email', '').strip().lower()
        password1 = request.form.get('password1', '')
        password2 = request.form.get('password2', '')

        # 入力値の検証
        if not all([name, email, password1, password2]):
            flash('全ての項目を入力してください', 'error')
            return redirect(url_for('signup'))

        if password1 != password2:
            flash('パスワードが一致しません', 'error')
            return redirect(url_for('signup'))

        if not SecurityUtils.validate_email(email):
            flash('有効なメールアドレスを入力してください', 'error')
            return redirect(url_for('signup'))

        is_valid, message = SecurityUtils.validate_password(password1)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('signup'))

        # ユーザー作成
        uid = str(uuid.uuid4())
        user_model.create(name, email, password1)
        
        # セッション設定
        session.clear()
        session['uid'] = uid
        session['user_name'] = name
        session['is_admin'] = False
        session['_session_id'] = uuid.uuid4().hex
        session.permanent = True
        
        logger.info(f"New user registered: {email}")
        flash('アカウントが作成されました', 'success')
        return redirect(url_for('index'))

    except UniqueConstraintError:
        flash('このメールアドレスは既に登録されています', 'error')
        return redirect(url_for('signup'))
    except DatabaseError as e:
        logger.error(f"Database error during signup: {str(e)}")
        flash('アカウント作成中にエラーが発生しました', 'error')
        return redirect(url_for('signup'))
    except Exception as e:
        logger.error(f"Unexpected error during signup: {str(e)}")
        flash('予期せぬエラーが発生しました', 'error')
        return redirect(url_for('signup'))

@app.route('/login')
def login():
    """ログインページの表示"""
    if 'uid' in session:
        return redirect(url_for('index'))
    return render_template('registration/login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def user_login():
    """ログイン処理"""
    try:
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        next_url = request.form.get('next', '')

        if not email or not password:
            flash('メールアドレスとパスワードを入力してください', 'error')
            return redirect(url_for('login'))

        # ログイン試行回数のチェック
        login_attempts = session.get('login_attempts', 0)
        last_attempt = session.get('last_attempt', 0)
        
        if login_attempts >= MAX_LOGIN_ATTEMPTS:
            if time.time() - last_attempt < LOGIN_TIMEOUT:
                flash(f'ログイン試行回数が上限を超えました。{LOGIN_TIMEOUT}秒後に再試行してください', 'error')
                return redirect(url_for('login'))
            session['login_attempts'] = 0

        user = user_model.get_by_email(email)
        if not user:
            session['login_attempts'] = login_attempts + 1
            session['last_attempt'] = time.time()
            logger.warning(f"Failed login attempt: User not found - {email}")
            flash('メールアドレスまたはパスワードが正しくありません', 'error')
            return redirect(url_for('login'))

        if not user.get('is_active', True):
            logger.warning(f"Login attempt for inactive account: {email}")
            flash('このアカウントは現在無効になっています', 'error')
            return redirect(url_for('login'))

        # パスワードの検証
        hashed_password = user_model._hash_password(password)
        if hashed_password != user['password']:
            session['login_attempts'] = login_attempts + 1
            session['last_attempt'] = time.time()
            logger.warning(f"Failed login attempt: Invalid password - {email}")
            flash('メールアドレスまたはパスワードが正しくありません', 'error')
            return redirect(url_for('login'))

        # ログイン成功
        session.clear()
        session['uid'] = user['uid']
        session['user_name'] = user['user_name']
        session['is_admin'] = user.get('is_admin', False)
        session['_session_id'] = uuid.uuid4().hex
        session.permanent = True

        logger.info(f"User logged in successfully: {email}")
        flash('ログインしました', 'success')

        # 安全な次のURLへリダイレクト
        if next_url and URLValidator.is_safe_redirect(next_url):
            return redirect(next_url)
        return redirect(url_for('index'))

    except DatabaseError as e:
        logger.error(f"Database error during login: {str(e)}")
        flash('ログイン処理中にエラーが発生しました', 'error')
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        flash('予期せぬエラーが発生しました', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """ログアウト処理"""
    if 'uid' in session:
        logger.info(f"User logged out: {session.get('user_name')}")
    session.clear()
    flash('ログアウトしました', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """チャンネル一覧の表示"""
    try:
        channels = channel_model.get_all()
        return render_template(
            'index.html',
            channels=channels,
            uid=session['uid']
        )
    except DatabaseError as e:
        logger.error(f"Error fetching channels: {str(e)}")
        flash('チャンネル一覧の取得中にエラーが発生しました', 'error')
        return render_template('index.html', channels=[], uid=session['uid'])

@app.route('/channels/create', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def create_channel():
    """チャンネルの作成"""
    try:
        # 入力値のサニタイズと取得
        name = XSSProtection.sanitize_input(request.form.get('channelTitle', '').strip())
        description = XSSProtection.sanitize_input(request.form.get('channelDescription', '').strip())

        # バリデーション
        if not name:
            flash('チャンネル名を入力してください', 'error')
            return redirect(url_for('index'))

        if len(name) > MAX_CHANNEL_NAME_LENGTH:
            flash(f'チャンネル名は{MAX_CHANNEL_NAME_LENGTH}文字以内で入力してください', 'error')
            return redirect(url_for('index'))

        if len(description) > MAX_CHANNEL_DESCRIPTION_LENGTH:
            flash(f'説明は{MAX_CHANNEL_DESCRIPTION_LENGTH}文字以内で入力してください', 'error')
            return redirect(url_for('index'))

        # チャンネルの作成
        channel_id = channel_model.create(session['uid'], name, description)
        logger.info(f"Channel created: {name} by {session['user_name']}")
        flash('チャンネルを作成しました', 'success')
        return redirect(url_for('channel_detail', channel_id=channel_id))

    except UniqueConstraintError:
        flash('同じ名前のチャンネルが既に存在します', 'error')
        return redirect(url_for('index'))
    except DatabaseError as e:
        logger.error(f"Channel creation error: {str(e)}")
        flash('チャンネルの作成中にエラーが発生しました', 'error')
        return redirect(url_for('index'))

@app.route('/channels/<int:channel_id>')
@login_required
def channel_detail(channel_id: int):
    """チャンネル詳細の表示"""
    try:
        channel = channel_model.get_by_id(channel_id)
        if not channel:
            flash('チャンネルが見つかりません', 'error')
            return redirect(url_for('index'))

        messages = message_model.get_by_channel(channel_id)
        return render_template(
            'detail.html',
            messages=messages,
            channel=channel,
            uid=session['uid'],
            is_owner=channel['uid'] == session['uid']
        )
    except DatabaseError as e:
        logger.error(f"Error fetching channel details: {str(e)}")
        flash('チャンネル詳細の取得中にエラーが発生しました', 'error')
        return redirect(url_for('index'))

@app.route('/channels/<int:channel_id>/update', methods=['POST'])
@login_required
def update_channel(channel_id: int):
    """チャンネルの更新"""
    try:
        # 権限チェック
        channel = channel_model.get_by_id(channel_id)
        if not channel or (channel['uid'] != session['uid'] and not session.get('is_admin')):
            flash('チャンネルの更新権限がありません', 'error')
            return redirect(url_for('index'))

        # 入力値のサニタイズと取得
        name = XSSProtection.sanitize_input(request.form.get('channelTitle', '').strip())
        description = XSSProtection.sanitize_input(request.form.get('channelDescription', '').strip())

        # バリデーション
        if not name:
            flash('チャンネル名を入力してください', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        if len(name) > MAX_CHANNEL_NAME_LENGTH:
            flash(f'チャンネル名は{MAX_CHANNEL_NAME_LENGTH}文字以内で入力してください', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        if len(description) > MAX_CHANNEL_DESCRIPTION_LENGTH:
            flash(f'説明は{MAX_CHANNEL_DESCRIPTION_LENGTH}文字以内で入力してください', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        # チャンネルの更新
        channel_model.update(channel_id, session['uid'], name, description)
        logger.info(f"Channel updated: {channel_id} by {session['user_name']}")
        flash('チャンネルを更新しました', 'success')
        return redirect(url_for('channel_detail', channel_id=channel_id))

    except UniqueConstraintError:
        flash('同じ名前のチャンネルが既に存在します', 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))
    except DatabaseError as e:
        logger.error(f"Channel update error: {str(e)}")
        flash('チャンネルの更新中にエラーが発生しました', 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))

@app.route('/channels/<int:channel_id>/delete', methods=['POST'])
@login_required
def delete_channel(channel_id: int):
    """チャンネルの削除"""
    try:
        # 権限チェック
        channel = channel_model.get_by_id(channel_id)
        if not channel or (channel['uid'] != session['uid'] and not session.get('is_admin')):
            flash('チャンネルの削除権限がありません', 'error')
            return redirect(url_for('index'))

        # チャンネルの削除
        channel_model.delete(channel_id, session['uid'])
        logger.info(f"Channel deleted: {channel_id} by {session['user_name']}")
        flash('チャンネルを削除しました', 'success')
        return redirect(url_for('index'))

    except DatabaseError as e:
        logger.error(f"Channel deletion error: {str(e)}")
        flash('チャンネルの削除中にエラーが発生しました', 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))

@app.route('/channels/<int:channel_id>/messages', methods=['POST'])
@login_required
@limiter.limit("60 per minute")
def create_message(channel_id: int):
    """メッセージの作成"""
    try:
        # 入力値のサニタイズと取得
        content = XSSProtection.sanitize_input(request.form.get('message', '').strip())
        
        # バリデーション
        if not content:
            flash('メッセージを入力してください', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        if len(content) > MAX_MESSAGE_LENGTH:
            flash(f'メッセージは{MAX_MESSAGE_LENGTH}文字以内で入力してください', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        # メッセージの作成
        message_model.create(session['uid'], channel_id, content)
        logger.info(f"Message created in channel {channel_id} by {session['user_name']}")
        return redirect(url_for('channel_detail', channel_id=channel_id))

    except ValidationError as e:
        flash(str(e), 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))
    except DatabaseError as e:
        logger.error(f"Message creation error: {str(e)}")
        flash('メッセージの投稿中にエラーが発生しました', 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))

@app.route('/messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id: int):
    """メッセージの削除"""
    try:
        # メッセージの取得と権限チェック
        message = message_model.get_by_id(message_id)
        if not message:
            flash('メッセージが見つかりません', 'error')
            return redirect(url_for('index'))

        if message['uid'] != session['uid'] and not session.get('is_admin'):
            flash('メッセージの削除権限がありません', 'error')
            return redirect(url_for('channel_detail', channel_id=message['channel_id']))

        # メッセージの削除
        message_model.delete(message_id, session['uid'])
        logger.info(f"Message deleted: {message_id} by {session['user_name']}")
        flash('メッセージを削除しました', 'success')
        return redirect(url_for('channel_detail', channel_id=message['channel_id']))

    except DatabaseError as e:
        logger.error(f"Message deletion error: {str(e)}")
        flash('メッセージの削除中にエラーが発生しました', 'error')
        return redirect(url_for('channel_detail', channel_id=message['channel_id']))

@app.route('/channels/<int:channel_id>/upload', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def upload_file(channel_id: int):
    """ファイルアップロード処理"""
    try:
        if 'file' not in request.files:
            flash('ファイルが選択されていません', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        file = request.files['file']
        if not file.filename:
            flash('ファイルが選択されていません', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        # ファイルアップロードの処理
        uploader = FileUploader()
        
        # ファイルのバリデーション
        is_valid, message = uploader.validate_file(file)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        # ファイルの保存
        try:
            filename = uploader.save_file(file, file.filename)
        except Exception as e:
            logger.error(f"File save error: {str(e)}")
            flash('ファイルの保存中にエラーが発生しました', 'error')
            return redirect(url_for('channel_detail', channel_id=channel_id))

        # ファイル情報をデータベースに保存
        file_url = url_for('uploaded_file', filename=filename, _external=True)
        message_model.create_with_file(
            session['uid'],
            channel_id,
            f'ファイルを共有しました: {filename}',
            file_url
        )
        
        logger.info(f"File uploaded: {filename} by {session['user_name']}")
        flash('ファイルがアップロードされました', 'success')
        return redirect(url_for('channel_detail', channel_id=channel_id))

    except DatabaseError as e:
        logger.error(f"Database error during file upload: {str(e)}")
        flash('ファイル情報の保存中にエラーが発生しました', 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))
    except Exception as e:
        logger.error(f"Unexpected error during file upload: {str(e)}")
        flash('ファイルのアップロード中にエラーが発生しました', 'error')
        return redirect(url_for('channel_detail', channel_id=channel_id))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """アップロードされたファイルの提供"""
    try:
        # ファイル名の検証
        if not re.match(r'^[a-f0-9]{32}\.[a-zA-Z0-9]+$', filename):
            abort(404)

        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        logger.error(f"File download error: {str(e)}")
        abort(404)


# エラーハンドラ
@app.errorhandler(400)
def bad_request_error(error):
    """400エラーのハンドラ"""
    logger.error(f"400 error: {request.url}")
    if request.is_xhr:
        return jsonify(error='不正なリクエストです'), 400
    return render_template('errors/400.html'), 400

@app.errorhandler(403)
def forbidden_error(error):
    """403エラーのハンドラ"""
    logger.error(f"403 error: {request.url}")
    if request.is_xhr:
        return jsonify(error='アクセス権限がありません'), 403
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    """404エラーのハンドラ"""
    logger.error(f"404 error: {request.url}")
    if request.is_xhr:
        return jsonify(error='ページが見つかりません'), 404
    return render_template('errors/404.html'), 404

@app.errorhandler(413)
def request_entity_too_large_error(error):
    """413エラーのハンドラ"""
    logger.error(f"413 error: {request.url}")
    if request.is_xhr:
        return jsonify(error='ファイルサイズが大きすぎます'), 413
    return render_template('errors/413.html'), 413

@app.errorhandler(429)
def too_many_requests_error(error):
    """429エラーのハンドラ"""
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    if request.is_xhr:
        return jsonify(error='リクエスト回数が制限を超えました'), 429
    return render_template(
        'errors/429.html',
        retry_after=error.description
    ), 429

@app.errorhandler(500)
def internal_error(error):
    """500エラーのハンドラ"""
    logger.error(f"500 error: {str(error)}")
    if request.is_xhr:
        return jsonify(error='内部サーバーエラーが発生しました'), 500
    return render_template('errors/500.html'), 500

@app.errorhandler(DatabaseError)
def handle_database_error(error):
    """データベースエラーのハンドラ"""
    logger.error(f"Database error: {str(error)}")
    if request.is_xhr:
        return jsonify(error='データベースエラーが発生しました'), 500
    flash('データベース操作中にエラーが発生しました', 'error')
    return redirect(url_for('index'))

@app.errorhandler(ValidationError)
def handle_validation_error(error):
    """バリデーションエラーのハンドラ"""
    logger.warning(f"Validation error: {str(error)}")
    if request.is_xhr:
        return jsonify(error=str(error)), 400
    flash(str(error), 'error')
    return redirect(request.referrer or url_for('index'))

# ヘルスチェックエンドポイント
@app.route('/health')
def health_check():
    """ヘルスチェックエンドポイント"""
    try:
        # データベース接続確認
        user_model.get_count()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'environment': os.getenv('FLASK_ENV', 'production')
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# 開発環境用の設定
if app.debug:
    @app.route('/debug/errors')
    @admin_required
    def test_errors():
        """各種エラーページのテスト用エンドポイント"""
        return render_template('debug/error_test.html')

# アプリケーション起動
if __name__ == '__main__':
    # 必要なディレクトリの作成
    for directory in ['logs', app.config['UPLOAD_FOLDER']]:
        os.makedirs(directory, exist_ok=True)
    
    # 環境変数から設定を読み込み
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    # SSL設定
    ssl_context = None
    if not debug_mode:
        cert_path = os.getenv('SSL_CERT_PATH')
        key_path = os.getenv('SSL_KEY_PATH')
        if cert_path and key_path:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                ssl_context = (cert_path, key_path)
            else:
                logger.warning("SSL certificate files not found, using 'adhoc' certificates")
                ssl_context = 'adhoc'
        else:
            logger.warning("SSL paths not configured, using 'adhoc' certificates")
            ssl_context = 'adhoc'

    # アプリケーション起動前の最終チェック
    if not app.debug:
        assert app.secret_key != uuid.uuid4().hex, "本番環境では固定のシークレットキーを使用してください"
        assert app.config['SESSION_COOKIE_SECURE'], "本番環境ではセキュアクッキーを有効にしてください"
    
    # アプリケーション起動
    app.run(
        host=host,
        port=port,
        debug=debug_mode,
        ssl_context=ssl_context
    )

    app.run(host="0.0.0.0")
