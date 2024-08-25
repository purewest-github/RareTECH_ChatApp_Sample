-- データベースとユーザーが存在する場合のみ削除
DROP DATABASE IF EXISTS chatapp;
DROP USER IF EXISTS 'admin'@'%';

-- ユーザーの作成
CREATE USER 'admin'@'%' IDENTIFIED BY 'prodpassword';

-- データベースの作成
CREATE DATABASE chatapp;

-- データベースの選択
USE chatapp;

-- ユーザーに権限を付与
GRANT ALL PRIVILEGES ON chatapp.* TO 'admin'@'%';

-- テーブルの作成
CREATE TABLE users (
    uid VARCHAR(255) PRIMARY KEY,
    user_name VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE channels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uid VARCHAR(255),
    name VARCHAR(255) UNIQUE NOT NULL,
    abstract VARCHAR(255),
    FOREIGN KEY (uid) REFERENCES users(uid)
);

CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    uid VARCHAR(255),
    cid INT,
    message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uid) REFERENCES users(uid),
    FOREIGN KEY (cid) REFERENCES channels(id) ON DELETE CASCADE
);

-- サンプルデータの挿入
INSERT INTO users (uid, user_name, email, password) 
VALUES ('970af84c-dd40-47ff-af23-282b72b7cca8', 'テスト', 'test@gmail.com', '37268335dd6931045bdcdf92623ff819a64244b53d0e746d438797349d4da578');

INSERT INTO channels (id, uid, name, abstract) 
VALUES (1, '970af84c-dd40-47ff-af23-282b72b7cca8', 'ぼっち部屋', 'テストさんの孤独な部屋です');

INSERT INTO messages (id, uid, cid, message) 
VALUES (1, '970af84c-dd40-47ff-af23-282b72b7cca8', 1, '誰かかまってください、、');

-- 変更を確定
FLUSH PRIVILEGES;