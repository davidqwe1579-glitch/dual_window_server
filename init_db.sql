CREATE DATABASE IF NOT EXISTS dual_windows;
USE dual_windows;

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(255) PRIMARY KEY,
    is_login TINYINT(1) DEFAULT 0,
    expiry_date DATETIME NOT NULL,
    last_heartbeat DATETIME DEFAULT NOW()
);

-- 테스트용 데이터
INSERT INTO users (user_id, is_login, expiry_date, last_heartbeat) 
VALUES ('test_user', 0, '2026-12-31 23:59:59', NOW())
ON DUPLICATE KEY UPDATE 
    expiry_date = '2026-12-31 23:59:59',
    last_heartbeat = NOW();
