-- ============================================================
-- SMV Security - WAF System Database Schema
-- Database: smv_waf_local (installed on customer servers)
-- Version: 1.0
-- Created: February 2026
-- ============================================================

CREATE DATABASE IF NOT EXISTS smv_waf_local
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE smv_waf_local;

-- ============================================================
-- TABLE 1: CONFIGURATION
-- ============================================================
CREATE TABLE IF NOT EXISTS config (
    id INT PRIMARY KEY AUTO_INCREMENT,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value LONGTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_key (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 2: LOCAL THREATS DETECTED
-- ============================================================
CREATE TABLE IF NOT EXISTS local_threats (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    source_ip_hash VARCHAR(64),
    target_path VARCHAR(500),
    target_service VARCHAR(100),
    attack_pattern TEXT,
    payload_hash VARCHAR(64),
    request_method VARCHAR(10),
    user_agent TEXT,
    
    -- Action taken
    action_taken VARCHAR(50) DEFAULT 'logged',
    block_method VARCHAR(100),
    
    -- Status
    reported_to_control TINYINT(1) DEFAULT 0,
    reported_at TIMESTAMP NULL,
    
    -- Timestamps
    detected_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_threat_type (threat_type),
    INDEX idx_severity (severity),
    INDEX idx_source_ip (source_ip),
    INDEX idx_detected_at (detected_at),
    INDEX idx_reported (reported_to_control)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 3: FIREWALL RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(50), -- ip_block, pattern_block, rate_limit, geo_block
    
    -- Rule conditions
    match_ip VARCHAR(45),
    match_pattern TEXT,
    match_domain VARCHAR(255),
    
    -- Actions
    action VARCHAR(50), -- block, log, challenge, rate_limit
    action_value VARCHAR(255),
    
    -- Source
    source VARCHAR(50), -- local, control_center, manual
    source_id INT, -- threat_id if from threat
    
    -- Status
    is_active TINYINT(1) DEFAULT 1,
    priority INT DEFAULT 100,
    
    -- Hit count
    hit_count INT DEFAULT 0,
    last_hit TIMESTAMP NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_type (rule_type),
    INDEX idx_active (is_active),
    INDEX idx_priority (priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 4: BLOCKED IPS
-- ============================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    threat_type VARCHAR(100),
    
    -- Block details
    block_type VARCHAR(50), -- permanent, temporary
    blocked_at DATETIME NOT NULL,
    expires_at DATETIME NULL,
    
    -- Hit tracking
    block_hit_count INT DEFAULT 1,
    last_attempt TIMESTAMP NULL,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_ip (ip_address),
    INDEX idx_expires (expires_at),
    INDEX idx_type (block_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 5: DETECTED ATTACK PATTERNS
-- ============================================================
CREATE TABLE IF NOT EXISTS attack_patterns (
    id INT PRIMARY KEY AUTO_INCREMENT,
    pattern_name VARCHAR(255) NOT NULL,
    pattern_type VARCHAR(100), -- sql_injection, xss, brute_force, etc
    pattern_regex TEXT,
    
    -- Detection
    detection_method VARCHAR(100),
    severity VARCHAR(20),
    
    -- Status
    is_active TINYINT(1) DEFAULT 1,
    hit_count INT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_type (pattern_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 6: DAEMON LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS daemon_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    
    -- Execution info
    execution_time DATETIME NOT NULL,
    execution_duration_ms INT,
    
    -- Statistics
    logs_scanned INT DEFAULT 0,
    threats_detected INT DEFAULT 0,
    rules_applied INT DEFAULT 0,
    
    -- Status
    status VARCHAR(50), -- success, error, partial
    error_message TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_execution_time (execution_time),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 7: SYSTEM STATISTICS
-- ============================================================
CREATE TABLE IF NOT EXISTS statistics (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Time period
    period_date DATE NOT NULL,
    period_type VARCHAR(50), -- hourly, daily, weekly
    
    -- Counts
    total_requests INT DEFAULT 0,
    blocked_requests INT DEFAULT 0,
    threats_detected INT DEFAULT 0,
    
    -- By severity
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    
    -- By type
    sql_injection INT DEFAULT 0,
    brute_force INT DEFAULT 0,
    ddos INT DEFAULT 0,
    xss INT DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_period (period_date, period_type),
    INDEX idx_date (period_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 8: CONTROL CENTER SYNC LOG
-- ============================================================
CREATE TABLE IF NOT EXISTS sync_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Sync info
    sync_type VARCHAR(50), -- threat_report, rule_update, config_fetch
    sync_direction VARCHAR(50), -- send, receive
    
    -- Data
    data_records INT DEFAULT 0,
    success TINYINT(1) DEFAULT 1,
    error_message TEXT,
    
    -- Control center response
    response_code INT,
    response_time_ms INT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_type (sync_type),
    INDEX idx_success (success),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 9: THREAT FEED CACHE
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_feed_cache (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Threat info
    source_ip_hash VARCHAR(64) NOT NULL,
    threat_type VARCHAR(100),
    severity VARCHAR(20),
    source_country VARCHAR(100),
    
    -- Network info
    report_count INT DEFAULT 1,
    last_seen TIMESTAMP NULL,
    
    -- Action
    should_block TINYINT(1) DEFAULT 0,
    block_method VARCHAR(50),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_ip_hash (source_ip_hash),
    INDEX idx_threat_type (threat_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE 10: INSTALLATION INFO
-- ============================================================
CREATE TABLE IF NOT EXISTS installation (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Installation details
    installed_at DATETIME NOT NULL,
    installation_version VARCHAR(20),
    
    -- System info
    php_version VARCHAR(20),
    server_type VARCHAR(100),
    os_info VARCHAR(255),
    
    -- Daemon info
    daemon_enabled TINYINT(1) DEFAULT 0,
    last_daemon_run TIMESTAMP NULL,
    daemon_schedule VARCHAR(100),
    
    -- Control center connection
    control_center_url VARCHAR(255),
    api_key_set TINYINT(1) DEFAULT 0,
    first_sync TIMESTAMP NULL,
    
    -- Status
    is_active TINYINT(1) DEFAULT 1,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Sample Configuration Data
-- ============================================================

INSERT INTO config (config_key, config_value) VALUES
('control_center_url', 'http://localhost/scolemax-control-center'),
('api_key', ''),
('api_secret', ''),
('waf_enabled', '1'),
('threat_detection_enabled', '1'),
('auto_block_enabled', '1'),
('log_file_path', '/var/log/apache2/access.log'),
('daemon_interval_minutes', '5'),
('daemon_enabled', '0'),
('last_sync', ''),
('installation_date', DATE(NOW()));

-- ============================================================
-- Installation Record
-- ============================================================

INSERT INTO installation (installed_at, installation_version, daemon_enabled, is_active) VALUES
(NOW(), '1.0.0', 0, 1);

-- ============================================================
-- Default Attack Patterns
-- ============================================================

INSERT INTO attack_patterns (pattern_name, pattern_type, pattern_regex, detection_method, severity, is_active) VALUES
('SQL Injection - UNION', 'sql_injection', 'union.*select', 'regex', 'high', 1),
('SQL Injection - OR', 'sql_injection', "or\\s+['\"]?\\d+['\"]?\\s*=", 'regex', 'high', 1),
('XSS - Script Tag', 'xss', '<script[^>]*>', 'regex', 'high', 1),
('XSS - Event Handler', 'xss', 'on\\w+\\s*=', 'regex', 'medium', 1),
('Path Traversal', 'path_traversal', '\\.\\./|\\.\\\\', 'regex', 'high', 1),
('Command Injection', 'command_injection', ';\\s*(cat|ls|pwd|whoami)', 'regex', 'critical', 1);

-- ============================================================
-- END OF SCHEMA
-- ============================================================
