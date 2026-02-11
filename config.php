<?php
/**
 * SMV Security - WAF System Configuration
 * Local WAF installation on customer server
 */

// ============================================================
// 1. DATABASE CONFIGURATION (LOCAL)
// ============================================================

define('DB_HOST', 'localhost');
define('DB_USER', 'hidden_for_security_purposes');
define('DB_PASS', 'hidden_for_security_purposes');
define('DB_NAME', 'hidden_for_security_purposes');
define('DB_CHARSET', 'utf8mb4');
 
// ============================================================
// 2. APPLICATION SETTINGS
// ============================================================

define('APP_NAME', 'SMV Security WAF');
define('APP_VERSION', '1.0.0');
define('ENVIRONMENT', 'production'); // development, staging, production

// Timezone
define('TIMEZONE', 'Africa/Nairobi');
date_default_timezone_set(TIMEZONE);

// ============================================================
// 3. WAF SETTINGS
// ============================================================

// Enable/disable WAF
define('WAF_ENABLED', true);

// Threat detection
define('THREAT_DETECTION_ENABLED', true);
define('AUTO_BLOCK_ENABLED', true);

// Log files to monitor
define('LOG_FILES', [
    '/var/log/apache2/access.log',      // Apache
    '/var/log/nginx/access.log',        // Nginx
    '/var/log/httpd/access_log',        // cPanel/WHM Apache
]);

// ============================================================
// 4. DAEMON SETTINGS
// ============================================================

// Daemon interval (minutes)
define('DAEMON_INTERVAL', 5);

// Daemon timeout (seconds)
define('DAEMON_TIMEOUT', 30);

// Log scanning
define('LOG_SCAN_BATCH_SIZE', 1000);
define('LOG_SCAN_MAX_SIZE_MB', 100);

// ============================================================
// 5. THREAT DETECTION RULES
// ============================================================

// Auto-block dangerous IPs
define('AUTO_BLOCK_CRITICAL', true);
define('AUTO_BLOCK_CRITICAL_AFTER', 2); // Block after 2 critical threats

// Rate limiting
define('RATE_LIMIT_ENABLED', true);
define('RATE_LIMIT_REQUESTS', 100);
define('RATE_LIMIT_WINDOW', 60); // seconds

// DDoS detection
define('DDOS_DETECTION_ENABLED', true);
define('DDOS_THRESHOLD_REQUESTS', 1000); // requests per minute

// ============================================================
// 6. CONTROL CENTER CONNECTION
// ============================================================

// Control center URL
define('CONTROL_CENTER_URL', 'http://localhost/scolemax-control-center');

// API endpoints
define('CONTROL_CENTER_REPORT_ENDPOINT', '/integrations/waf.php');
define('CONTROL_CENTER_FEED_ENDPOINT', '/integrations/waf.php?action=threat_feed');

// Connection timeout
define('API_TIMEOUT', 15);

// API credentials (set during installation)
define('API_KEY', '');
define('API_SECRET', '');

// ============================================================
// 7. BLOCKING METHODS
// ============================================================

// Supported blocking methods
define('BLOCKING_METHODS', [
    'htaccess' => true,      // Using .htaccess (Apache)
    'nginx_rules' => false,  // Using Nginx rules
    'iptables' => false,     // Using iptables
]);

// .htaccess file location
define('HTACCESS_FILE', __DIR__ . '/../.htaccess.smv');

// ============================================================
// 8. FILE LOCATIONS
// ============================================================

// Working directories
define('BASE_DIR', __DIR__ . '/..');
define('LOG_DIR', BASE_DIR . '/logs/');
define('CACHE_DIR', BASE_DIR . '/cache/');
define('RULES_DIR', BASE_DIR . '/rules/');
define('BACKUP_DIR', BASE_DIR . '/backups/');

// Ensure directories exist
foreach ([LOG_DIR, CACHE_DIR, RULES_DIR, BACKUP_DIR] as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
}

// Log files
define('APP_LOG', LOG_DIR . 'waf.log');
define('ERROR_LOG', LOG_DIR . 'errors.log');
define('THREAT_LOG', LOG_DIR . 'threats.log');
define('DAEMON_LOG', LOG_DIR . 'daemon.log');
define('SYNC_LOG', LOG_DIR . 'sync.log');

// ============================================================
// 9. SECURITY SETTINGS
// ============================================================

// Log level: debug, info, warning, error
define('LOG_LEVEL', 'info');

// Maximum log file size (MB) before rotation
define('MAX_LOG_SIZE_MB', 10);

// Threat retention (days)
define('THREAT_RETENTION_DAYS', 30);

// IP block retention (days)
define('BLOCK_RETENTION_DAYS', 7); // Temporary blocks

// ============================================================
// 10. DASHBOARD SETTINGS (if webui enabled)
// ============================================================

// Web UI enabled
define('WEBUI_ENABLED', true);

// Web UI port/path
define('WEBUI_PATH', '/webui/');

// Session timeout (minutes)
define('SESSION_TIMEOUT', 30);

// ============================================================
// 11. DATABASE CONNECTION CLASS
// ============================================================

class Database {
    private $connection;
    private static $instance = null;

    private function __construct() {
        try {
            $this->connection = new mysqli(
                DB_HOST,
                DB_USER,
                DB_PASS,
                DB_NAME
            );

            if (!$this->connection->set_charset(DB_CHARSET)) {
                throw new Exception("Error setting charset: " . $this->connection->error);
            }

            if ($this->connection->connect_error) {
                throw new Exception("Database connection failed: " . $this->connection->connect_error);
            }
        } catch (Exception $e) {
            $this->handleError($e->getMessage());
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->connection;
    }

    public function prepare($query) {
        return $this->connection->prepare($query);
    }

    public function query($query) {
        return $this->connection->query($query);
    }

    public function close() {
        if ($this->connection) {
            $this->connection->close();
        }
    }

    private function handleError($message) {
        if (ENVIRONMENT === 'production') {
            error_log($message, 3, ERROR_LOG);
            die('Database connection error.');
        } else {
            die('Database Error: ' . $message);
        }
    }

    public function getError() {
        return $this->connection->error;
    }

    public function getLastInsertId() {
        return $this->connection->insert_id;
    }

    public function __destruct() {
        $this->close();
    }
}

// ============================================================
// 12. HELPER FUNCTIONS
// ============================================================

/**
 * Get database instance
 */
function getDB() {
    return Database::getInstance()->getConnection();
}

/**
 * Log message to file
 */
function logMessage($message, $type = 'info') {
    $log_file = ($type === 'error') ? ERROR_LOG : APP_LOG;
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] [$type] $message\n";
    error_log($log_entry, 3, $log_file);
}

/**
 * Log threat
 */
function logThreat($threat_type, $severity, $source_ip, $details = '') {
    $threat_log = THREAT_LOG;
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] Threat: $threat_type | Severity: $severity | IP: $source_ip | $details\n";
    error_log($log_entry, 3, $threat_log);
}

/**
 * Sanitize input
 */
function sanitize($input) {
    return htmlspecialchars(stripslashes(trim($input)), ENT_QUOTES, 'UTF-8');
}

/**
 * Hash IP address
 */
function hashIP($ip) {
    return hash('sha256', $ip);
}

/**
 * Check if IP is in CIDR range
 */
function ipInRange($ip, $range) {
    if (strpos($range, '/') === false) {
        return $ip === $range;
    }
    
    list($subnet, $bits) = explode('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) === $subnet;
}

/**
 * Get client IP
 */
function getClientIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } else {
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }
}

/**
 * Send JSON response
 */
function jsonResponse($data, $status = 200) {
    header('Content-Type: application/json');
    http_response_code($status);
    echo json_encode($data);
    exit;
}

/**
 * Log API request
 */
function logAPIRequest($endpoint, $method, $success, $response_time = 0, $error = '') {
    $sync_log = SYNC_LOG;
    $timestamp = date('Y-m-d H:i:s');
    $status = $success ? 'SUCCESS' : 'FAILED';
    $log_entry = "[$timestamp] $method $endpoint - $status ({$response_time}ms)";
    if ($error) {
        $log_entry .= " - Error: $error";
    }
    $log_entry .= "\n";
    error_log($log_entry, 3, $sync_log);
}

/**
 * Get config value from database
 */
function getConfig($key, $default = '') {
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT config_value FROM config WHERE config_key = ? LIMIT 1");
        $stmt->bind_param("s", $key);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        return $row ? $row['config_value'] : $default;
    } catch (Exception $e) {
        return $default;
    }
}

/**
 * Set config value in database
 */
function setConfig($key, $value) {
    try {
        $db = getDB();
        $stmt = $db->prepare(
            "INSERT INTO config (config_key, config_value) VALUES (?, ?) 
            ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)"
        );
        $stmt->bind_param("ss", $key, $value);
        return $stmt->execute();
    } catch (Exception $e) {
        return false;
    }
}

// ============================================================
// 13. ERROR HANDLING
// ============================================================

if (ENVIRONMENT === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', ERROR_LOG);
}

set_error_handler(function($errno, $errstr, $errfile, $errline) {
    $error_message = "[" . date('Y-m-d H:i:s') . "] Error: $errstr in $errfile:$errline";
    error_log($error_message . "\n", 3, ERROR_LOG);
    
    if (ENVIRONMENT === 'development') {
        echo "<pre>$error_message</pre>";
    }
});

// ============================================================
// END OF CONFIGURATION
// ============================================================

?>
