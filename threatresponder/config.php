<?php
/**
 * SMV Security - Control Center Configuration
 * 
 * Core configuration file for the threat response system
 * Database connections, API settings, email, LLAMA integration, etc.
 */

// ============================================================
// 1. DATABASE CONFIGURATION
// ============================================================

define('DB_HOST', 'localhost');
define('DB_USER', '');
define('DB_PASS', '');
define('DB_NAME', '');
define('DB_CHARSET', 'utf8mb4');

// ============================================================
// 2. APPLICATION SETTINGS
// ============================================================

// Base URL
define('BASE_URL', 'https://threatresponder.scolemax.co.ke');
// For production: define('BASE_URL', 'https://smv-security.co.ke');


// Application name
define('APP_NAME', 'SMV Security Control Center');
define('APP_VERSION', '1.0.0');

// Application environment
define('ENVIRONMENT', 'development'); // development, staging, production
// For production: define('ENVIRONMENT', 'production');

// Timezone
define('TIMEZONE', 'Africa/Nairobi');
date_default_timezone_set(TIMEZONE);

// ============================================================
// 3. SECURITY SETTINGS
// ============================================================

// JWT Secret (for API authentication) - CHANGE THIS!
define('JWT_SECRET', 'your-super-secret-jwt-key-change-this-in-production');

// API Key length
define('API_KEY_LENGTH', 64);

// Session timeout (minutes)
define('SESSION_TIMEOUT', 60);

// Password requirements
define('MIN_PASSWORD_LENGTH', 12);
define('REQUIRE_SPECIAL_CHARS', true);

// CORS settings
define('ALLOWED_ORIGINS', [
    'http://localhost',
    'http://localhost:3000',
    'https://smv-security.co.ke',
    // Add your domains here
]);

// ============================================================
// 4. LLAMA AI SETTINGS
// ============================================================

// LLAMA Server connection
define('LLAMA_URL', 'http://localhost:11434');
define('LLAMA_API_ENDPOINT', 'http://localhost:11434/api/generate');
define('LLAMA_MODEL', 'llama2');

// LLAMA timeout (seconds)
define('LLAMA_TIMEOUT', 30);

// LLAMA temperature (0.0 to 1.0) - lower = more deterministic
define('LLAMA_TEMPERATURE', 0.2);

// Enable/disable LLAMA (for fallback)
define('LLAMA_ENABLED', true);

// LLAMA caching (seconds) - cache identical threats for this duration
define('LLAMA_CACHE_TTL', 3600); // 1 hour

// ============================================================
// 5. WAF API SETTINGS
// ============================================================

// WAF endpoint (where WAF systems send threats)
define('WAF_ENDPOINT', '/integrations/waf.php');

// WAF API timeout
define('WAF_API_TIMEOUT', 15);

// Allow unsigned requests from WAF (for testing only!)
define('ALLOW_UNSIGNED_WAF_REQUESTS', false); // Set to true only in development

// ============================================================
// 6. EMAIL SETTINGS
// ============================================================

// Email method: 'smtp' or 'php'
define('EMAIL_METHOD', 'php');

// SMTP settings (if using SMTP)
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USER', 'your-email@gmail.com');
define('SMTP_PASS', 'your-app-password');
define('SMTP_FROM', 'noreply@scolemax.co.ke');
define('SMTP_FROM_NAME', 'SMV Security');

// Email addresses
define('ADMIN_EMAIL', 'admin@scolemax.co.ke');
define('SUPPORT_EMAIL', 'support@scolemax.co.ke');
define('ALERTS_EMAIL', 'alerts@scolemax.co.ke');

// ============================================================
// 7. FILE UPLOAD SETTINGS
// ============================================================

// Upload directory for zip files
define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('ZIP_UPLOAD_DIR', UPLOAD_DIR . 'zips/');

// Ensure directories exist
if (!is_dir(ZIP_UPLOAD_DIR)) {
    mkdir(ZIP_UPLOAD_DIR, 0755, true);
}

// Maximum zip file size (bytes) - 50MB
define('MAX_ZIP_SIZE', 50 * 1024 * 1024);

// ============================================================
// 8. LOGGING SETTINGS
// ============================================================

// Log directory
define('LOG_DIR', __DIR__ . '/../logs/');

// Ensure log directory exists
if (!is_dir(LOG_DIR)) {
    mkdir(LOG_DIR, 0755, true);
}

// Log files
define('LOG_FILE', LOG_DIR . 'application.log');
define('ERROR_LOG_FILE', LOG_DIR . 'errors.log');
define('API_LOG_FILE', LOG_DIR . 'api.log');
define('THREAT_LOG_FILE', LOG_DIR . 'threats.log');

// Log level: 'debug', 'info', 'warning', 'error'
define('LOG_LEVEL', 'info');

// ============================================================
// 9. API TOKEN SETTINGS
// ============================================================

// Download token validity (hours)
define('DOWNLOAD_TOKEN_VALIDITY', 48);

// API key validity (days) - null for no expiration
define('API_KEY_VALIDITY_DAYS', null);

// Rate limiting (requests per minute per API key)
define('RATE_LIMIT_REQUESTS', 100);
define('RATE_LIMIT_WINDOW', 60); // seconds

// ============================================================
// 10. THREAT SETTINGS
// ============================================================

// Threat report cache duration (minutes)
define('THREAT_CACHE_TTL', 5);

// Auto-escalate to NIS if threat is:
define('AUTO_ESCALATE_SEVERITY', 'critical');
define('AUTO_ESCALATE_REPORT_COUNT', 10); // If reported by 10+ servers

// Threat retention (days)
define('THREAT_RETENTION_DAYS', 90);

// ============================================================
// 11. PARTNER/NIS SETTINGS
// ============================================================

// NIS API endpoint (for sending threats)
define('NIS_API_ENDPOINT', 'https://nis.example.com/api/threats');
define('NIS_API_KEY', 'your-nis-api-key-here');
define('NIS_API_SECRET', 'your-nis-api-secret-here');

// Enable NIS integration
define('NIS_INTEGRATION_ENABLED', false); // Set to true when ready

// Partner data sharing
define('SHARE_ANONYMIZED_THREATS', true);
define('SHARE_WITH_PARTNERS', true);

// ============================================================
// 12. FEATURE FLAGS
// ============================================================

// Enable/disable features
define('FEATURE_LLAMA_ANALYSIS', true);
define('FEATURE_EXPERT_FEEDBACK', true);
define('FEATURE_NIS_ESCALATION', false); // Until partnership setup
define('FEATURE_THREAT_SHARING', true);
define('FEATURE_ANALYTICS_DASHBOARD', true);

// ============================================================
// 13. CACHE SETTINGS
// ============================================================

// Cache method: 'file', 'redis', 'memcached', 'none'
define('CACHE_METHOD', 'file');

// Cache directory (if using file cache)
define('CACHE_DIR', __DIR__ . '/../cache/');

// Ensure cache directory exists
if (!is_dir(CACHE_DIR)) {
    mkdir(CACHE_DIR, 0755, true);
}

// Redis settings (if using Redis)
define('REDIS_HOST', 'localhost');
define('REDIS_PORT', 6379);
define('REDIS_PASSWORD', null);

// ============================================================
// 14. SECURITY HEADERS
// ============================================================

define('SECURITY_HEADERS', [
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY',
    'X-XSS-Protection' => '1; mode=block',
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
]);

// ============================================================
// 15. PAGINATION
// ============================================================

define('ITEMS_PER_PAGE', 20);
define('MAX_ITEMS_PER_PAGE', 100);

// ============================================================
// 16. DATABASE CONNECTION CLASS
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

            // Set charset
            if (!$this->connection->set_charset(DB_CHARSET)) {
                throw new Exception("Error setting charset: " . $this->connection->error);
            }

            // Check connection
            if ($this->connection->connect_error) {
                throw new Exception("Database connection failed: " . $this->connection->connect_error);
            }
        } catch (Exception $e) {
            $this->handleError($e->getMessage());
        }
    }

    // Singleton pattern
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    // Get connection
    public function getConnection() {
        return $this->connection;
    }

    // Prepare statement
    public function prepare($query) {
        return $this->connection->prepare($query);
    }

    // Execute query
    public function query($query) {
        return $this->connection->query($query);
    }

    // Close connection
    public function close() {
        if ($this->connection) {
            $this->connection->close();
        }
    }

    // Handle errors
    private function handleError($message) {
        if (ENVIRONMENT === 'production') {
            // Log error silently in production
            error_log($message, 3, ERROR_LOG_FILE);
            die('Database connection error. Please contact support.');
        } else {
            // Show error in development
            die('Database Error: ' . $message);
        }
    }

    // Get last error
    public function getError() {
        return $this->connection->error;
    }

    // Get last insert ID
    public function getLastInsertId() {
        return $this->connection->insert_id;
    }

    // Close on destruct
    public function __destruct() {
        $this->close();
    }
}

// ============================================================
// 17. ERROR HANDLING
// ============================================================

// Set error reporting
if (ENVIRONMENT === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', ERROR_LOG_FILE);
}

// Custom error handler
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    $error_message = "[" . date('Y-m-d H:i:s') . "] Error: $errstr in $errfile:$errline";
    error_log($error_message . "\n", 3, ERROR_LOG_FILE);
    
    if (ENVIRONMENT === 'development') {
        echo "<pre>$error_message</pre>";
    }
});

// ============================================================
// 18. HELPER FUNCTIONS
// ============================================================

/**
 * Get database instance
 */
function getDB() {
    return Database::getInstance()->getConnection();
}

/**
 * Log message
 */
function logMessage($message, $type = 'info') {
    $log_file = ($type === 'error') ? ERROR_LOG_FILE : LOG_FILE;
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] [$type] $message\n";
    error_log($log_entry, 3, $log_file);
}

/**
 * Sanitize input
 */
function sanitize($input) {
    return htmlspecialchars(stripslashes(trim($input)), ENT_QUOTES, 'UTF-8');
}

/**
 * Generate API key
 */
function generateApiKey() {
    return 'smv_live_' . bin2hex(random_bytes(API_KEY_LENGTH / 2));
}

/**
 * Generate secure token
 */
function generateToken() {
    return bin2hex(random_bytes(32));
}

/**
 * Hash password
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
}

/**
 * Verify password
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
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
 * Check if API key is valid
 */
function validateApiKey($api_key, $api_secret) {
    $db = getDB();
    $stmt = $db->prepare("SELECT id, customer_id, is_active FROM api_keys WHERE api_key = ? AND api_secret = ? AND is_active = 1");
    $stmt->bind_param("ss", $api_key, $api_secret);
    $stmt->execute();
    $result = $stmt->get_result();
    
    return $result->fetch_assoc();
}

/**
 * Set security headers
 */
function setSecurityHeaders() {
    foreach (SECURITY_HEADERS as $header => $value) {
        header("$header: $value");
    }
}

// ============================================================
// 19. SESSION CONFIGURATION
// ============================================================

// Session settings - only if session not already started
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.gc_maxlifetime', SESSION_TIMEOUT * 60);
    session_set_cookie_params([
        'lifetime' => SESSION_TIMEOUT * 60,
        'path' => '/',
        'domain' => '',
        'secure' => (ENVIRONMENT === 'production'),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}

// ============================================================
// END OF CONFIGURATION
// ============================================================

?>
