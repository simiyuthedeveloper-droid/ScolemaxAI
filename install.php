<?php
/**
 * SMV Security - WAF System Installer
 * Automated installation script for customer servers
 * Run: php install.php
 */

// ============================================================
// 1. INSTALLER INITIALIZATION
// ============================================================

// Start output buffering
ob_start();

// Set error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set execution time
set_time_limit(300);

// Define base directory
define('BASE_DIR', __DIR__);
define('INSTALL_LOG', BASE_DIR . '/install.log');

// Colors for CLI output
$colors = [
    'reset' => "\033[0m",
    'red' => "\033[91m",
    'green' => "\033[92m",
    'yellow' => "\033[93m",
    'blue' => "\033[94m",
    'cyan' => "\033[96m",
];

// ============================================================
// 2. INSTALLER CLASS
// ============================================================

class WAFInstaller {
    private $baseDir;
    private $colors;
    private $errors = [];
    private $warnings = [];
    private $success = [];
    
    public function __construct($baseDir, $colors) {
        $this->baseDir = $baseDir;
        $this->colors = $colors;
    }
    
    /**
     * Output colored message
     */
    private function output($message, $type = 'info') {
        $prefix = '';
        
        switch ($type) {
            case 'success':
                $prefix = $this->colors['green'] . '✓' . $this->colors['reset'];
                break;
            case 'error':
                $prefix = $this->colors['red'] . '✗' . $this->colors['reset'];
                break;
            case 'warning':
                $prefix = $this->colors['yellow'] . '⚠' . $this->colors['reset'];
                break;
            case 'info':
                $prefix = $this->colors['blue'] . 'ℹ' . $this->colors['reset'];
                break;
            case 'title':
                echo "\n" . $this->colors['cyan'] . str_repeat('=', 60) . $this->colors['reset'] . "\n";
                echo $this->colors['cyan'] . $message . $this->colors['reset'] . "\n";
                echo $this->colors['cyan'] . str_repeat('=', 60) . $this->colors['reset'] . "\n\n";
                return;
        }
        
        echo "$prefix $message\n";
        $this->logInstall("[$type] $message");
    }
    
    /**
     * Log installation progress
     */
    private function logInstall($message) {
        error_log("[" . date('Y-m-d H:i:s') . "] $message\n", 3, INSTALL_LOG);
    }
    
    /**
     * Check system requirements
     */
    public function checkRequirements() {
        $this->output('Checking System Requirements', 'title');
        
        $checks = [
            'PHP Version 7.4+' => version_compare(PHP_VERSION, '7.4', '>='),
            'mysqli Extension' => extension_loaded('mysqli'),
            'JSON Extension' => extension_loaded('json'),
            'cURL Extension' => extension_loaded('curl'),
            'Write Permission' => is_writable($this->baseDir),
        ];
        
        $allPassed = true;
        
        foreach ($checks as $check => $result) {
            if ($result) {
                $this->output("$check", 'success');
                $this->success[] = $check;
            } else {
                $this->output("$check", 'error');
                $this->errors[] = $check;
                $allPassed = false;
            }
        }
        
        if (!$allPassed) {
            $this->output("\nPlease fix the above errors and try again.", 'error');
            return false;
        }
        
        $this->output("All requirements met!\n", 'success');
        return true;
    }
    
    /**
     * Create required directories
     */
    public function createDirectories() {
        $this->output('Creating Directories', 'title');
        
        $directories = [
            'logs' => $this->baseDir . '/logs',
            'cache' => $this->baseDir . '/cache',
            'rules' => $this->baseDir . '/rules',
            'backups' => $this->baseDir . '/backups',
            'includes' => $this->baseDir . '/includes',
            'webui' => $this->baseDir . '/webui',
        ];
        
        foreach ($directories as $name => $dir) {
            if (!is_dir($dir)) {
                if (mkdir($dir, 0755, true)) {
                    $this->output("Created: $name/", 'success');
                } else {
                    $this->output("Failed to create: $name/", 'error');
                    $this->errors[] = "Could not create $dir";
                }
            } else {
                $this->output("Exists: $name/", 'info');
            }
        }
        
        // Set permissions
        @chmod($this->baseDir . '/logs', 0755);
        @chmod($this->baseDir . '/cache', 0755);
        
        $this->output("Directories ready!\n", 'success');
        return true;
    }
    
    /**
     * Check MySQL connection
     */
    public function checkDatabase() {
        $this->output('Checking Database Connection', 'title');
        
        // Try to detect MySQL
        $mysqlPaths = [
            'localhost',
            '127.0.0.1',
            'localhost:3306',
        ];
        
        foreach ($mysqlPaths as $host) {
            try {
                $conn = new mysqli($host, 'root', '');
                if (!$conn->connect_error) {
                    $this->output("MySQL found at: $host", 'success');
                    $conn->close();
                    return true;
                }
            } catch (Exception $e) {
                // Try next
            }
        }
        
        $this->output("Could not find MySQL - will try during installation", 'warning');
        $this->warnings[] = "MySQL connection not verified";
        return true;
    }
    
    /**
     * Create database and tables
     */
    public function createDatabase($host, $user, $password) {
        $this->output('Creating Database', 'title');
        
        try {
            // Connect to MySQL
            $conn = new mysqli($host, $user, $password);
            
            if ($conn->connect_error) {
                $this->output("Connection failed: " . $conn->connect_error, 'error');
                $this->errors[] = "MySQL connection failed";
                return false;
            }
            
            $this->output("Connected to MySQL", 'success');
            
            // Create database
            $dbName = 'smv_waf_local';
            $sql = "CREATE DATABASE IF NOT EXISTS $dbName CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
            
            if ($conn->query($sql) === true) {
                $this->output("Database created: $dbName", 'success');
            } else {
                $this->output("Failed to create database: " . $conn->error, 'error');
                $this->errors[] = "Database creation failed";
                $conn->close();
                return false;
            }
            
            // Select database
            $conn->select_db($dbName);
            
            // Read and execute schema
            $schemaFile = $this->baseDir . '/waf_database.sql';
            
            if (!file_exists($schemaFile)) {
                $this->output("Schema file not found: $schemaFile", 'error');
                $this->errors[] = "Schema file missing";
                $conn->close();
                return false;
            }
            
            $schemaSQL = file_get_contents($schemaFile);
            
            // Split by semicolon and execute each statement
            $statements = array_filter(array_map('trim', explode(';', $schemaSQL)));
            $tableCount = 0;
            
            foreach ($statements as $statement) {
                if (!empty($statement) && !preg_match('/^--/', $statement)) {
                    if ($conn->query($statement) === true) {
                        if (preg_match('/CREATE TABLE/i', $statement)) {
                            $tableCount++;
                        }
                    } else {
                        // Log but don't fail on "table exists" errors
                        if (strpos($conn->error, 'already exists') === false) {
                            $this->output("Query error: " . $conn->error, 'warning');
                        }
                    }
                }
            }
            
            $this->output("Created tables: $tableCount", 'success');
            
            $conn->close();
            $this->output("Database setup complete!\n", 'success');
            return true;
            
        } catch (Exception $e) {
            $this->output("Error: " . $e->getMessage(), 'error');
            $this->errors[] = $e->getMessage();
            return false;
        }
    }
    
    /**
     * Generate API credentials
     */
    public function generateCredentials() {
        $this->output('Generating API Credentials', 'title');
        
        $apiKey = 'smv_waf_' . bin2hex(random_bytes(16));
        $apiSecret = bin2hex(random_bytes(32));
        
        $credentials = [
            'api_key' => $apiKey,
            'api_secret' => $apiSecret,
            'generated_at' => date('Y-m-d H:i:s'),
        ];
        
        // Save to file
        $credFile = $this->baseDir . '/.api-credentials.json';
        file_put_contents($credFile, json_encode($credentials, JSON_PRETTY_PRINT));
        chmod($credFile, 0600);
        
        $this->output("API Key: " . substr($apiKey, 0, 20) . "...", 'success');
        $this->output("API Secret saved securely", 'success');
        $this->output("Credentials file: $credFile\n", 'info');
        
        return $credentials;
    }
    
    /**
     * Create configuration file
     */
    public function createConfigFile() {
        $this->output('Creating Configuration File', 'title');
        
        $configFile = $this->baseDir . '/config.php';
        
        if (file_exists($configFile)) {
            $this->output("Config file already exists", 'info');
            return true;
        }
        
        // Copy from template
        $templateFile = $this->baseDir . '/waf_config.php';
        
        if (!file_exists($templateFile)) {
            $this->output("Template file not found", 'error');
            $this->errors[] = "Config template missing";
            return false;
        }
        
        if (copy($templateFile, $configFile)) {
            chmod($configFile, 0644);
            $this->output("Config file created", 'success');
            $this->output("Location: $configFile\n", 'info');
            return true;
        } else {
            $this->output("Failed to create config file", 'error');
            $this->errors[] = "Config creation failed";
            return false;
        }
    }
    
    /**
     * Update configuration with credentials
     */
    public function updateConfiguration($apiKey, $apiSecret, $controlCenterUrl) {
        $this->output('Updating Configuration', 'title');
        
        $configFile = $this->baseDir . '/config.php';
        
        if (!file_exists($configFile)) {
            $this->output("Config file not found", 'error');
            return false;
        }
        
        try {
            $content = file_get_contents($configFile);
            
            // Update API key
            $content = preg_replace(
                "/define\('API_KEY',\s*'[^']*'\);/",
                "define('API_KEY', '$apiKey');",
                $content
            );
            
            // Update API secret
            $content = preg_replace(
                "/define\('API_SECRET',\s*'[^']*'\);/",
                "define('API_SECRET', '$apiSecret');",
                $content
            );
            
            // Update control center URL
            $content = preg_replace(
                "/define\('CONTROL_CENTER_URL',\s*'[^']*'\);/",
                "define('CONTROL_CENTER_URL', '$controlCenterUrl');",
                $content
            );
            
            file_put_contents($configFile, $content);
            
            $this->output("API Key configured", 'success');
            $this->output("API Secret configured", 'success');
            $this->output("Control Center URL configured\n", 'success');
            
            return true;
        } catch (Exception $e) {
            $this->output("Error updating config: " . $e->getMessage(), 'error');
            return false;
        }
    }
    
    /**
     * Create .htaccess for blocking
     */
    public function createHTAccess() {
        $this->output('Creating WAF Rules File', 'title');
        
        $htaccessFile = $this->baseDir . '/.htaccess.smv';
        
        $content = <<<'HTACCESS'
# SMV Security WAF Rules
# Auto-generated on installation

# Disable directory listing
Options -Indexes

# Block common attacks
<FilesMatch "\.(php|phtml|php3|php4|php5|phtml|shtml)$">
    Deny from all
</FilesMatch>

# SQL Injection protection
SetEnvIf Request_URI "(\*|union|select|insert|update|delete|drop)" BLOCK=1
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{ENV:BLOCK} =1
    RewriteRule .* - [F,L]
</IfModule>

HTACCESS;
        
        if (file_put_contents($htaccessFile, $content)) {
            chmod($htaccessFile, 0644);
            $this->output("WAF rules file created", 'success');
            $this->output("Location: $htaccessFile\n", 'info');
            return true;
        } else {
            $this->output("Failed to create WAF rules file", 'warning');
            return true; // Don't fail installation
        }
    }
    
    /**
     * Setup cron job for daemon
     */
    public function setupCron() {
        $this->output('Cron Job Setup (Manual)', 'title');
        
        $daemonPath = $this->baseDir . '/daemon.php';
        $phpPath = PHP_EXECUTABLE;
        
        $cronCommand = "*/5 * * * * $phpPath $daemonPath >> " . $this->baseDir . "/logs/daemon.log 2>&1";
        
        $this->output("To enable threat detection, add this to your crontab:", 'info');
        $this->output("", 'info');
        $this->output("$cronCommand", 'cyan');
        $this->output("", 'info');
        $this->output("Run: crontab -e", 'info');
        $this->output("Then paste the above line\n", 'info');
        
        return true;
    }
    
    /**
     * Display installation summary
     */
    public function displaySummary($credentials) {
        $this->output('Installation Summary', 'title');
        
        $this->output("Installation Status: " . (empty($this->errors) ? "✓ SUCCESSFUL" : "✗ FAILED"), 
            empty($this->errors) ? 'success' : 'error');
        
        if (!empty($this->success)) {
            $this->output("\nCompleted:", 'info');
            foreach ($this->success as $item) {
                $this->output("  • $item", 'success');
            }
        }
        
        if (!empty($this->warnings)) {
            $this->output("\nWarnings:", 'warning');
            foreach ($this->warnings as $item) {
                $this->output("  • $item", 'warning');
            }
        }
        
        if (!empty($this->errors)) {
            $this->output("\nErrors:", 'error');
            foreach ($this->errors as $item) {
                $this->output("  • $item", 'error');
            }
        }
        
        $this->output("\nNext Steps:", 'info');
        $this->output("1. Save your API credentials securely", 'info');
        $this->output("   API Key: " . $credentials['api_key'], 'cyan');
        $this->output("", 'info');
        $this->output("2. Set up cron job for threat detection", 'info');
        $this->output("3. Test WAF by visiting your website", 'info');
        $this->output("4. Check dashboard at: /webui/\n", 'info');
        
        return empty($this->errors);
    }
}

// ============================================================
// 3. RUN INSTALLATION
// ============================================================

// Check if running from CLI
$isCLI = (php_sapi_name() === 'cli');

if (!$isCLI) {
    // If web request, show simple HTML
    echo <<<'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>SMV Security WAF - Installation</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #3b82f6; }
        .error { color: #dc2626; }
        .success { color: #16a34a; }
        .info { color: #0284c7; }
        code { background: #f3f4f6; padding: 10px; display: block; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SMV Security WAF Installer</h1>
        
        <p class="info">Please run this installer from the command line:</p>
        
        <code>php install.php</code>
        
        <p class="info">Or via cron/SSH:</p>
        
        <code>cd /path/to/waf && php install.php</code>
        
        <p class="error"><strong>CLI Installation Only</strong></p>
        <p>For security reasons, this installer must be run from the command line, not through a web browser.</p>
    </div>
</body>
</html>
HTML;
    exit;
}

// Initialize installer
$installer = new WAFInstaller(BASE_DIR, $colors);

echo "\n";
echo $colors['cyan'] . "╔══════════════════════════════════════════════════════════╗" . $colors['reset'] . "\n";
echo $colors['cyan'] . "║                                                          ║" . $colors['reset'] . "\n";
echo $colors['cyan'] . "║        🛡️  SMV Security WAF Automated Installer          ║" . $colors['reset'] . "\n";
echo $colors['cyan'] . "║                                                          ║" . $colors['reset'] . "\n";
echo $colors['cyan'] . "╚══════════════════════════════════════════════════════════╝" . $colors['reset'] . "\n\n";

// Run installation steps
if (!$installer->checkRequirements()) {
    exit(1);
}

if (!$installer->createDirectories()) {
    exit(1);
}

$installer->checkDatabase();

// Get database credentials from user (with defaults)
echo $colors['yellow'] . "MySQL Connection Details" . $colors['reset'] . "\n";
echo "Leave blank for defaults (localhost, root, no password)\n\n";

$dbHost = trim(readline("MySQL Host [localhost]: ") ?: 'localhost');
$dbUser = trim(readline("MySQL User [root]: ") ?: 'root');
$dbPass = trim(readline("MySQL Password [none]: ") ?: '');

if (!$installer->createDatabase($dbHost, $dbUser, $dbPass)) {
    exit(1);
}

if (!$installer->createConfigFile()) {
    exit(1);
}

// Generate credentials
$credentials = $installer->generateCredentials();

// Get control center URL
echo "\n" . $colors['yellow'] . "Control Center Configuration" . $colors['reset'] . "\n";
$controlCenterUrl = trim(readline("Control Center URL [http://localhost/scolemax-control-center]: ") ?: 'http://localhost/scolemax-control-center');

if (!$installer->updateConfiguration($credentials['api_key'], $credentials['api_secret'], $controlCenterUrl)) {
    exit(1);
}

$installer->createHTAccess();
$installer->setupCron();

// Display summary
$success = $installer->displaySummary($credentials);

echo "\n" . $colors['cyan'] . str_repeat('=', 60) . $colors['reset'] . "\n\n";

exit($success ? 0 : 1);

?>
