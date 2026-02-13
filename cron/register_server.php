<?php
/**
 * SMV Security WAF - Server Registration & Heartbeat
 * Auto-registers server with Control Center
 * 
 * This file should be called:
 * 1. During WAF installation/setup
 * 2. Periodically via cron (every 5-15 minutes)
 * 3. Before reporting threats
 */

// Load WAF configuration
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/ScoleMaxControlAPI.php';

/**
 * Register or update server with Control Center
 */
function registerServerWithControlCenter() {
    try {
        // Check if Control Center is configured
        if (!function_exists('getConfig')) {
            return [
                'success' => false,
                'message' => 'WAF not configured yet'
            ];
        }
        
        $controlCenterUrl = getConfig('control_center_url', '');
        $apiKey = getConfig('api_key', '');
        $apiSecret = getConfig('api_secret', '');
        
        if (empty($controlCenterUrl) || empty($apiKey) || empty($apiSecret)) {
            return [
                'success' => false,
                'message' => 'Control Center credentials not configured'
            ];
        }
        
        // Initialize API client
        $api = new ScoleMaxControlAPI($controlCenterUrl, $apiKey, $apiSecret);
        
        // Prepare server information
        $serverInfo = [
            'hostname' => $_SERVER['HTTP_HOST'] ?? gethostname(),
            'server_ip' => $_SERVER['SERVER_ADDR'] ?? null,
            'server_name' => $_SERVER['SERVER_NAME'] ?? gethostname(),
            'php_version' => PHP_VERSION,
            'mysql_version' => function_exists('mysqli_get_client_info') ? mysqli_get_client_info() : 'unknown',
            'waf_version' => defined('WAF_VERSION') ? WAF_VERSION : '1.0.0',
            'server_timezone' => date_default_timezone_get(),
            'server_os' => PHP_OS
        ];
        
        // Register server
        $response = $api->registerServer($serverInfo);
        
        if (isset($response['success']) && $response['success'] === true) {
            // Log success
            if (function_exists('logMessage')) {
                $action = $response['data']['action'] ?? 'registered';
                logMessage("Server $action with Control Center", 'info');
            }
            
            return [
                'success' => true,
                'message' => $response['data']['message'] ?? 'Server registered',
                'data' => $response['data'] ?? []
            ];
        } else {
            // Log failure
            if (function_exists('logMessage')) {
                $error = $response['error'] ?? 'Unknown error';
                logMessage("Server registration failed: $error", 'error');
            }
            
            return [
                'success' => false,
                'message' => $response['error'] ?? 'Registration failed'
            ];
        }
        
    } catch (Exception $e) {
        if (function_exists('logMessage')) {
            logMessage("Server registration exception: " . $e->getMessage(), 'error');
        }
        
        return [
            'success' => false,
            'message' => 'Exception: ' . $e->getMessage()
        ];
    }
}

// If called directly (not included), execute registration
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    $result = registerServerWithControlCenter();
    
    if (php_sapi_name() === 'cli') {
        // Command line output
        echo "Server Registration: " . ($result['success'] ? 'SUCCESS' : 'FAILED') . "\n";
        echo "Message: " . $result['message'] . "\n";
    } else {
        // Web output
        header('Content-Type: application/json');
        echo json_encode($result, JSON_PRETTY_PRINT);
    }
    
    exit($result['success'] ? 0 : 1);
}

return true;
