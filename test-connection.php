<?php
/**
 * SMV Security - WAF Integration Test Handler
 * Standalone AJAX endpoint for testing Control Center connection
 * 
 * This file must be called BEFORE any HTML output
 */

// Start output buffering to catch any stray output
ob_start();

// Only handle AJAX test_connection requests
if (!isset($_POST['action']) || $_POST['action'] !== 'test_connection') {
    ob_end_clean();
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => 'Invalid request']);
    exit;
}

// Set JSON header
ob_end_clean();
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

$control_center_url = trim($_POST['control_center_url'] ?? '');
$api_key = trim($_POST['api_key'] ?? '');
$api_secret = trim($_POST['api_secret'] ?? '');

// Validate inputs
if (empty($control_center_url) || empty($api_key) || empty($api_secret)) {
    echo json_encode([
        'success' => false,
        'message' => 'All fields are required'
    ]);
    exit;
}

// Validate URL format
if (!filter_var($control_center_url, FILTER_VALIDATE_URL)) {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid Control Center URL format'
    ]);
    exit;
}

// Test connection to control center
try {
    $test_endpoint = rtrim($control_center_url, '/') . '/integrations/waf.php?action=ping';
    
    // Generate timestamp and signature (as per API docs)
    $timestamp = date('c'); // ISO 8601 format
    $message = $api_key . $timestamp . $api_secret;
    $signature = hash_hmac('sha256', $message, $api_secret);
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $test_endpoint,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER => [
            'X-API-Key: ' . $api_key,
            'X-API-Secret: ' . $api_secret,
            'X-Timestamp: ' . $timestamp,
            'X-Signature: ' . $signature,
            'Content-Type: application/json',
            'Accept: application/json'
        ],
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);
    
    // Check for curl errors
    if ($curl_error) {
        echo json_encode([
            'success' => false,
            'message' => 'Connection error: ' . $curl_error,
            'details' => 'Could not reach the Control Center. Check the URL and network connectivity.',
            'debug_info' => [
                'endpoint' => $test_endpoint,
                'curl_error' => $curl_error
            ]
        ]);
        exit;
    }
    
    // Check if response is JSON
    if (stripos($content_type, 'application/json') === false && 
        stripos($content_type, 'text/json') === false) {
        
        echo json_encode([
            'success' => false,
            'message' => 'Invalid response format from server',
            'details' => 'Server returned HTML instead of JSON. The endpoint may not exist or there is a PHP error on the server.',
            'debug_info' => [
                'http_code' => $http_code,
                'content_type' => $content_type,
                'response_preview' => substr(strip_tags($response), 0, 200),
                'endpoint' => $test_endpoint
            ]
        ]);
        exit;
    }
    
    // Check HTTP response code
    if ($http_code !== 200) {
        $error_data = @json_decode($response, true);
        
        echo json_encode([
            'success' => false,
            'message' => 'HTTP Error ' . $http_code,
            'details' => $error_data['message'] ?? 'Control Center returned an error. Check API credentials.',
            'debug_info' => [
                'http_code' => $http_code,
                'endpoint' => $test_endpoint,
                'response' => $error_data ?? substr($response, 0, 200)
            ]
        ]);
        exit;
    }
    
    // Parse JSON response
    $response_data = json_decode($response, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid JSON response from server',
            'details' => 'Could not parse server response: ' . json_last_error_msg(),
            'debug_info' => [
                'json_error' => json_last_error_msg(),
                'response_preview' => substr($response, 0, 300),
                'endpoint' => $test_endpoint
            ]
        ]);
        exit;
    }
    
    // Check if response indicates success
    if ($response_data && isset($response_data['success']) && $response_data['success'] === true) {
        // Extract data from nested structure if present
        $data = $response_data['data'] ?? $response_data;
        
        // ============================================================
        // AUTO-REGISTER SERVER AFTER SUCCESSFUL PING
        // ============================================================
        $server_registered = false;
        $registration_message = '';
        
        try {
            // Prepare server information
            $server_info = [
                'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
                'server_ip' => $_SERVER['SERVER_ADDR'] ?? null,
                'server_name' => $_SERVER['SERVER_NAME'] ?? null,
                'php_version' => PHP_VERSION,
                'mysql_version' => function_exists('mysqli_get_client_info') ? mysqli_get_client_info() : 'unknown',
                'waf_version' => defined('WAF_VERSION') ? WAF_VERSION : '1.0.0',
                'server_timezone' => date_default_timezone_get(),
                'server_os' => PHP_OS
            ];
            
            // Call register_server endpoint
            $register_endpoint = rtrim($control_center_url, '/') . '/integrations/waf.php?action=register_server';
            $register_timestamp = date('c');
            $register_message = $api_key . $register_timestamp . $api_secret;
            $register_signature = hash_hmac('sha256', $register_message, $api_secret);
            
            $register_ch = curl_init();
            curl_setopt_array($register_ch, [
                CURLOPT_URL => $register_endpoint,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($server_info),
                CURLOPT_TIMEOUT => 15,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_HTTPHEADER => [
                    'X-API-Key: ' . $api_key,
                    'X-API-Secret: ' . $api_secret,
                    'X-Timestamp: ' . $register_timestamp,
                    'X-Signature: ' . $register_signature,
                    'Content-Type: application/json',
                    'Accept: application/json'
                ],
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false
            ]);
            
            $register_response = curl_exec($register_ch);
            $register_http_code = curl_getinfo($register_ch, CURLINFO_HTTP_CODE);
            curl_close($register_ch);
            
            if ($register_http_code === 200) {
                $register_data = json_decode($register_response, true);
                if ($register_data && isset($register_data['success']) && $register_data['success'] === true) {
                    $server_registered = true;
                    $reg_info = $register_data['data'] ?? [];
                    $action = $reg_info['action'] ?? 'registered';
                    $registration_message = $action === 'registered' 
                        ? 'Server registered successfully in Control Center!' 
                        : 'Server heartbeat updated in Control Center!';
                }
            }
        } catch (Exception $reg_error) {
            // Registration failed but don't fail the whole test
            $registration_message = 'Warning: Server registration failed - ' . $reg_error->getMessage();
        }
        
        // Return success with registration info
        echo json_encode([
            'success' => true,
            'message' => 'Connection successful!',
            'details' => 'Successfully connected to ScoleMax Control Center.',
            'server_info' => $data['server'] ?? 'ScoleMax Threat Response Center',
            'server_registered' => $server_registered,
            'registration_message' => $registration_message,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Authentication failed',
            'details' => $response_data['error'] ?? $response_data['message'] ?? 'Invalid API credentials or endpoint not configured properly',
            'debug_info' => [
                'response' => $response_data
            ]
        ]);
    }
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Test failed: ' . $e->getMessage(),
        'details' => 'An unexpected error occurred during testing'
    ]);
}

exit;
