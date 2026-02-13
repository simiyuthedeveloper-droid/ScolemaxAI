<?php
/**
 * WAF Integration Diagnostic Tool
 * Tests Control Center endpoint and shows exact response
 * 
 * Usage: Run this file directly in your browser or via command line
 * Example: php diagnostic.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "=== WAF Integration Diagnostic Tool ===\n\n";

// Configuration - UPDATE THESE VALUES
$control_center_url = 'https://threatresponder.scolemax.co.ke'; // YOUR Control Center URL
$api_key = 'smv_waf_xxxxx'; // YOUR API Key
$api_secret = 'xxxxxxxxxxxxxx'; // YOUR API Secret

echo "Testing Connection to: $control_center_url\n";
echo "API Key: $api_key\n";
echo "API Secret: " . substr($api_secret, 0, 10) . "...\n\n";

// Test endpoint
$test_endpoint = rtrim($control_center_url, '/') . '/integrations/waf.php?action=ping';

echo "Full Endpoint URL: $test_endpoint\n\n";

// Generate timestamp and signature (as per API docs)
$timestamp = date('c'); // ISO 8601 format
$message = $api_key . $timestamp . $api_secret;
$signature = hash_hmac('sha256', $message, $api_secret);

echo "=== Authentication Details ===\n";
echo "Timestamp: $timestamp\n";
echo "Message to Sign: " . substr($message, 0, 50) . "...\n";
echo "HMAC Signature: $signature\n\n";

// Prepare headers
$headers = [
    'X-API-Key: ' . $api_key,
    'X-API-Secret: ' . $api_secret,
    'X-Timestamp: ' . $timestamp,
    'X-Signature: ' . $signature,
    'Content-Type: application/json',
    'Accept: application/json'
];

echo "=== Request Headers ===\n";
foreach ($headers as $header) {
    echo "$header\n";
}
echo "\n";

// Make request
echo "=== Making Request ===\n";
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $test_endpoint,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_VERBOSE => false
]);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_error = curl_error($ch);
$content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
$redirect_url = curl_getinfo($ch, CURLINFO_REDIRECT_URL);

// Get all response info
$curl_info = curl_getinfo($ch);

curl_close($ch);

echo "Request completed!\n\n";

// Display results
echo "=== Response Information ===\n";
echo "HTTP Status Code: $http_code\n";
echo "Content-Type: $content_type\n";
echo "cURL Error: " . ($curl_error ?: 'None') . "\n";
echo "Redirect URL: " . ($redirect_url ?: 'None') . "\n";
echo "Total Time: " . $curl_info['total_time'] . " seconds\n";
echo "DNS Lookup Time: " . $curl_info['namelookup_time'] . " seconds\n";
echo "Connect Time: " . $curl_info['connect_time'] . " seconds\n\n";

// Analyze response
echo "=== Response Analysis ===\n";

if ($curl_error) {
    echo "❌ CURL ERROR: $curl_error\n";
    echo "\nPossible causes:\n";
    echo "- DNS resolution failed\n";
    echo "- Network connectivity issues\n";
    echo "- Firewall blocking outbound connections\n";
    echo "- Invalid URL\n";
    exit(1);
}

if ($http_code !== 200) {
    echo "❌ HTTP Error: $http_code\n";
    
    switch ($http_code) {
        case 404:
            echo "\nEndpoint not found!\n";
            echo "Check if /integrations/waf.php exists on Control Center\n";
            break;
        case 401:
            echo "\nUnauthorized - Invalid credentials\n";
            break;
        case 403:
            echo "\nForbidden - Access denied\n";
            break;
        case 500:
            echo "\nInternal Server Error - PHP error on Control Center\n";
            break;
        case 502:
        case 503:
            echo "\nControl Center server is down or unreachable\n";
            break;
    }
}

// Check content type
$is_json = (stripos($content_type, 'application/json') !== false || 
            stripos($content_type, 'text/json') !== false);

if ($is_json) {
    echo "✅ Content-Type is JSON\n\n";
} else {
    echo "❌ Content-Type is NOT JSON: $content_type\n";
    echo "Server is returning HTML/text instead of JSON\n\n";
}

// Display raw response
echo "=== Raw Response (first 2000 characters) ===\n";
echo str_repeat('=', 60) . "\n";
echo substr($response, 0, 2000);
if (strlen($response) > 2000) {
    echo "\n... (response truncated, total length: " . strlen($response) . " bytes)";
}
echo "\n" . str_repeat('=', 60) . "\n\n";

// Try to parse as JSON
echo "=== JSON Parse Attempt ===\n";
$json_data = json_decode($response, true);

if (json_last_error() === JSON_ERROR_NONE) {
    echo "✅ Valid JSON response!\n\n";
    echo "Parsed JSON:\n";
    echo json_encode($json_data, JSON_PRETTY_PRINT) . "\n\n";
    
    if (isset($json_data['success'])) {
        if ($json_data['success'] === true) {
            echo "🎉 SUCCESS! Connection to Control Center is working!\n";
        } else {
            echo "❌ API returned success=false\n";
            echo "Message: " . ($json_data['message'] ?? 'No message') . "\n";
        }
    }
} else {
    echo "❌ Invalid JSON: " . json_last_error_msg() . "\n\n";
    
    echo "=== Debugging Tips ===\n";
    echo "1. Response looks like HTML? Check Control Center PHP errors\n";
    echo "2. Response is empty? Check if endpoint exists\n";
    echo "3. Response has PHP errors? Enable error_reporting on Control Center\n\n";
    
    // Try to detect what kind of response it is
    if (stripos($response, '<!DOCTYPE') !== false || stripos($response, '<html') !== false) {
        echo "⚠️  Response appears to be HTML\n";
        echo "This usually means:\n";
        echo "- PHP error on Control Center\n";
        echo "- Endpoint doesn't exist (404 page)\n";
        echo "- Server configuration issue\n\n";
        
        // Try to extract error message
        if (preg_match('/<title>(.*?)<\/title>/i', $response, $matches)) {
            echo "Page Title: " . $matches[1] . "\n";
        }
        
        if (preg_match('/Fatal error:(.*?)in/i', $response, $matches)) {
            echo "PHP Error Found: " . trim($matches[1]) . "\n";
        }
    } elseif (empty($response)) {
        echo "⚠️  Response is empty\n";
        echo "This usually means:\n";
        echo "- Endpoint doesn't produce any output\n";
        echo "- Server terminated connection\n";
        echo "- Script exited early\n";
    }
}

echo "\n=== Recommended Next Steps ===\n";

if (!$is_json) {
    echo "1. Check Control Center error logs:\n";
    echo "   - /var/log/apache2/error.log (Apache)\n";
    echo "   - /var/log/nginx/error.log (Nginx)\n";
    echo "   - Application error log if available\n\n";
    
    echo "2. Verify endpoint exists:\n";
    echo "   - Browse to: $control_center_url/integrations/\n";
    echo "   - Check if waf.php file exists\n\n";
    
    echo "3. Test endpoint manually:\n";
    echo "   curl -v '$test_endpoint'\n\n";
    
    echo "4. Enable error display on Control Center temporarily:\n";
    echo "   error_reporting(E_ALL);\n";
    echo "   ini_set('display_errors', 1);\n\n";
} else {
    echo "✅ Connection is working! JSON response received.\n";
    echo "You can now use the WAF integration.\n";
}

echo "\n" . str_repeat('=', 60) . "\n";
echo "Diagnostic Complete\n";
echo str_repeat('=', 60) . "\n";
?>
