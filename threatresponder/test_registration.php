<?php
/**
 * Server Registration Diagnostic Tool
 * Place this in your threat responder root directory
 * Access: https://threatresponder.scolemax.co.ke/test_registration.php
 */

header('Content-Type: text/html; charset=utf-8');
require_once 'config.php';

echo "<h1>Server Registration Diagnostic Test</h1>";
echo "<pre>";

// Test 1: Check if servers table exists
echo "\n=== TEST 1: Checking servers table ===\n";
try {
    $db = getDB();
    $result = $db->query("SELECT COUNT(*) as count FROM servers");
    $row = $result->fetch_assoc();
    echo "✓ Servers table exists\n";
    echo "  Current servers: " . $row['count'] . "\n";
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
}

// Test 2: Check connection_logs
echo "\n=== TEST 2: Checking connection_logs ===\n";
try {
    $result = $db->query("SELECT COUNT(*) as count FROM connection_logs");
    $row = $result->fetch_assoc();
    echo "✓ Connection_logs table exists\n";
    echo "  Total connection attempts logged: " . $row['count'] . "\n";
    
    if ($row['count'] > 0) {
        echo "\n  Recent connection attempts:\n";
        $recent = $db->query("SELECT action, status, error_message, created_at FROM connection_logs ORDER BY created_at DESC LIMIT 5");
        while ($log = $recent->fetch_assoc()) {
            echo "  - [{$log['created_at']}] {$log['action']}: {$log['status']}";
            if ($log['error_message']) {
                echo " - {$log['error_message']}";
            }
            echo "\n";
        }
    }
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
}

// Test 3: Check API keys
echo "\n=== TEST 3: Checking API keys ===\n";
try {
    $result = $db->query("SELECT COUNT(*) as count FROM api_keys WHERE is_active = 1");
    $row = $result->fetch_assoc();
    echo "✓ Active API keys: " . $row['count'] . "\n";
    
    // Show first 3 API keys (partial)
    $keys = $db->query("SELECT id, customer_id, SUBSTRING(api_key, 1, 20) as api_key_prefix, last_used, usage_count FROM api_keys WHERE is_active = 1 LIMIT 3");
    echo "\n  Sample API keys:\n";
    while ($key = $keys->fetch_assoc()) {
        echo "  - ID: {$key['id']}, Customer: {$key['customer_id']}, Key: {$key['api_key_prefix']}..., Used: {$key['usage_count']} times";
        if ($key['last_used']) {
            echo ", Last: {$key['last_used']}";
        }
        echo "\n";
    }
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
}

// Test 4: Simulate a register_server request
echo "\n=== TEST 4: Simulating register_server request ===\n";
try {
    // Get first active API key
    $keyResult = $db->query("SELECT api_key, api_secret, customer_id FROM api_keys WHERE is_active = 1 LIMIT 1");
    $keyData = $keyResult->fetch_assoc();
    
    if (!$keyData) {
        echo "✗ No active API keys found!\n";
    } else {
        echo "Using Customer ID: {$keyData['customer_id']}\n";
        echo "API Key: " . substr($keyData['api_key'], 0, 20) . "...\n\n";
        
        // Simulate what the WAF endpoint should do
        $customer_id = $keyData['customer_id'];
        $hostname = 'test-server.example.com';
        $server_ip = '192.168.1.100';
        
        echo "Attempting to register test server...\n";
        
        // Check if server exists
        $checkStmt = $db->prepare("SELECT id FROM servers WHERE customer_id = ? AND hostname = ?");
        $checkStmt->bind_param("is", $customer_id, $hostname);
        $checkStmt->execute();
        $existing = $checkStmt->get_result()->fetch_assoc();
        
        if ($existing) {
            echo "  Server already exists (ID: {$existing['id']})\n";
            echo "  Updating last_seen...\n";
            
            $updateStmt = $db->prepare("UPDATE servers SET last_seen = NOW(), status = 'active' WHERE id = ?");
            $updateStmt->bind_param("i", $existing['id']);
            if ($updateStmt->execute()) {
                echo "✓ Server updated successfully!\n";
            } else {
                echo "✗ Update failed: " . $db->error . "\n";
            }
        } else {
            echo "  Server doesn't exist, creating new...\n";
            
            $insertStmt = $db->prepare(
                "INSERT INTO servers (customer_id, hostname, server_ip, php_version, status, first_seen, last_seen) 
                VALUES (?, ?, ?, ?, 'active', NOW(), NOW())"
            );
            $phpVer = PHP_VERSION;
            $insertStmt->bind_param("isss", $customer_id, $hostname, $server_ip, $phpVer);
            
            if ($insertStmt->execute()) {
                $serverId = $db->insert_id;
                echo "✓ Server created successfully! (ID: $serverId)\n";
                
                // Update customer status
                $updateCust = $db->prepare("UPDATE customers SET installation_status = 'installed', is_active = 1 WHERE id = ?");
                $updateCust->bind_param("i", $customer_id);
                $updateCust->execute();
                echo "✓ Customer status updated to 'installed'\n";
            } else {
                echo "✗ Insert failed: " . $db->error . "\n";
            }
        }
    }
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
}

// Test 5: Check current servers
echo "\n=== TEST 5: Current servers in database ===\n";
try {
    $result = $db->query("SELECT s.id, s.customer_id, c.company_name, s.hostname, s.status, s.last_seen FROM servers s LEFT JOIN customers c ON s.customer_id = c.id ORDER BY s.created_at DESC LIMIT 10");
    $count = $result->num_rows;
    
    if ($count == 0) {
        echo "No servers registered yet.\n";
    } else {
        echo "Total servers: $count\n\n";
        while ($server = $result->fetch_assoc()) {
            echo "  Server ID: {$server['id']}\n";
            echo "  Customer: {$server['company_name']} (ID: {$server['customer_id']})\n";
            echo "  Hostname: {$server['hostname']}\n";
            echo "  Status: {$server['status']}\n";
            echo "  Last Seen: " . ($server['last_seen'] ?? 'Never') . "\n";
            echo "  ---\n";
        }
    }
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
}

// Test 6: Check WAF endpoint accessibility
echo "\n=== TEST 6: Testing WAF endpoint ===\n";
$wafEndpoint = BASE_URL . '/integrations/waf.php?action=ping';
echo "Endpoint: $wafEndpoint\n";

try {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $wafEndpoint,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Accept: application/json']
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    if ($curlError) {
        echo "✗ cURL Error: $curlError\n";
    } else {
        echo "✓ Endpoint accessible (HTTP $httpCode)\n";
        $data = json_decode($response, true);
        if ($data) {
            echo "  Response: " . json_encode($data, JSON_PRETTY_PRINT) . "\n";
        }
    }
} catch (Exception $e) {
    echo "✗ ERROR: " . $e->getMessage() . "\n";
}

echo "\n=== DIAGNOSTIC COMPLETE ===\n";
echo "\nIf servers table is empty after Test 4, check:\n";
echo "1. PHP error logs at: " . ERROR_LOG_FILE . "\n";
echo "2. Application logs at: " . LOG_FILE . "\n";
echo "3. WAF endpoint logs\n";
echo "4. Database user permissions\n";

echo "</pre>";
?>
