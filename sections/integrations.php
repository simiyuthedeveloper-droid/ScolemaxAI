<?php
/**
 * SMV Security - WAF Integrations Section
 * Manage Control Center API integration and test connectivity
 */

// Ensure this file is included from webui.php
if (!defined('DB_HOST') && !isset($db)) {
    die('Direct access not permitted');
}

// Handle AJAX requests for testing configuration
if (isset($_POST['action']) && $_POST['action'] === 'test_connection') {
    header('Content-Type: application/json');
    
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
        // FIXED: Proper endpoint construction
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
                'Accept: application/json'  // ADDED: Tell server we expect JSON
            ],
            CURLOPT_SSL_VERIFYPEER => false, // For local testing
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_FOLLOWLOCATION => true,  // ADDED: Follow redirects
            CURLOPT_MAXREDIRS => 3
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);
        
        // ADDED: Debug logging
        error_log("WAF Test - URL: $test_endpoint");
        error_log("WAF Test - HTTP Code: $http_code");
        error_log("WAF Test - Content-Type: $content_type");
        error_log("WAF Test - Response Preview: " . substr($response, 0, 500)); // First 500 chars
        
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
        
        // FIXED: Check if response is actually JSON before parsing
        if (stripos($content_type, 'application/json') === false && 
            stripos($content_type, 'text/json') === false) {
            
            // Response is HTML or something else, not JSON
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
            // Try to parse error response
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
        
        // FIXED: Better JSON parsing with error handling
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
            echo json_encode([
                'success' => true,
                'message' => 'Connection successful!',
                'details' => 'Successfully connected to ScoleMax Control Center.',
                'server_info' => $response_data['server'] ?? 'ScoleMax Threat Response Center',
                'timestamp' => date('Y-m-d H:i:s')
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Authentication failed',
                'details' => $response_data['message'] ?? 'Invalid API credentials or endpoint not configured properly',
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
}

// Handle form submission to save configuration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_integration'])) {
    $control_center_url = trim($_POST['control_center_url'] ?? '');
    $api_key = trim($_POST['api_key'] ?? '');
    $api_secret = trim($_POST['api_secret'] ?? '');
    $auto_report = isset($_POST['auto_report']) ? 1 : 0;
    $auto_sync = isset($_POST['auto_sync']) ? 1 : 0;
    
    $save_success = true;
    $save_message = '';
    
    try {
        // Check if config entries exist, if not insert them
        $config_keys = ['control_center_url', 'api_key', 'api_secret', 'auto_report_threats', 'auto_sync_feeds'];
        
        foreach ($config_keys as $key) {
            $check = $db->query("SELECT config_key FROM config WHERE config_key = '$key' LIMIT 1");
            if ($check->num_rows == 0) {
                $db->query("INSERT INTO config (config_key, config_value) VALUES ('$key', '')");
            }
        }
        
        // Now update all values
        $stmt = $db->prepare("UPDATE config SET config_value = ? WHERE config_key = ?");
        
        // Control Center URL
        $key = 'control_center_url';
        $stmt->bind_param("ss", $control_center_url, $key);
        $stmt->execute();
        
        // API Key
        $key = 'api_key';
        $stmt->bind_param("ss", $api_key, $key);
        $stmt->execute();
        
        // API Secret
        $key = 'api_secret';
        $stmt->bind_param("ss", $api_secret, $key);
        $stmt->execute();
        
        // Auto report
        $auto_report_str = (string)$auto_report;
        $key = 'auto_report_threats';
        $stmt->bind_param("ss", $auto_report_str, $key);
        $stmt->execute();
        
        // Auto sync
        $auto_sync_str = (string)$auto_sync;
        $key = 'auto_sync_feeds';
        $stmt->bind_param("ss", $auto_sync_str, $key);
        $stmt->execute();
        
        $stmt->close();
        
        $save_message = 'Configuration saved successfully!';
        
    } catch (Exception $e) {
        $save_success = false;
        $save_message = 'Error saving configuration: ' . $e->getMessage();
    }
}

// Get current configuration from database
$current_config = [
    'control_center_url' => '',
    'api_key' => '',
    'api_secret' => '',
    'auto_report_threats' => '1',
    'auto_sync_feeds' => '1',
];

try {
    $result = $db->query("SELECT config_key, config_value FROM config WHERE config_key IN ('control_center_url', 'api_key', 'api_secret', 'auto_report_threats', 'auto_sync_feeds')");
    while ($row = $result->fetch_assoc()) {
        $current_config[$row['config_key']] = $row['config_value'];
    }
} catch (Exception $e) {
    error_log("Error loading config: " . $e->getMessage());
}

// Get last sync information
$last_sync = [
    'time' => 'Never',
    'status' => 'unknown',
    'threats_sent' => 0
];

try {
    $result = $db->query("SELECT sync_type, success, created_at, threats_sent FROM sync_log WHERE sync_type = 'threat_report' ORDER BY created_at DESC LIMIT 1");
    if ($row = $result->fetch_assoc()) {
        $last_sync = [
            'time' => date('M d, Y H:i:s', strtotime($row['created_at'])),
            'status' => $row['success'] ? 'success' : 'failed',
            'threats_sent' => $row['threats_sent'] ?? 0
        ];
    }
} catch (Exception $e) {
    error_log("Error loading sync log: " . $e->getMessage());
}

// Get sync statistics
$sync_stats = [
    'total_syncs' => 0,
    'successful_syncs' => 0,
    'failed_syncs' => 0,
    'total_threats_reported' => 0
];

try {
    $result = $db->query("SELECT 
        COUNT(*) as total_syncs,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_syncs,
        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_syncs,
        SUM(threats_sent) as total_threats_reported
        FROM sync_log 
        WHERE sync_type = 'threat_report'
    ");
    if ($row = $result->fetch_assoc()) {
        $sync_stats = [
            'total_syncs' => (int)$row['total_syncs'],
            'successful_syncs' => (int)$row['successful_syncs'],
            'failed_syncs' => (int)$row['failed_syncs'],
            'total_threats_reported' => (int)($row['total_threats_reported'] ?? 0)
        ];
    }
} catch (Exception $e) {
    error_log("Error loading sync stats: " . $e->getMessage());
}
?>

<!-- Success/Error Messages -->
<?php if (isset($save_message)): ?>
<div class="card" style="border-left: 4px solid <?php echo $save_success ? 'var(--success)' : 'var(--danger)'; ?>">
    <div class="card-body">
        <div style="display: flex; align-items: center; gap: 1rem;">
            <i class="fas <?php echo $save_success ? 'fa-check-circle' : 'fa-exclamation-circle'; ?>" 
               style="font-size: 1.5rem; color: <?php echo $save_success ? 'var(--success)' : 'var(--danger)'; ?>"></i>
            <div>
                <strong><?php echo $save_success ? 'Success!' : 'Error'; ?></strong>
                <p style="margin: 0; color: var(--text-muted); font-size: 0.875rem;"><?php echo htmlspecialchars($save_message); ?></p>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Integration Status -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo $sync_stats['total_syncs']; ?></div>
                <div class="stat-label">Total Syncs</div>
            </div>
            <div class="stat-icon blue">
                <i class="fas fa-sync-alt"></i>
            </div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo $sync_stats['successful_syncs']; ?></div>
                <div class="stat-label">Successful Syncs</div>
            </div>
            <div class="stat-icon green">
                <i class="fas fa-check-circle"></i>
            </div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo $sync_stats['failed_syncs']; ?></div>
                <div class="stat-label">Failed Syncs</div>
            </div>
            <div class="stat-icon red">
                <i class="fas fa-times-circle"></i>
            </div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo $sync_stats['total_threats_reported']; ?></div>
                <div class="stat-label">Threats Reported</div>
            </div>
            <div class="stat-icon purple">
                <i class="fas fa-shield-alt"></i>
            </div>
        </div>
    </div>
</div>

<!-- Last Sync Status -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-clock"></i> Last Sync Status
        </h3>
    </div>
    <div class="card-body">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem;">
            <div>
                <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.25rem;">Last Sync Time</div>
                <div style="font-weight: 600;"><?php echo htmlspecialchars($last_sync['time']); ?></div>
            </div>
            <div>
                <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.25rem;">Status</div>
                <div>
                    <?php if ($last_sync['status'] === 'success'): ?>
                        <span class="badge badge-success"><i class="fas fa-check"></i> Success</span>
                    <?php elseif ($last_sync['status'] === 'failed'): ?>
                        <span class="badge badge-danger"><i class="fas fa-times"></i> Failed</span>
                    <?php else: ?>
                        <span class="badge badge-info"><i class="fas fa-question"></i> Unknown</span>
                    <?php endif; ?>
                </div>
            </div>
            <div>
                <div style="color: var(--text-muted); font-size: 0.8rem; margin-bottom: 0.25rem;">Threats Sent</div>
                <div style="font-weight: 600;"><?php echo $last_sync['threats_sent']; ?></div>
            </div>
        </div>
    </div>
</div>

<!-- Control Center Configuration Form -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-plug"></i> ScoleMax Threat Response Center Integration
        </h3>
    </div>
    <div class="card-body">
        <form method="POST" id="integrationForm">
            <div class="form-group">
                <label class="form-label">
                    <i class="fas fa-server"></i> Response Center URL
                </label>
                <input 
                    type="url" 
                    name="control_center_url" 
                    id="control_center_url"
                    class="form-control" 
                    placeholder="https://threatresponder.scolemax.co.ke"
                    value="<?php echo htmlspecialchars($current_config['control_center_url']); ?>"
                    required
                >
                <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.25rem;">
                    Full URL to your ScoleMax Threat Response Center installation
                </small>
            </div>

            <div class="form-group">
                <label class="form-label">
                    <i class="fas fa-key"></i> API Key
                </label>
                <input 
                    type="text" 
                    name="api_key" 
                    id="api_key"
                    class="form-control" 
                    placeholder="smv_waf_xxxxxxxxxxxxxxxx"
                    value="<?php echo htmlspecialchars($current_config['api_key']); ?>"
                    required
                >
                <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.25rem;">
                    Your unique API key from the Response Center
                </small>
            </div>

            <div class="form-group">
                <label class="form-label">
                    <i class="fas fa-lock"></i> API Secret
                </label>
                <input 
                    type="password" 
                    name="api_secret" 
                    id="api_secret"
                    class="form-control" 
                    placeholder="Enter your API secret"
                    value="<?php echo htmlspecialchars($current_config['api_secret']); ?>"
                    required
                >
                <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-top: 0.25rem;">
                    Keep this secret secure - it authenticates your WAF to the Control Center
                </small>
            </div>

            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input 
                        type="checkbox" 
                        name="auto_report" 
                        <?php echo $current_config['auto_report_threats'] == '1' ? 'checked' : ''; ?>
                        style="width: 18px; height: 18px; cursor: pointer;"
                    >
                    <span style="font-weight: 500;">
                        <i class="fas fa-paper-plane"></i> Auto-report threats to Control Center
                    </span>
                </label>
                <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-left: 1.625rem;">
                    Automatically send detected threats to the Threat Response Center for analysis
                </small>
            </div>

            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                    <input 
                        type="checkbox" 
                        name="auto_sync" 
                        <?php echo $current_config['auto_sync_feeds'] == '1' ? 'checked' : ''; ?>
                        style="width: 18px; height: 18px; cursor: pointer;"
                    >
                    <span style="font-weight: 500;">
                        <i class="fas fa-download"></i> Auto-sync threat feeds from Response Center
                    </span>
                </label>
                <small style="color: var(--text-muted); font-size: 0.75rem; display: block; margin-left: 1.625rem;">
                    Receive and apply threat intelligence from the national threat feed
                </small>
            </div>

            <div style="display: flex; gap: 1rem; margin-top: 1.5rem;">
                <button type="button" id="testConfigBtn" class="btn btn-secondary">
                    <i class="fas fa-vial"></i> Test Configuration
                </button>
                <button type="submit" name="save_integration" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Configuration
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Test Results Container (Hidden by default) -->
<div id="testResultsCard" class="card" style="display: none;">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-flask"></i> Connection Test Results
        </h3>
    </div>
    <div class="card-body" id="testResultsBody">
        <!-- Results will be inserted here via JavaScript -->
    </div>
</div>

<!-- Recent Sync Activity -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-history"></i> Recent Sync Activity
        </h3>
    </div>
    <div class="card-body">
        <?php
        try {
            $result = $db->query("SELECT sync_type, success, created_at, threats_sent, response_message 
                                 FROM sync_log 
                                 ORDER BY created_at DESC 
                                 LIMIT 10");
            
            if ($result && $result->num_rows > 0):
        ?>
        <table>
            <thead>
                <tr>
                    <th>Sync Type</th>
                    <th>Status</th>
                    <th>Threats Sent</th>
                    <th>Message</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = $result->fetch_assoc()): ?>
                <tr>
                    <td>
                        <i class="fas fa-exchange-alt"></i>
                        <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $row['sync_type']))); ?>
                    </td>
                    <td>
                        <?php if ($row['success']): ?>
                            <span class="badge badge-success"><i class="fas fa-check"></i> Success</span>
                        <?php else: ?>
                            <span class="badge badge-danger"><i class="fas fa-times"></i> Failed</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo $row['threats_sent'] ?? 0; ?></td>
                    <td style="max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                        <?php echo htmlspecialchars($row['response_message'] ?? 'N/A'); ?>
                    </td>
                    <td><?php echo date('M d, Y H:i:s', strtotime($row['created_at'])); ?></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
        <?php 
            else:
        ?>
        <div class="empty-state">
            <i class="fas fa-inbox"></i>
            <p>No sync activity yet</p>
            <p style="font-size: 0.8rem; margin-top: 0.5rem;">Configure and test your integration to start syncing</p>
        </div>
        <?php 
            endif;
        } catch (Exception $e) {
            echo '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Error loading sync activity</p></div>';
        }
        ?>
    </div>
</div>

<!-- JavaScript for Test Configuration -->
<script>
document.getElementById('testConfigBtn').addEventListener('click', function() {
    const btn = this;
    const originalText = btn.innerHTML;
    
    // Disable button and show loading state
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
    
    // Get form values
    const formData = new FormData();
    formData.append('action', 'test_connection');
    formData.append('control_center_url', document.getElementById('control_center_url').value);
    formData.append('api_key', document.getElementById('api_key').value);
    formData.append('api_secret', document.getElementById('api_secret').value);
    
    // Send AJAX request to standalone handler
    fetch('test-connection.php', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        // Check if response is JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Server returned non-JSON response. Check server logs for PHP errors.');
        }
        return response.json();
    })
    .then(data => {
        // Show results card
        const resultsCard = document.getElementById('testResultsCard');
        const resultsBody = document.getElementById('testResultsBody');
        
        resultsCard.style.display = 'block';
        
        if (data.success) {
            // Build registration status HTML
            let registrationStatusHtml = '';
            if (data.server_registered !== undefined) {
                const regIcon = data.server_registered ? 'fa-check-circle' : 'fa-exclamation-circle';
                const regColor = data.server_registered ? 'var(--success)' : 'var(--warning)';
                const regStatus = data.server_registered ? 'Registered' : 'Not Registered';
                
                registrationStatusHtml = `
                    <div>
                        <div style="color: var(--text-muted); font-size: 0.75rem;">Registration Status</div>
                        <div style="font-weight: 600; margin-top: 0.25rem; color: ${regColor};">
                            <i class="fas ${regIcon}"></i> ${regStatus}
                        </div>
                    </div>
                `;
            }
            
            // Build registration message HTML
            let registrationMessageHtml = '';
            if (data.registration_message) {
                const isWarning = data.registration_message.toLowerCase().includes('warning');
                const msgColor = isWarning ? 'var(--warning)' : 'var(--success)';
                const msgIcon = isWarning ? 'fa-exclamation-triangle' : 'fa-server';
                
                registrationMessageHtml = `
                    <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(59, 130, 246, 0.05); border-left: 3px solid ${msgColor}; border-radius: 4px;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <i class="fas ${msgIcon}" style="color: ${msgColor};"></i>
                            <span style="font-size: 0.875rem; color: var(--text);">${data.registration_message}</span>
                        </div>
                    </div>
                `;
            }
            
            resultsBody.innerHTML = `
                <div style="border-left: 4px solid var(--success); padding: 1rem; background: rgba(74, 222, 128, 0.05); border-radius: 4px;">
                    <div style="display: flex; align-items: start; gap: 1rem;">
                        <i class="fas fa-check-circle" style="font-size: 2rem; color: var(--success);"></i>
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 0.5rem 0; color: var(--success);">
                                <i class="fas fa-check"></i> Connection Successful!
                            </h4>
                            <p style="margin: 0; color: var(--text);">${data.message}</p>
                            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border);">
                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                                    <div>
                                        <div style="color: var(--text-muted); font-size: 0.75rem;">Server Info</div>
                                        <div style="font-weight: 600; margin-top: 0.25rem;">${data.server_info || 'N/A'}</div>
                                    </div>
                                    <div>
                                        <div style="color: var(--text-muted); font-size: 0.75rem;">Test Time</div>
                                        <div style="font-weight: 600; margin-top: 0.25rem;">${data.timestamp || 'N/A'}</div>
                                    </div>
                                    ${registrationStatusHtml}
                                </div>
                            </div>
                            ${registrationMessageHtml}
                            <p style="margin: 1rem 0 0 0; color: var(--text-muted); font-size: 0.875rem;">
                                <i class="fas fa-info-circle"></i> ${data.details || 'Ready to sync'}
                            </p>
                        </div>
                    </div>
                </div>
            `;
        } else {
            // Show debug info if available
            let debugHtml = '';
            if (data.debug_info) {
                debugHtml = `
                    <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(0, 0, 0, 0.3); border-radius: 4px; font-family: monospace; font-size: 0.75rem;">
                        <div style="color: var(--text-muted); margin-bottom: 0.5rem;">Debug Information:</div>
                        <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(data.debug_info, null, 2)}</pre>
                    </div>
                `;
            }
            
            resultsBody.innerHTML = `
                <div style="border-left: 4px solid var(--danger); padding: 1rem; background: rgba(239, 68, 68, 0.05); border-radius: 4px;">
                    <div style="display: flex; align-items: start; gap: 1rem;">
                        <i class="fas fa-times-circle" style="font-size: 2rem; color: var(--danger);"></i>
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 0.5rem 0; color: var(--danger);">
                                <i class="fas fa-exclamation-triangle"></i> Connection Failed
                            </h4>
                            <p style="margin: 0; color: var(--text); font-weight: 600;">${data.message}</p>
                            <p style="margin: 0.75rem 0 0 0; color: var(--text-muted); font-size: 0.875rem;">
                                ${data.details || 'Please check your configuration and try again'}
                            </p>
                            ${debugHtml}
                            <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(0, 0, 0, 0.2); border-radius: 4px;">
                                <div style="color: var(--text-muted); font-size: 0.75rem; margin-bottom: 0.5rem;">
                                    <i class="fas fa-lightbulb"></i> Troubleshooting Tips:
                                </div>
                                <ul style="margin: 0; padding-left: 1.5rem; color: var(--text); font-size: 0.875rem;">
                                    <li>Verify the Control Center URL is correct and accessible</li>
                                    <li>Check that your API Key and Secret are valid</li>
                                    <li>Ensure the Control Center server is running</li>
                                    <li>Check firewall settings and network connectivity</li>
                                    <li>Check server error logs for PHP errors</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Scroll to results
        resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    })
    .catch(error => {
        // Show error
        const resultsCard = document.getElementById('testResultsCard');
        const resultsBody = document.getElementById('testResultsBody');
        
        resultsCard.style.display = 'block';
        resultsBody.innerHTML = `
            <div style="border-left: 4px solid var(--danger); padding: 1rem; background: rgba(239, 68, 68, 0.05); border-radius: 4px;">
                <div style="display: flex; align-items: center; gap: 1rem;">
                    <i class="fas fa-exclamation-circle" style="font-size: 1.5rem; color: var(--danger);"></i>
                    <div>
                        <strong style="color: var(--danger);">Test Error</strong>
                        <p style="margin: 0; color: var(--text-muted); font-size: 0.875rem;">
                            ${error.message || 'An unexpected error occurred'}
                        </p>
                    </div>
                </div>
            </div>
        `;
    })
    .finally(() => {
        // Re-enable button
        btn.disabled = false;
        btn.innerHTML = originalText;
    });
});
</script>
