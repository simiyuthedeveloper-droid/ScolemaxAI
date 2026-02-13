<?php
/**
 * SMV Security - WAF Settings Section
 * Comprehensive system configuration and management
 */

// Ensure this file is included from webui.php
if (!defined('DB_HOST') && !isset($db)) {
    die('Direct access not permitted');
}

$success_message = '';
$error_message = '';

// Handle settings update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    try {
        switch ($action) {
            case 'update_waf_settings':
                $waf_enabled = isset($_POST['waf_enabled']) ? 1 : 0;
                $auto_block = isset($_POST['auto_block']) ? 1 : 0;
                $threat_detection = isset($_POST['threat_detection']) ? 1 : 0;
                $rate_limit = intval($_POST['rate_limit'] ?? 100);
                $ddos_threshold = intval($_POST['ddos_threshold'] ?? 1000);
                
                // Update settings in database using prepared statements
                $stmt = $db->prepare("INSERT INTO config (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)");
                
                $settings = [
                    'waf_enabled' => $waf_enabled,
                    'auto_block_enabled' => $auto_block,
                    'threat_detection_enabled' => $threat_detection,
                    'rate_limit_requests' => $rate_limit,
                    'ddos_threshold' => $ddos_threshold,
                ];
                
                foreach ($settings as $key => $value) {
                    $value_str = (string)$value;
                    $stmt->bind_param("ss", $key, $value_str);
                    $stmt->execute();
                }
                $stmt->close();
                
                $success_message = 'WAF settings updated successfully!';
                break;
                
            case 'update_retention_settings':
                $threat_retention = intval($_POST['threat_retention_days'] ?? 30);
                $block_retention = intval($_POST['block_retention_days'] ?? 7);
                $log_retention = intval($_POST['log_retention_days'] ?? 90);
                
                $stmt = $db->prepare("INSERT INTO config (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)");
                
                $settings = [
                    'threat_retention_days' => $threat_retention,
                    'block_retention_days' => $block_retention,
                    'log_retention_days' => $log_retention,
                ];
                
                foreach ($settings as $key => $value) {
                    $value_str = (string)$value;
                    $stmt->bind_param("ss", $key, $value_str);
                    $stmt->execute();
                }
                $stmt->close();
                
                $success_message = 'Retention settings updated successfully!';
                break;
                
            case 'update_daemon_settings':
                $daemon_enabled = isset($_POST['daemon_enabled']) ? 1 : 0;
                $daemon_interval = intval($_POST['daemon_interval'] ?? 5);
                $log_file_path = trim($_POST['log_file_path'] ?? '');
                
                $stmt = $db->prepare("INSERT INTO config (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)");
                
                $settings = [
                    'daemon_enabled' => $daemon_enabled,
                    'daemon_interval_minutes' => $daemon_interval,
                    'log_file_path' => $log_file_path,
                ];
                
                foreach ($settings as $key => $value) {
                    $value_str = (string)$value;
                    $stmt->bind_param("ss", $key, $value_str);
                    $stmt->execute();
                }
                $stmt->close();
                
                $success_message = 'Daemon settings updated successfully!';
                break;
                
            case 'update_notification_settings':
                $email_notifications = isset($_POST['email_notifications']) ? 1 : 0;
                $notification_email = trim($_POST['notification_email'] ?? '');
                $notify_on_critical = isset($_POST['notify_on_critical']) ? 1 : 0;
                $notify_on_block = isset($_POST['notify_on_block']) ? 1 : 0;
                
                $stmt = $db->prepare("INSERT INTO config (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)");
                
                $settings = [
                    'email_notifications_enabled' => $email_notifications,
                    'notification_email' => $notification_email,
                    'notify_on_critical_threats' => $notify_on_critical,
                    'notify_on_ip_block' => $notify_on_block,
                ];
                
                foreach ($settings as $key => $value) {
                    $value_str = (string)$value;
                    $stmt->bind_param("ss", $key, $value_str);
                    $stmt->execute();
                }
                $stmt->close();
                
                $success_message = 'Notification settings updated successfully!';
                break;
                
            case 'clear_threat_logs':
                $confirm = $_POST['confirm_clear'] ?? '';
                if ($confirm === 'CLEAR') {
                    $result = $db->query("DELETE FROM local_threats");
                    $affected = $db->affected_rows;
                    $success_message = "Successfully cleared {$affected} threat log(s)";
                } else {
                    $error_message = 'Please type CLEAR to confirm this action';
                }
                break;
                
            case 'unblock_all_ips':
                $confirm = $_POST['confirm_unblock'] ?? '';
                if ($confirm === 'UNBLOCK') {
                    $result = $db->query("DELETE FROM blocked_ips");
                    $affected = $db->affected_rows;
                    $success_message = "Successfully unblocked {$affected} IP address(es)";
                } else {
                    $error_message = 'Please type UNBLOCK to confirm this action';
                }
                break;
                
            case 'cleanup_old_data':
                $deleted_threats = 0;
                $deleted_blocks = 0;
                
                // Get retention settings
                $result = $db->query("SELECT config_value FROM config WHERE config_key = 'threat_retention_days'");
                $threat_days = 30;
                if ($row = $result->fetch_assoc()) {
                    $threat_days = intval($row['config_value']);
                }
                
                $result = $db->query("SELECT config_value FROM config WHERE config_key = 'block_retention_days'");
                $block_days = 7;
                if ($row = $result->fetch_assoc()) {
                    $block_days = intval($row['config_value']);
                }
                
                // Delete old threats
                $db->query("DELETE FROM local_threats WHERE detected_at < DATE_SUB(NOW(), INTERVAL {$threat_days} DAY)");
                $deleted_threats = $db->affected_rows;
                
                // Delete expired blocks
                $db->query("DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < NOW()");
                $deleted_blocks = $db->affected_rows;
                
                $success_message = "Cleanup complete: Removed {$deleted_threats} old threat(s) and {$deleted_blocks} expired block(s)";
                break;
                
            default:
                $error_message = 'Invalid action';
        }
        
    } catch (Exception $e) {
        $error_message = 'Operation failed: ' . $e->getMessage();
    }
}

// Get current settings from database
$current_settings = [
    'waf_enabled' => '1',
    'auto_block_enabled' => '1',
    'threat_detection_enabled' => '1',
    'rate_limit_requests' => '100',
    'ddos_threshold' => '1000',
    'threat_retention_days' => '30',
    'block_retention_days' => '7',
    'log_retention_days' => '90',
    'daemon_enabled' => '0',
    'daemon_interval_minutes' => '5',
    'log_file_path' => '/var/log/apache2/access.log',
    'email_notifications_enabled' => '0',
    'notification_email' => '',
    'notify_on_critical_threats' => '1',
    'notify_on_ip_block' => '1',
];

try {
    $result = $db->query("SELECT config_key, config_value FROM config");
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            if (isset($current_settings[$row['config_key']])) {
                $current_settings[$row['config_key']] = $row['config_value'];
            }
        }
    }
} catch (Exception $e) {
    error_log("Error loading settings: " . $e->getMessage());
}

// Get database statistics
$db_stats = [
    'total_threats' => 0,
    'total_blocks' => 0,
    'database_size' => 'Unknown',
    'old_threats' => 0,
    'expired_blocks' => 0,
];

try {
    // Total threats
    $result = $db->query("SELECT COUNT(*) as count FROM local_threats");
    if ($row = $result->fetch_assoc()) {
        $db_stats['total_threats'] = $row['count'];
    }
    
    // Total blocks
    $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips");
    if ($row = $result->fetch_assoc()) {
        $db_stats['total_blocks'] = $row['count'];
    }
    
    // Database size
    $result = $db->query("SELECT SUM(data_length + index_length) / 1024 / 1024 AS size_mb FROM information_schema.TABLES WHERE table_schema = '{$db_name}'");
    if ($row = $result->fetch_assoc()) {
        $db_stats['database_size'] = number_format($row['size_mb'], 2) . ' MB';
    }
    
    // Old threats (beyond retention)
    $retention_days = intval($current_settings['threat_retention_days']);
    $result = $db->query("SELECT COUNT(*) as count FROM local_threats WHERE detected_at < DATE_SUB(NOW(), INTERVAL {$retention_days} DAY)");
    if ($row = $result->fetch_assoc()) {
        $db_stats['old_threats'] = $row['count'];
    }
    
    // Expired blocks
    $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < NOW()");
    if ($row = $result->fetch_assoc()) {
        $db_stats['expired_blocks'] = $row['count'];
    }
    
} catch (Exception $e) {
    error_log("Error loading database stats: " . $e->getMessage());
}
?>

<!-- Success/Error Messages -->
<?php if (!empty($success_message)): ?>
<div class="card" style="border-left: 4px solid var(--success); background: rgba(74, 222, 128, 0.05);">
    <div class="card-body">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
            <i class="fas fa-check-circle" style="font-size: 1.5rem; color: var(--success);"></i>
            <div>
                <strong style="color: var(--success);">Success!</strong>
                <p style="margin: 0; color: var(--text-muted); font-size: 0.875rem;"><?php echo htmlspecialchars($success_message); ?></p>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<?php if (!empty($error_message)): ?>
<div class="card" style="border-left: 4px solid var(--danger); background: rgba(239, 68, 68, 0.05);">
    <div class="card-body">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
            <i class="fas fa-exclamation-circle" style="font-size: 1.5rem; color: var(--danger);"></i>
            <div>
                <strong style="color: var(--danger);">Error!</strong>
                <p style="margin: 0; color: var(--text-muted); font-size: 0.875rem;"><?php echo htmlspecialchars($error_message); ?></p>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Database Statistics Overview -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($db_stats['total_threats']); ?></div>
                <div class="stat-label">Total Threats Logged</div>
            </div>
            <div class="stat-icon blue">
                <i class="fas fa-shield-alt"></i>
            </div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($db_stats['total_blocks']); ?></div>
                <div class="stat-label">Blocked IPs</div>
            </div>
            <div class="stat-icon red">
                <i class="fas fa-ban"></i>
            </div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo $db_stats['database_size']; ?></div>
                <div class="stat-label">Database Size</div>
            </div>
            <div class="stat-icon cyan">
                <i class="fas fa-database"></i>
            </div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($db_stats['old_threats']); ?></div>
                <div class="stat-label">Old Threats (Can Cleanup)</div>
            </div>
            <div class="stat-icon yellow">
                <i class="fas fa-broom"></i>
            </div>
        </div>
    </div>
</div>

<!-- WAF Configuration -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-shield-alt"></i> WAF Configuration
        </h3>
        <span class="badge badge-<?php echo $current_settings['waf_enabled'] == '1' ? 'success' : 'danger'; ?>">
            <?php echo $current_settings['waf_enabled'] == '1' ? 'Enabled' : 'Disabled'; ?>
        </span>
    </div>
    <div class="card-body">
        <form method="POST" action="">
            <input type="hidden" name="action" value="update_waf_settings">
            
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
                    <input type="checkbox" name="waf_enabled" value="1" <?php echo $current_settings['waf_enabled'] == '1' ? 'checked' : ''; ?> 
                           style="width: 18px; height: 18px; cursor: pointer;">
                    <div>
                        <div class="form-label" style="margin-bottom: 0.25rem;">
                            <i class="fas fa-power-off"></i> Enable WAF Protection
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem;">Activate real-time threat detection and blocking system</div>
                    </div>
                </label>
            </div>
            
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
                    <input type="checkbox" name="threat_detection" value="1" <?php echo $current_settings['threat_detection_enabled'] == '1' ? 'checked' : ''; ?>
                           style="width: 18px; height: 18px; cursor: pointer;">
                    <div>
                        <div class="form-label" style="margin-bottom: 0.25rem;">
                            <i class="fas fa-search"></i> Threat Detection
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem;">Scan and identify malicious patterns in traffic</div>
                    </div>
                </label>
            </div>
            
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
                    <input type="checkbox" name="auto_block" value="1" <?php echo $current_settings['auto_block_enabled'] == '1' ? 'checked' : ''; ?>
                           style="width: 18px; height: 18px; cursor: pointer;">
                    <div>
                        <div class="form-label" style="margin-bottom: 0.25rem;">
                            <i class="fas fa-ban"></i> Auto-Block Threats
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem;">Automatically block IPs after detecting critical threats</div>
                    </div>
                </label>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.25rem; margin-top: 1.5rem;">
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-tachometer-alt"></i> Rate Limit (requests/minute)
                    </label>
                    <input type="number" name="rate_limit" class="form-control" 
                           value="<?php echo intval($current_settings['rate_limit_requests']); ?>" min="10" max="10000">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">Maximum requests per minute from a single IP</div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-exclamation-triangle"></i> DDoS Threshold (requests/minute)
                    </label>
                    <input type="number" name="ddos_threshold" class="form-control" 
                           value="<?php echo intval($current_settings['ddos_threshold']); ?>" min="100" max="100000">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">Trigger DDoS protection at this threshold</div>
                </div>
            </div>
            
            <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save WAF Settings
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Data Retention Settings -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-clock"></i> Data Retention
        </h3>
    </div>
    <div class="card-body">
        <form method="POST" action="">
            <input type="hidden" name="action" value="update_retention_settings">
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.25rem;">
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-shield-alt"></i> Threat Logs Retention (days)
                    </label>
                    <input type="number" name="threat_retention_days" class="form-control" 
                           value="<?php echo intval($current_settings['threat_retention_days']); ?>" min="1" max="365">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">
                        Threat logs older than this will be deleted during cleanup
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-ban"></i> Blocked IP Retention (days)
                    </label>
                    <input type="number" name="block_retention_days" class="form-control" 
                           value="<?php echo intval($current_settings['block_retention_days']); ?>" min="1" max="365">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">
                        Temporary blocks expire after this period
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-file-alt"></i> System Logs Retention (days)
                    </label>
                    <input type="number" name="log_retention_days" class="form-control" 
                           value="<?php echo intval($current_settings['log_retention_days']); ?>" min="1" max="365">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">
                        System and daemon logs retention period
                    </div>
                </div>
            </div>
            
            <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Retention Settings
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Daemon Settings -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-robot"></i> Daemon Settings
        </h3>
        <span class="badge badge-<?php echo $current_settings['daemon_enabled'] == '1' ? 'success' : 'warning'; ?>">
            <?php echo $current_settings['daemon_enabled'] == '1' ? 'Running' : 'Stopped'; ?>
        </span>
    </div>
    <div class="card-body">
        <form method="POST" action="">
            <input type="hidden" name="action" value="update_daemon_settings">
            
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
                    <input type="checkbox" name="daemon_enabled" value="1" <?php echo $current_settings['daemon_enabled'] == '1' ? 'checked' : ''; ?>
                           style="width: 18px; height: 18px; cursor: pointer;">
                    <div>
                        <div class="form-label" style="margin-bottom: 0.25rem;">
                            <i class="fas fa-play-circle"></i> Enable Background Daemon
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem;">Automatically monitor logs and detect threats in the background</div>
                    </div>
                </label>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.25rem; margin-top: 1.5rem;">
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-stopwatch"></i> Scan Interval (minutes)
                    </label>
                    <input type="number" name="daemon_interval" class="form-control" 
                           value="<?php echo intval($current_settings['daemon_interval_minutes']); ?>" min="1" max="60">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">
                        How often the daemon scans for new threats
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-file"></i> Log File Path
                    </label>
                    <input type="text" name="log_file_path" class="form-control" 
                           value="<?php echo htmlspecialchars($current_settings['log_file_path']); ?>" 
                           placeholder="/var/log/apache2/access.log">
                    <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">
                        Primary log file to monitor for threats
                    </div>
                </div>
            </div>
            
            <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Daemon Settings
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Notification Settings -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-bell"></i> Notification Settings
        </h3>
        <span class="badge badge-<?php echo $current_settings['email_notifications_enabled'] == '1' ? 'success' : 'info'; ?>">
            <?php echo $current_settings['email_notifications_enabled'] == '1' ? 'Active' : 'Inactive'; ?>
        </span>
    </div>
    <div class="card-body">
        <form method="POST" action="">
            <input type="hidden" name="action" value="update_notification_settings">
            
            <div class="form-group">
                <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
                    <input type="checkbox" name="email_notifications" value="1" <?php echo $current_settings['email_notifications_enabled'] == '1' ? 'checked' : ''; ?>
                           style="width: 18px; height: 18px; cursor: pointer;">
                    <div>
                        <div class="form-label" style="margin-bottom: 0.25rem;">
                            <i class="fas fa-envelope"></i> Enable Email Notifications
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem;">Receive email alerts for important security events</div>
                    </div>
                </label>
            </div>
            
            <div class="form-group">
                <label class="form-label">
                    <i class="fas fa-at"></i> Notification Email Address
                </label>
                <input type="email" name="notification_email" class="form-control" 
                       value="<?php echo htmlspecialchars($current_settings['notification_email']); ?>" 
                       placeholder="security@example.com">
                <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.25rem;">
                    Email address to receive security notifications
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-top: 1rem;">
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                        <input type="checkbox" name="notify_on_critical" value="1" <?php echo $current_settings['notify_on_critical_threats'] == '1' ? 'checked' : ''; ?>
                               style="width: 16px; height: 16px; cursor: pointer;">
                        <span style="font-size: 0.875rem;">
                            <i class="fas fa-exclamation-triangle"></i> Notify on critical threats
                        </span>
                    </label>
                </div>
                
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                        <input type="checkbox" name="notify_on_block" value="1" <?php echo $current_settings['notify_on_ip_block'] == '1' ? 'checked' : ''; ?>
                               style="width: 16px; height: 16px; cursor: pointer;">
                        <span style="font-size: 0.875rem;">
                            <i class="fas fa-ban"></i> Notify when IPs are blocked
                        </span>
                    </label>
                </div>
            </div>
            
            <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Notification Settings
                </button>
            </div>
        </form>
    </div>
</div>

<!-- System Information -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-info-circle"></i> System Information
        </h3>
    </div>
    <div class="card-body">
        <div style="display: grid; gap: 0.75rem;">
            <?php
            // Get system info
            $system_info = [
                'WAF Version' => 'SMV WAF 1.0.0',
                'PHP Version' => phpversion(),
                'Database Server' => $db->server_info,
                'Database Name' => $db_name,
                'Server Time' => date('Y-m-d H:i:s'),
                'Timezone' => date_default_timezone_get(),
                'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
            ];
            
            foreach ($system_info as $label => $value):
            ?>
            <div style="display: grid; grid-template-columns: 220px 1fr; gap: 1rem; padding: 0.75rem; background: rgba(59, 130, 246, 0.03); border-radius: 6px;">
                <div style="color: var(--text-muted); font-weight: 600; font-size: 0.875rem;">
                    <?php echo $label; ?>
                </div>
                <div style="color: var(--text); font-family: monospace; font-size: 0.875rem;">
                    <?php echo htmlspecialchars($value); ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<!-- Maintenance Actions -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">
            <i class="fas fa-tools"></i> Maintenance
        </h3>
    </div>
    <div class="card-body">
        <form method="POST" action="">
            <input type="hidden" name="action" value="cleanup_old_data">
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: rgba(59, 130, 246, 0.05); border-radius: 6px; border: 1px solid var(--border);">
                <div>
                    <div style="color: var(--text); font-weight: 600; margin-bottom: 0.25rem;">
                        <i class="fas fa-broom"></i> Cleanup Old Data
                    </div>
                    <div style="color: var(--text-muted); font-size: 0.875rem;">
                        Remove threats older than <?php echo intval($current_settings['threat_retention_days']); ?> days and expired IP blocks
                    </div>
                    <?php if ($db_stats['old_threats'] > 0 || $db_stats['expired_blocks'] > 0): ?>
                    <div style="margin-top: 0.5rem; padding: 0.5rem; background: rgba(251, 191, 36, 0.1); border-radius: 4px;">
                        <span class="badge badge-warning" style="margin-right: 0.5rem;">
                            <?php echo $db_stats['old_threats']; ?> old threat(s)
                        </span>
                        <span class="badge badge-warning">
                            <?php echo $db_stats['expired_blocks']; ?> expired block(s)
                        </span>
                    </div>
                    <?php endif; ?>
                </div>
                <button type="submit" class="btn btn-secondary" onclick="return confirm('This will permanently delete old data. Continue?')">
                    <i class="fas fa-broom"></i> Run Cleanup
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Danger Zone -->
<div class="card" style="border-color: rgba(239, 68, 68, 0.3);">
    <div class="card-header" style="border-bottom-color: rgba(239, 68, 68, 0.3);">
        <h3 class="card-title" style="color: var(--danger);">
            <i class="fas fa-exclamation-triangle"></i> Danger Zone
        </h3>
    </div>
    <div class="card-body">
        <!-- Clear Threat Logs -->
        <div style="margin-bottom: 1rem;">
            <div style="padding: 1rem; background: rgba(239, 68, 68, 0.05); border-radius: 6px; border: 1px solid rgba(239, 68, 68, 0.2);">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                        <div style="color: var(--text); font-weight: 600; margin-bottom: 0.25rem;">
                            <i class="fas fa-trash-alt"></i> Clear All Threat Logs
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem; margin-bottom: 0.75rem;">
                            Permanently delete all <?php echo number_format($db_stats['total_threats']); ?> threat detection logs from the database
                        </div>
                        <form method="POST" action="" style="display: flex; gap: 0.75rem; align-items: end;">
                            <input type="hidden" name="action" value="clear_threat_logs">
                            <div style="flex: 1; max-width: 200px;">
                                <label style="display: block; color: var(--text-muted); font-size: 0.75rem; margin-bottom: 0.25rem;">
                                    Type <strong>CLEAR</strong> to confirm
                                </label>
                                <input type="text" name="confirm_clear" class="form-control" placeholder="CLEAR" required>
                            </div>
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-trash"></i> Clear Logs
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Unblock All IPs -->
        <div>
            <div style="padding: 1rem; background: rgba(239, 68, 68, 0.05); border-radius: 6px; border: 1px solid rgba(239, 68, 68, 0.2);">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                        <div style="color: var(--text); font-weight: 600; margin-bottom: 0.25rem;">
                            <i class="fas fa-unlock"></i> Unblock All IPs
                        </div>
                        <div style="color: var(--text-muted); font-size: 0.875rem; margin-bottom: 0.75rem;">
                            Remove all <?php echo number_format($db_stats['total_blocks']); ?> IP addresses from the block list
                        </div>
                        <form method="POST" action="" style="display: flex; gap: 0.75rem; align-items: end;">
                            <input type="hidden" name="action" value="unblock_all_ips">
                            <div style="flex: 1; max-width: 200px;">
                                <label style="display: block; color: var(--text-muted); font-size: 0.75rem; margin-bottom: 0.25rem;">
                                    Type <strong>UNBLOCK</strong> to confirm
                                </label>
                                <input type="text" name="confirm_unblock" class="form-control" placeholder="UNBLOCK" required>
                            </div>
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-unlock"></i> Unblock All
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
