<?php
/**
 * SMV Security - WAF Daemon
 * Threat detection and blocking engine
 * Runs every 5 minutes via cron job
 * 
 * Usage: php daemon.php
 * Or via cron: */5 * * * * php /path/to/daemon.php
 */

// ============================================================
// 1. INITIALIZATION
// ============================================================

// Start execution timer
$startTime = microtime(true);

// Define base directory
define('BASE_DIR', __DIR__);
define('DAEMON_LOG', BASE_DIR . '/logs/daemon.log');
define('THREAT_LOG', BASE_DIR . '/logs/threats.log');

// Load configuration
require_once BASE_DIR . '/config.php';

// Set execution time
set_time_limit(DAEMON_TIMEOUT);

// Ensure we're not already running
$lockFile = BASE_DIR . '/logs/.daemon.lock';
if (file_exists($lockFile)) {
    $lockAge = time() - filemtime($lockFile);
    if ($lockAge < DAEMON_INTERVAL * 60) {
        logDaemon("Daemon already running (lock file exists)", 'warning');
        exit(0);
    }
    @unlink($lockFile);
}

// Create lock file
touch($lockFile);

// ============================================================
// 2. DAEMON CLASS
// ============================================================

class WAFDaemon {
    private $db;
    private $startTime;
    private $logsScanned = 0;
    private $threatsDetected = 0;
    private $rulesApplied = 0;
    private $errors = [];
    
    public function __construct() {
        try {
            $this->db = getDB();
            $this->startTime = microtime(true);
        } catch (Exception $e) {
            logDaemon("Failed to initialize daemon: " . $e->getMessage(), 'error');
            exit(1);
        }
    }
    
    /**
     * Run daemon cycle
     */
    public function run() {
        logDaemon("Daemon started", 'info');
        
        try {
            // Step 1: Load active firewall rules
            $this->loadRules();
            
            // Step 2: Load threat feed from Control Center
            $this->loadThreatFeed();
            
            // Step 3: Scan server logs
            $this->scanLogs();
            
            // Step 4: Apply firewall rules
            $this->applyRules();
            
            // Step 5: Report to Control Center
            $this->reportToControlCenter();
            
            // Step 6: Cleanup old data
            $this->cleanup();
            
            // Log execution
            $this->logExecution('success');
            
            logDaemon("Daemon completed successfully", 'info');
            
        } catch (Exception $e) {
            logDaemon("Daemon error: " . $e->getMessage(), 'error');
            $this->logExecution('error', $e->getMessage());
        }
    }
    
    /**
     * Load active firewall rules from database
     */
    private function loadRules() {
        try {
            $stmt = $this->db->prepare(
                "SELECT id, rule_type, match_ip, match_pattern, action FROM firewall_rules WHERE is_active = 1 ORDER BY priority DESC"
            );
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            $ruleCount = 0;
            while ($row = $result->fetch_assoc()) {
                $ruleCount++;
            }
            
            logDaemon("Loaded $ruleCount active firewall rules", 'info');
            
        } catch (Exception $e) {
            logDaemon("Error loading rules: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Load threat feed from Control Center
     */
    private function loadThreatFeed() {
        if (!CONTROL_CENTER_URL || !API_KEY) {
            logDaemon("Control Center not configured, skipping threat feed", 'warning');
            return;
        }
        
        try {
            $url = CONTROL_CENTER_URL . CONTROL_CENTER_FEED_ENDPOINT;
            
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'X-API-Key: ' . API_KEY,
                'X-API-Secret: ' . API_SECRET,
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);
                
                if (isset($data['threat_feed']) && is_array($data['threat_feed'])) {
                    $this->cacheThreatFeed($data['threat_feed']);
                    logDaemon("Cached " . count($data['threat_feed']) . " threats from network", 'info');
                }
            }
            
        } catch (Exception $e) {
            logDaemon("Error loading threat feed: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Cache threat feed in database
     */
    private function cacheThreatFeed($threats) {
        foreach ($threats as $threat) {
            try {
                $stmt = $this->db->prepare(
                    "INSERT INTO threat_feed_cache 
                    (source_ip_hash, threat_type, severity, source_country, report_count, should_block)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE 
                    report_count = ?, last_seen = NOW(), should_block = ?"
                );
                
                $ipHash = $threat['source_ip_hash'] ?? '';
                $threatType = $threat['threat_type'] ?? '';
                $severity = $threat['severity'] ?? '';
                $country = $threat['source_country'] ?? '';
                $reportCount = intval($threat['report_count'] ?? 1);
                $shouldBlock = intval($threat['should_block'] ?? 0);
                
                $stmt->bind_param(
                    'ssssiiiii',
                    $ipHash, $threatType, $severity, $country, $reportCount, $shouldBlock,
                    $reportCount, $shouldBlock
                );
                
                $stmt->execute();
                
            } catch (Exception $e) {
                // Continue processing other threats
            }
        }
    }
    
    /**
     * Scan server logs for threats
     */
    private function scanLogs() {
        $logFiles = LOG_FILES;
        $threatPatterns = $this->getThreatPatterns();
        
        foreach ($logFiles as $logFile) {
            if (!file_exists($logFile)) {
                continue;
            }
            
            try {
                // Get last scan position from cache
                $lastPos = $this->getLastLogPosition($logFile);
                $currentSize = filesize($logFile);
                
                // Skip if file hasn't grown
                if ($lastPos >= $currentSize) {
                    continue;
                }
                
                // Read new lines
                $handle = fopen($logFile, 'r');
                fseek($handle, $lastPos);
                
                $lineCount = 0;
                while (!feof($handle) && $lineCount < LOG_SCAN_BATCH_SIZE) {
                    $line = fgets($handle);
                    if ($line) {
                        $lineCount++;
                        $this->logsScanned++;
                        
                        // Analyze line for threats
                        $threat = $this->analyzeLine($line, $threatPatterns);
                        if ($threat) {
                            $this->threatsDetected++;
                            $this->storeThreat($threat);
                        }
                    }
                }
                
                // Save new position
                $newPos = ftell($handle);
                $this->saveLastLogPosition($logFile, $newPos);
                
                fclose($handle);
                
            } catch (Exception $e) {
                logDaemon("Error scanning $logFile: " . $e->getMessage(), 'warning');
            }
        }
        
        logDaemon("Scanned $this->logsScanned log lines, detected $this->threatsDetected threats", 'info');
    }
    
    /**
     * Get threat patterns from database
     */
    private function getThreatPatterns() {
        try {
            $stmt = $this->db->prepare(
                "SELECT pattern_type, pattern_regex, severity FROM attack_patterns WHERE is_active = 1"
            );
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            $patterns = [];
            while ($row = $result->fetch_assoc()) {
                $patterns[] = $row;
            }
            
            return $patterns;
            
        } catch (Exception $e) {
            logDaemon("Error getting patterns: " . $e->getMessage(), 'warning');
            return [];
        }
    }
    
    /**
     * Analyze log line for threats
     */
    private function analyzeLine($line, $patterns) {
        // Skip binary lines and very short lines
        if (strlen($line) < 20 || !mb_check_encoding($line, 'UTF-8')) {
            return null;
        }
        
        // Parse Apache/Nginx log format: IP REQUEST USERAGENT
        $matches = [];
        if (!preg_match('/^(\S+)\s+.*"(\w+)\s+(\S+)\s+HTTP.*".*"([^"]*)"/', $line, $matches)) {
            return null;
        }
        
        $sourceIP = $matches[1] ?? '';
        $method = $matches[2] ?? '';
        $path = $matches[3] ?? '';
        $userAgent = $matches[4] ?? '';
        
        // Check against threat patterns
        foreach ($patterns as $pattern) {
            if (!empty($pattern['pattern_regex'])) {
                if (@preg_match('/' . $pattern['pattern_regex'] . '/i', $line)) {
                    return [
                        'threat_type' => $pattern['pattern_type'],
                        'severity' => $pattern['severity'],
                        'source_ip' => $sourceIP,
                        'target_path' => $path,
                        'request_method' => $method,
                        'user_agent' => $userAgent,
                        'attack_pattern' => substr($line, 0, 255),
                        'detected_at' => date('Y-m-d H:i:s'),
                    ];
                }
            }
        }
        
        return null;
    }
    
    /**
     * Store detected threat
     */
    private function storeThreat($threat) {
        try {
            $sourceIPHash = hash('sha256', $threat['source_ip']);
            
            $stmt = $this->db->prepare(
                "INSERT INTO local_threats 
                (threat_type, severity, source_ip, source_ip_hash, target_path, 
                 request_method, user_agent, attack_pattern, action_taken, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            );
            
            $actionTaken = AUTO_BLOCK_ENABLED ? 'blocked' : 'logged';
            
            $stmt->bind_param(
                'sssssssss',
                $threat['threat_type'],
                $threat['severity'],
                $threat['source_ip'],
                $sourceIPHash,
                $threat['target_path'],
                $threat['request_method'],
                $threat['user_agent'],
                $threat['attack_pattern'],
                $actionTaken,
                $threat['detected_at']
            );
            
            if ($stmt->execute()) {
                logThreat(
                    $threat['threat_type'],
                    $threat['severity'],
                    $threat['source_ip'],
                    $threat['target_path']
                );
                
                // Auto-block if enabled
                if (AUTO_BLOCK_ENABLED && $threat['severity'] === 'critical') {
                    $this->blockIP($threat['source_ip'], $threat['threat_type']);
                }
            }
            
        } catch (Exception $e) {
            logDaemon("Error storing threat: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Block IP address
     */
    private function blockIP($ip, $reason) {
        try {
            $stmt = $this->db->prepare(
                "INSERT IGNORE INTO blocked_ips (ip_address, reason, threat_type, block_type, blocked_at)
                VALUES (?, ?, ?, 'temporary', NOW())"
            );
            
            $blockType = 'temporary';
            $stmt->bind_param('sss', $ip, $reason, $reason);
            $stmt->execute();
            
            // Apply to firewall
            $this->applyIPBlock($ip);
            
        } catch (Exception $e) {
            logDaemon("Error blocking IP: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Apply IP block to firewall
     */
    private function applyIPBlock($ip) {
        // Try to update .htaccess
        $htaccessFile = BASE_DIR . '/.htaccess.smv';
        
        if (file_exists($htaccessFile)) {
            try {
                $content = file_get_contents($htaccessFile);
                
                // Check if IP already blocked
                if (strpos($content, $ip) === false) {
                    // Add deny rule
                    $denyRule = "\nDeny from $ip # SMV WAF Auto-Block\n";
                    file_put_contents($htaccessFile, $denyRule, FILE_APPEND);
                    
                    $this->rulesApplied++;
                    logDaemon("Applied block for IP: $ip", 'info');
                }
            } catch (Exception $e) {
                logDaemon("Error applying IP block: " . $e->getMessage(), 'warning');
            }
        }
    }
    
    /**
     * Apply firewall rules
     */
    private function applyRules() {
        try {
            $stmt = $this->db->prepare(
                "SELECT COUNT(*) as count FROM firewall_rules WHERE is_active = 1"
            );
            
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            $this->rulesApplied = $row['count'] ?? 0;
            logDaemon("Applied $this->rulesApplied firewall rules", 'info');
            
        } catch (Exception $e) {
            logDaemon("Error applying rules: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Report threats to Control Center
     */
    private function reportToControlCenter() {
        if (!CONTROL_CENTER_URL || !API_KEY) {
            logDaemon("Control Center not configured, skipping report", 'warning');
            return;
        }
        
        try {
            // Get unreported threats
            $stmt = $this->db->prepare(
                "SELECT id, threat_type, severity, source_ip, source_ip_hash, target_path, 
                        target_service, attack_pattern, request_method, user_agent, detected_at
                FROM local_threats
                WHERE reported_to_control = 0
                LIMIT 50"
            );
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            $threats = [];
            $threatIDs = [];
            
            while ($row = $result->fetch_assoc()) {
                $threats[] = $row;
                $threatIDs[] = $row['id'];
            }
            
            if (empty($threats)) {
                logDaemon("No threats to report", 'info');
                return;
            }
            
            // Send to Control Center
            $url = CONTROL_CENTER_URL . CONTROL_CENTER_REPORT_ENDPOINT;
            
            $data = json_encode([
                'threats' => $threats,
            ]);
            
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'X-API-Key: ' . API_KEY,
                'X-API-Secret: ' . API_SECRET,
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);
            
            if ($httpCode === 200) {
                // Mark as reported
                $ids = implode(',', array_map('intval', $threatIDs));
                $this->db->query("UPDATE local_threats SET reported_to_control = 1, reported_at = NOW() WHERE id IN ($ids)");
                
                logDaemon("Reported " . count($threats) . " threats to Control Center", 'info');
            } else {
                logDaemon("Failed to report threats: HTTP $httpCode - $error", 'warning');
            }
            
        } catch (Exception $e) {
            logDaemon("Error reporting to Control Center: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Cleanup old data
     */
    private function cleanup() {
        try {
            // Delete old threats
            $stmt = $this->db->prepare(
                "DELETE FROM local_threats WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)"
            );
            
            $days = THREAT_RETENTION_DAYS;
            $stmt->bind_param('i', $days);
            $stmt->execute();
            
            // Delete expired blocks
            $stmt = $this->db->prepare(
                "DELETE FROM blocked_ips WHERE block_type = 'temporary' AND expires_at < NOW()"
            );
            $stmt->execute();
            
            logDaemon("Cleanup completed", 'info');
            
        } catch (Exception $e) {
            logDaemon("Error during cleanup: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Get last log position
     */
    private function getLastLogPosition($logFile) {
        try {
            $stmt = $this->db->prepare(
                "SELECT config_value FROM config WHERE config_key = ?"
            );
            
            $key = 'log_pos_' . md5($logFile);
            $stmt->bind_param('s', $key);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            return intval($row['config_value'] ?? 0);
            
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * Save last log position
     */
    private function saveLastLogPosition($logFile, $position) {
        try {
            $key = 'log_pos_' . md5($logFile);
            setConfig($key, (string)$position);
        } catch (Exception $e) {
            // Non-critical
        }
    }
    
    /**
     * Log execution to database
     */
    private function logExecution($status, $error = '') {
        try {
            $duration = round((microtime(true) - $this->startTime) * 1000);
            
            $stmt = $this->db->prepare(
                "INSERT INTO daemon_logs (execution_time, execution_duration_ms, logs_scanned, threats_detected, rules_applied, status, error_message)
                VALUES (NOW(), ?, ?, ?, ?, ?, ?)"
            );
            
            $stmt->bind_param(
                'iiiiiss',
                $duration,
                $this->logsScanned,
                $this->threatsDetected,
                $this->rulesApplied,
                $status,
                $error
            );
            
            $stmt->execute();
            
        } catch (Exception $e) {
            // Non-critical
        }
    }
}

// ============================================================
// 3. HELPER FUNCTIONS
// ============================================================

/**
 * Log daemon message
 */
function logDaemon($message, $type = 'info') {
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] [$type] $message\n";
    error_log($log_entry, 3, DAEMON_LOG);
}

/**
 * Log threat
 */
function logThreat($threat_type, $severity, $source_ip, $details = '') {
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] $threat_type | $severity | $source_ip | $details\n";
    error_log($log_entry, 3, THREAT_LOG);
}

// ============================================================
// 4. RUN DAEMON
// ============================================================

try {
    $daemon = new WAFDaemon();
    $daemon->run();
    
} catch (Exception $e) {
    logDaemon("Fatal error: " . $e->getMessage(), 'error');
    exit(1);
    
} finally {
    // Remove lock file
    if (file_exists($lockFile)) {
        @unlink($lockFile);
    }
}

?>
