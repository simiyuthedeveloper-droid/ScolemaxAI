<?php
/**
 * SMV Security - ScoleMax Control Center API Client
 * Handles all communication with the Threat Response Center
 */

class ScoleMaxControlAPI {
    
    private $baseUrl;
    private $apiKey;
    private $apiSecret;
    private $timeout = 15;
    private $logger;
    
    /**
     * Constructor
     */
    public function __construct($baseUrl = null, $apiKey = null, $apiSecret = null) {
        // Load from config if not provided
        if (function_exists('getConfig')) {
            $this->baseUrl = $baseUrl ?? getConfig('control_center_url', '');
            $this->apiKey = $apiKey ?? getConfig('api_key', '');
            $this->apiSecret = $apiSecret ?? getConfig('api_secret', '');
        } else {
            // Fallback if getConfig not available
            $this->baseUrl = $baseUrl ?? (defined('CONTROL_CENTER_URL') ? CONTROL_CENTER_URL : '');
            $this->apiKey = $apiKey ?? (defined('API_KEY') ? API_KEY : '');
            $this->apiSecret = $apiSecret ?? (defined('API_SECRET') ? API_SECRET : '');
        }
        
        // Initialize logger if available
        if (class_exists('Logger')) {
            $this->logger = new Logger();
        }
    }
    
    /**
     * Generate HMAC signature for request (as per API documentation)
     */
    private function generateSignature($timestamp) {
        $message = $this->apiKey . $timestamp . $this->apiSecret;
        return hash_hmac('sha256', $message, $this->apiSecret);
    }
    
    /**
     * Make API request
     */
    private function makeRequest($endpoint, $method = 'GET', $data = null) {
        try {
            $url = rtrim($this->baseUrl, '/') . '/integrations/waf.php' . $endpoint;
            
            // Generate timestamp and signature
            $timestamp = date('c'); // ISO 8601 format
            $signature = $this->generateSignature($timestamp);
            
            $ch = curl_init();
            
            $headers = [
                'Content-Type: application/json',
                'Accept: application/json',
                'X-API-Key: ' . $this->apiKey,
                'X-API-Secret: ' . $this->apiSecret,
                'X-Timestamp: ' . $timestamp,
                'X-Signature: ' . $signature
            ];
            
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3
            ]);
            
            if ($method === 'POST' && $data !== null) {
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            }
            
            $startTime = microtime(true);
            $response = curl_exec($ch);
            $responseTime = round((microtime(true) - $startTime) * 1000);
            
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            curl_close($ch);
            
            // Log the request
            if ($this->logger) {
                $this->logger->logAPISync(
                    $endpoint,
                    $method,
                    $httpCode === 200 && empty($curlError),
                    $responseTime,
                    $curlError
                );
            }
            
            if ($curlError) {
                throw new Exception("cURL Error: $curlError");
            }
            
            // Check if response is JSON
            if (stripos($contentType, 'application/json') === false && 
                stripos($contentType, 'text/json') === false) {
                throw new Exception("Invalid response format. Server returned: " . substr($contentType, 0, 100));
            }
            
            if ($httpCode !== 200) {
                throw new Exception("HTTP Error $httpCode");
            }
            
            $responseData = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("Invalid JSON response: " . json_last_error_msg());
            }
            
            return $responseData;
            
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error("API Request failed: " . $e->getMessage());
            }
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Test connection (ping)
     */
    public function ping() {
        return $this->makeRequest('?action=ping', 'GET');
    }
    
    /**
     * Register server with Control Center (NEW)
     * Call this on initial setup or periodically as heartbeat
     */
    public function registerServer($serverInfo = null) {
        // Prepare server information if not provided
        if ($serverInfo === null) {
            $serverInfo = [
                'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
                'server_ip' => $_SERVER['SERVER_ADDR'] ?? null,
                'server_name' => $_SERVER['SERVER_NAME'] ?? null,
                'php_version' => PHP_VERSION,
                'mysql_version' => function_exists('mysqli_get_client_info') ? mysqli_get_client_info() : 'unknown',
                'waf_version' => defined('WAF_VERSION') ? WAF_VERSION : '1.0.0',
                'server_timezone' => date_default_timezone_get(),
                'server_os' => PHP_OS
            ];
        }
        
        $response = $this->makeRequest('?action=register_server', 'POST', $serverInfo);
        
        // Log to database
        if (function_exists('getDB')) {
            try {
                $db = getDB();
                $success = isset($response['success']) && $response['success'] === true ? 1 : 0;
                $message = '';
                
                if ($success && isset($response['data'])) {
                    $data = $response['data'];
                    $action = $data['action'] ?? 'unknown';
                    $message = $data['message'] ?? 'Server ' . $action;
                } else {
                    $message = $response['error'] ?? 'Server registration failed';
                }
                
                $stmt = $db->prepare(
                    "INSERT INTO sync_log (sync_type, success, threats_sent, response_message, created_at) 
                    VALUES ('server_registration', ?, 0, ?, NOW())"
                );
                $stmt->bind_param('is', $success, $message);
                $stmt->execute();
            } catch (Exception $e) {
                // Non-critical
            }
        }
        
        return $response;
    }
    
    /**
     * Report threats to Control Center
     */
    public function reportThreats($threats) {
        $payload = [
            'threats' => $threats,
            'reported_at' => date('c'),
            // Include server info for auto-registration
            'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
            'server_ip' => $_SERVER['SERVER_ADDR'] ?? null
        ];
        
        $response = $this->makeRequest('?action=report_threats', 'POST', $payload);
        
        // Log to database
        if (function_exists('getDB')) {
            try {
                $db = getDB();
                $success = isset($response['success']) && $response['success'] === true ? 1 : 0;
                $threatsCount = is_array($threats) ? count($threats) : 0;
                $message = $response['message'] ?? ($response['error'] ?? 'Unknown error');
                
                $stmt = $db->prepare(
                    "INSERT INTO sync_log (sync_type, success, threats_sent, response_message, created_at) 
                    VALUES ('threat_report', ?, ?, ?, NOW())"
                );
                $stmt->bind_param('iis', $success, $threatsCount, $message);
                $stmt->execute();
            } catch (Exception $e) {
                // Non-critical
            }
        }
        
        return $response;
    }
    
    /**
     * Get threat feed from Control Center
     */
    public function getThreatFeed($limit = 100, $threatType = null, $severity = null) {
        $params = '?action=get_feed&limit=' . intval($limit);
        
        if ($threatType) {
            $params .= '&threat_type=' . urlencode($threatType);
        }
        
        if ($severity) {
            $params .= '&severity=' . urlencode($severity);
        }
        
        $response = $this->makeRequest($params, 'GET');
        
        // Log to database
        if (function_exists('getDB')) {
            try {
                $db = getDB();
                $success = isset($response['success']) && $response['success'] === true ? 1 : 0;
                $feedCount = isset($response['count']) ? intval($response['count']) : 0;
                $message = $response['message'] ?? ($response['error'] ?? 'Threat feed retrieved');
                
                $stmt = $db->prepare(
                    "INSERT INTO sync_log (sync_type, success, threats_sent, response_message, created_at) 
                    VALUES ('threat_feed', ?, ?, ?, NOW())"
                );
                $stmt->bind_param('iis', $success, $feedCount, $message);
                $stmt->execute();
            } catch (Exception $e) {
                // Non-critical
            }
        }
        
        return $response;
    }
    
    /**
     * Get firewall rules from Control Center
     */
    public function getRules() {
        $response = $this->makeRequest('?action=get_rules', 'GET');
        
        // Log to database
        if (function_exists('getDB')) {
            try {
                $db = getDB();
                $success = isset($response['success']) && $response['success'] === true ? 1 : 0;
                $rulesCount = isset($response['count']) ? intval($response['count']) : 0;
                $message = "Retrieved $rulesCount rules";
                
                $stmt = $db->prepare(
                    "INSERT INTO sync_log (sync_type, success, threats_sent, response_message, created_at) 
                    VALUES ('rules_sync', ?, ?, ?, NOW())"
                );
                $stmt->bind_param('iis', $success, $rulesCount, $message);
                $stmt->execute();
            } catch (Exception $e) {
                // Non-critical
            }
        }
        
        return $response;
    }
    
    /**
     * Analyze threat using AI
     */
    public function analyzeThreat($threat) {
        return $this->makeRequest('?action=analyze', 'POST', [
            'threat' => $threat
        ]);
    }
    
    /**
     * Report IP block action
     */
    public function reportBlock($ip, $reason, $threatType) {
        return $this->makeRequest('?action=report_block', 'POST', [
            'ip' => $ip,
            'reason' => $reason,
            'threat_type' => $threatType
        ]);
    }
    
    /**
     * Sync configuration
     */
    public function syncConfig() {
        return $this->makeRequest('?action=sync_config', 'POST');
    }
    
    /**
     * Get API connection status
     */
    public function getConnectionStatus() {
        $status = [
            'configured' => false,
            'connected' => false,
            'server_registered' => false,
            'last_sync' => null,
            'error' => null
        ];
        
        // Check if credentials are configured
        if (empty($this->baseUrl) || empty($this->apiKey) || empty($this->apiSecret)) {
            $status['error'] = 'API credentials not configured';
            return $status;
        }
        
        $status['configured'] = true;
        
        // Test connection
        $pingResponse = $this->ping();
        
        if (isset($pingResponse['success']) && $pingResponse['success'] === true) {
            $status['connected'] = true;
            
            // Try to register/update server
            $registerResponse = $this->registerServer();
            if (isset($registerResponse['success']) && $registerResponse['success'] === true) {
                $status['server_registered'] = true;
            }
        } else {
            $status['error'] = $pingResponse['error'] ?? 'Connection failed';
        }
        
        // Get last sync time from database
        if (function_exists('getDB')) {
            try {
                $db = getDB();
                $result = $db->query(
                    "SELECT created_at FROM sync_log 
                    ORDER BY created_at DESC LIMIT 1"
                );
                
                if ($row = $result->fetch_assoc()) {
                    $status['last_sync'] = $row['created_at'];
                }
            } catch (Exception $e) {
                // Non-critical
            }
        }
        
        return $status;
    }
    
    /**
     * Auto-report threats (called by daemon)
     */
    public function autoReportThreats($sinceLast = '1 hour') {
        // Check if auto-reporting is enabled
        $autoReport = function_exists('getConfig') ? getConfig('auto_report_threats', '1') : '1';
        
        if ($autoReport !== '1') {
            return [
                'success' => false,
                'message' => 'Auto-reporting is disabled'
            ];
        }
        
        // Get unreported threats from database
        if (!function_exists('getDB')) {
            return [
                'success' => false,
                'message' => 'Database not available'
            ];
        }
        
        try {
            $db = getDB();
            
            // Get threats that haven't been reported yet
            $result = $db->query(
                "SELECT id, threat_type, severity, source_ip, target_path, detected_at 
                FROM local_threats 
                WHERE reported_to_control = 0 
                AND detected_at >= DATE_SUB(NOW(), INTERVAL $sinceLast)
                LIMIT 100"
            );
            
            if ($result->num_rows == 0) {
                return [
                    'success' => true,
                    'message' => 'No new threats to report'
                ];
            }
            
            $threats = [];
            $threatIds = [];
            
            while ($row = $result->fetch_assoc()) {
                $threats[] = [
                    'threat_type' => $row['threat_type'],
                    'severity' => $row['severity'],
                    'source_ip' => $row['source_ip'],
                    'target_path' => $row['target_path'] ?? '',
                    'reported_at' => $row['detected_at']
                ];
                $threatIds[] = $row['id'];
            }
            
            // Report to Control Center
            $response = $this->reportThreats($threats);
            
            // Mark as reported if successful
            if (isset($response['success']) && $response['success'] === true) {
                $idsStr = implode(',', $threatIds);
                $db->query(
                    "UPDATE local_threats 
                    SET reported_to_control = 1 
                    WHERE id IN ($idsStr)"
                );
                
                return [
                    'success' => true,
                    'message' => 'Reported ' . count($threats) . ' threats',
                    'count' => count($threats)
                ];
            }
            
            return $response;
            
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error("Auto-report failed: " . $e->getMessage());
            }
            
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Auto-sync threat feeds (called by daemon)
     */
    public function autoSyncFeeds() {
        // Check if auto-sync is enabled
        $autoSync = function_exists('getConfig') ? getConfig('auto_sync_feeds', '1') : '1';
        
        if ($autoSync !== '1') {
            return [
                'success' => false,
                'message' => 'Auto-sync is disabled'
            ];
        }
        
        // Get threat feed
        $response = $this->getThreatFeed(500);
        
        if (!isset($response['success']) || $response['success'] !== true) {
            return $response;
        }
        
        // Apply threat feed to local database
        if (!function_exists('getDB') || !isset($response['threat_feed'])) {
            return $response;
        }
        
        try {
            $db = getDB();
            $applied = 0;
            
            foreach ($response['threat_feed'] as $threat) {
                // Check if IP should be blocked
                if (isset($threat['should_block']) && $threat['should_block'] === true) {
                    // Check if already blocked
                    $ipHash = $threat['source_ip_hash'] ?? '';
                    
                    $check = $db->query(
                        "SELECT id FROM blocked_ips 
                        WHERE ip_hash = '$ipHash' 
                        LIMIT 1"
                    );
                    
                    if ($check->num_rows == 0) {
                        // Block the IP
                        $threatType = $threat['threat_type'] ?? 'unknown';
                        $severity = $threat['severity'] ?? 'medium';
                        $reason = "Auto-blocked from threat feed ($threatType, reported {$threat['report_count']} times)";
                        
                        $stmt = $db->prepare(
                            "INSERT INTO blocked_ips (ip_hash, reason, threat_type, blocked_at, block_source) 
                            VALUES (?, ?, ?, NOW(), 'control_center_feed')"
                        );
                        $stmt->bind_param('sss', $ipHash, $reason, $threatType);
                        $stmt->execute();
                        
                        $applied++;
                    }
                }
            }
            
            return [
                'success' => true,
                'message' => "Synced threat feed, applied $applied blocks",
                'received' => count($response['threat_feed']),
                'applied' => $applied
            ];
            
        } catch (Exception $e) {
            if ($this->logger) {
                $this->logger->error("Feed sync failed: " . $e->getMessage());
            }
            
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}
