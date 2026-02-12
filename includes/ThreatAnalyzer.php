<?php
/**
 * SMV Security - Threat Analyzer Class
 * 
 * Analyzes detected threats in detail
 * Scores severity, determines blocking action
 * Extracts threat intelligence
 */

class ThreatAnalyzer {
    
    private $db;
    private $threat;
    private $analysis = [];
    
    /**
     * Constructor
     */
    public function __construct($db) {
        $this->db = $db;
    }
    
    /**
     * Analyze a threat in detail
     */
    public function analyze($threatData) {
        $this->threat = $threatData;
        $this->analysis = [];
        
        try {
            // Extract threat characteristics
            $this->extractCharacteristics();
            
            // Score threat severity
            $this->scoreSeverity();
            
            // Determine blocking action
            $this->determineAction();
            
            // Extract intelligence
            $this->extractIntelligence();
            
            // Check for coordinated attacks
            $this->checkCoordinatedAttacks();
            
            return $this->analysis;
            
        } catch (Exception $e) {
            logDaemon("Error analyzing threat: " . $e->getMessage(), 'error');
            return null;
        }
    }
    
    /**
     * Extract threat characteristics
     */
    private function extractCharacteristics() {
        $threat = $this->threat;
        
        // Determine threat type confidence
        $typeConfidence = $this->calculateTypeConfidence($threat['threat_type']);
        
        // Check if IP is repeat offender
        $isRepeatOffender = $this->isRepeatOffender($threat['source_ip']);
        
        // Get attack frequency
        $attackFrequency = $this->getAttackFrequency($threat['source_ip']);
        
        // Check geographic location
        $geoData = $this->getGeoLocation($threat['source_ip']);
        
        $this->analysis['characteristics'] = [
            'threat_type' => $threat['threat_type'],
            'threat_type_confidence' => $typeConfidence,
            'source_ip' => $threat['source_ip'],
            'source_country' => $geoData['country'] ?? 'Unknown',
            'source_asn' => $geoData['asn'] ?? 'Unknown',
            'is_repeat_offender' => $isRepeatOffender,
            'attack_frequency' => $attackFrequency,
            'target_path' => $threat['target_path'] ?? '',
            'target_service' => $threat['target_service'] ?? 'Unknown',
            'user_agent' => substr($threat['user_agent'] ?? '', 0, 255),
            'request_method' => $threat['request_method'] ?? 'GET',
        ];
    }
    
    /**
     * Score threat severity
     */
    private function scoreSeverity() {
        $threat = $this->threat;
        $baseScore = 0;
        $factors = [];
        
        // Factor 1: Threat type severity
        $typeSeverity = [
            'sql_injection' => 9,
            'command_injection' => 10,
            'rce' => 10,
            'xss' => 6,
            'path_traversal' => 8,
            'brute_force' => 7,
            'ddos' => 8,
            'file_upload' => 7,
            'xxe' => 8,
            'csrf' => 5,
        ];
        
        $typeScore = $typeSeverity[$threat['threat_type']] ?? 5;
        $baseScore += $typeScore;
        $factors[] = ['factor' => 'threat_type', 'score' => $typeScore, 'weight' => 1.0];
        
        // Factor 2: Repeat offender
        if ($this->isRepeatOffender($threat['source_ip'])) {
            $repeatBonus = 2;
            $baseScore += $repeatBonus;
            $factors[] = ['factor' => 'repeat_offender', 'score' => $repeatBonus, 'weight' => 0.5];
        }
        
        // Factor 3: Attack frequency
        $frequency = $this->getAttackFrequency($threat['source_ip']);
        if ($frequency > 10) {
            $frequencyBonus = 3;
            $baseScore += $frequencyBonus;
            $factors[] = ['factor' => 'high_frequency', 'score' => $frequencyBonus, 'weight' => 0.4];
        }
        
        // Factor 4: Suspicious user agent
        if ($this->isSuspiciousUserAgent($threat['user_agent'] ?? '')) {
            $uaBonus = 1;
            $baseScore += $uaBonus;
            $factors[] = ['factor' => 'suspicious_user_agent', 'score' => $uaBonus, 'weight' => 0.2];
        }
        
        // Factor 5: Payload complexity
        $payloadScore = $this->analyzePayload($threat['attack_pattern'] ?? '');
        $baseScore += $payloadScore;
        $factors[] = ['factor' => 'payload_complexity', 'score' => $payloadScore, 'weight' => 0.3];
        
        // Normalize score to 0-10 scale
        $finalScore = min(10, $baseScore);
        
        // Determine severity level
        if ($finalScore >= 9) {
            $severityLevel = 'critical';
        } elseif ($finalScore >= 7) {
            $severityLevel = 'high';
        } elseif ($finalScore >= 5) {
            $severityLevel = 'medium';
        } else {
            $severityLevel = 'low';
        }
        
        $this->analysis['severity'] = [
            'score' => round($finalScore, 2),
            'level' => $severityLevel,
            'factors' => $factors,
            'confidence' => round((array_sum(array_column($factors, 'score')) / count($factors)) * 10, 2),
        ];
    }
    
    /**
     * Determine recommended action
     */
    private function determineAction() {
        $severity = $this->analysis['severity'];
        $characteristics = $this->analysis['characteristics'];
        
        $actions = [];
        $primaryAction = 'log_only';
        $blockType = null;
        
        // Critical threats - block immediately
        if ($severity['level'] === 'critical') {
            $actions[] = 'block_ip';
            $actions[] = 'alert_admin';
            $actions[] = 'escalate_to_control_center';
            $primaryAction = 'block_ip';
            $blockType = 'permanent';
        }
        // High severity - block or rate limit
        elseif ($severity['level'] === 'high') {
            if ($characteristics['is_repeat_offender']) {
                $actions[] = 'block_ip';
                $primaryAction = 'block_ip';
                $blockType = 'temporary';
            } else {
                $actions[] = 'rate_limit';
                $actions[] = 'alert_admin';
                $primaryAction = 'rate_limit';
            }
        }
        // Medium severity - rate limit
        elseif ($severity['level'] === 'medium') {
            $actions[] = 'rate_limit';
            $actions[] = 'log';
            $primaryAction = 'rate_limit';
        }
        // Low severity - log only
        else {
            $actions[] = 'log';
            $primaryAction = 'log_only';
        }
        
        $this->analysis['recommended_action'] = [
            'primary' => $primaryAction,
            'secondary' => $actions,
            'block_type' => $blockType,
            'reason' => $this->getActionReason($severity['level'], $characteristics),
        ];
    }
    
    /**
     * Extract threat intelligence
     */
    private function extractIntelligence() {
        $threat = $this->threat;
        $characteristics = $this->analysis['characteristics'];
        
        // Detect attack pattern family
        $patternFamily = $this->detectPatternFamily($threat['threat_type'], $threat['attack_pattern'] ?? '');
        
        // Extract IOCs (Indicators of Compromise)
        $iocs = $this->extractIOCs($threat);
        
        // Potential attribution
        $attribution = $this->getAttribution($characteristics['source_country'], $threat['threat_type']);
        
        $this->analysis['intelligence'] = [
            'pattern_family' => $patternFamily,
            'iocs' => $iocs,
            'attribution' => $attribution,
            'similar_campaigns' => $this->findSimilarCampaigns($threat),
            'ttps' => $this->extractTTPs($threat['threat_type']),
        ];
    }
    
    /**
     * Check for coordinated attacks
     */
    private function checkCoordinatedAttacks() {
        try {
            $threat = $this->threat;
            $sourceIP = $threat['source_ip'];
            
            // Find similar threats from other IPs in last hour
            $stmt = $this->db->prepare(
                "SELECT COUNT(DISTINCT source_ip) as ip_count, threat_type, COUNT(*) as attack_count
                FROM local_threats
                WHERE threat_type = ? AND detected_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                AND source_ip != ?
                GROUP BY threat_type"
            );
            
            $threatType = $threat['threat_type'];
            $stmt->bind_param('ss', $threatType, $sourceIP);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            $isCoordinated = false;
            $coordinatedCount = 0;
            
            if ($row && $row['ip_count'] >= 3) {
                $isCoordinated = true;
                $coordinatedCount = $row['ip_count'];
            }
            
            $this->analysis['coordination'] = [
                'is_coordinated_attack' => $isCoordinated,
                'participating_ips' => $coordinatedCount,
                'attack_type' => $threatType,
                'time_window' => '1 hour',
            ];
            
        } catch (Exception $e) {
            $this->analysis['coordination'] = [
                'is_coordinated_attack' => false,
                'participating_ips' => 0,
            ];
        }
    }
    
    /**
     * Calculate type confidence
     */
    private function calculateTypeConfidence($threatType) {
        $typeConfidence = [
            'sql_injection' => 0.95,
            'xss' => 0.88,
            'brute_force' => 0.92,
            'path_traversal' => 0.85,
            'command_injection' => 0.98,
            'ddos' => 0.80,
            'file_upload' => 0.87,
        ];
        
        return $typeConfidence[$threatType] ?? 0.75;
    }
    
    /**
     * Check if IP is repeat offender
     */
    private function isRepeatOffender($ip) {
        try {
            $stmt = $this->db->prepare(
                "SELECT COUNT(*) as count FROM local_threats 
                WHERE source_ip = ? AND detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
            );
            
            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            return $row['count'] >= 2;
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Get attack frequency
     */
    private function getAttackFrequency($ip) {
        try {
            $stmt = $this->db->prepare(
                "SELECT COUNT(*) as count FROM local_threats 
                WHERE source_ip = ? AND detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
            );
            
            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            return intval($row['count'] ?? 0);
            
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * Get geolocation data
     */
    private function getGeoLocation($ip) {
        // In production, would use MaxMind or similar
        // For now, basic detection
        $parts = explode('.', $ip);
        
        return [
            'country' => 'Unknown',
            'asn' => 'Unknown',
            'is_vpn' => false,
            'is_proxy' => false,
        ];
    }
    
    /**
     * Check if user agent is suspicious
     */
    private function isSuspiciousUserAgent($userAgent) {
        $suspiciousPatterns = [
            'curl',
            'wget',
            'python',
            'sqlmap',
            'nikto',
            'nessus',
            'masscan',
            'nmap',
            'metasploit',
        ];
        
        $lower = strtolower($userAgent);
        foreach ($suspiciousPatterns as $pattern) {
            if (strpos($lower, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Analyze payload complexity
     */
    private function analyzePayload($payload) {
        $score = 0;
        
        // Length indicates complexity
        if (strlen($payload) > 500) $score += 1;
        if (strlen($payload) > 1000) $score += 1;
        
        // Encoding indicates obfuscation
        if (preg_match('/base64|hex|url|unicode/i', $payload)) $score += 2;
        
        // Multiple operators
        if (preg_match_all('/(\+|-|\*|\/|=)/', $payload) > 3) $score += 1;
        
        // Comment syntax
        if (preg_match('/\/\*|\*\/|--|#|;/', $payload)) $score += 1;
        
        return min(5, $score);
    }
    
    /**
     * Get action reason
     */
    private function getActionReason($level, $characteristics) {
        $reasons = [
            'critical' => 'Critical threat detected - immediate blocking required',
            'high' => 'High severity threat - requires rate limiting or blocking',
            'medium' => 'Medium severity threat - rate limiting recommended',
            'low' => 'Low severity threat - logging for monitoring',
        ];
        
        return $reasons[$level] ?? 'Threat detected';
    }
    
    /**
     * Detect pattern family
     */
    private function detectPatternFamily($threatType, $pattern) {
        $families = [
            'sql_injection' => ['UNION', 'OR', 'AND', '--', '/*'],
            'xss' => ['<script', 'onerror', 'onclick', 'javascript'],
            'path_traversal' => ['../', '..\\', '....', '%2e%2e'],
        ];
        
        if (isset($families[$threatType])) {
            foreach ($families[$threatType] as $keyword) {
                if (stripos($pattern, $keyword) !== false) {
                    return $threatType . '_variant_' . strtolower($keyword);
                }
            }
        }
        
        return $threatType . '_generic';
    }
    
    /**
     * Extract IOCs (Indicators of Compromise)
     */
    private function extractIOCs($threat) {
        $iocs = [];
        
        // IP address
        $iocs[] = [
            'type' => 'ipv4',
            'value' => $threat['source_ip'],
            'severity' => 'high',
        ];
        
        // File hashes
        if (!empty($threat['payload_hash'])) {
            $iocs[] = [
                'type' => 'file_hash',
                'value' => $threat['payload_hash'],
                'severity' => 'medium',
            ];
        }
        
        // URLs/paths
        if (!empty($threat['target_path'])) {
            $iocs[] = [
                'type' => 'uri',
                'value' => $threat['target_path'],
                'severity' => 'low',
            ];
        }
        
        return $iocs;
    }
    
    /**
     * Get attribution hints
     */
    private function getAttribution($country, $threatType) {
        // Simple attribution based on country and threat type
        $attributions = [
            'critical' => 'Potential APT activity detected',
            'high' => 'Possibly organized cybercrime group',
            'medium' => 'Likely automated scanning tool',
            'low' => 'Script kiddie activity',
        ];
        
        return $attributions[$threatType] ?? 'Unknown actor';
    }
    
    /**
     * Find similar campaigns
     */
    private function findSimilarCampaigns($threat) {
        try {
            $stmt = $this->db->prepare(
                "SELECT DISTINCT threat_type, COUNT(*) as count 
                FROM local_threats 
                WHERE threat_type = ? AND detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY threat_type"
            );
            
            $threatType = $threat['threat_type'];
            $stmt->bind_param('s', $threatType);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            
            if ($row && $row['count'] > 5) {
                return [
                    'campaign_type' => $threatType . '_wave',
                    'incident_count' => $row['count'],
                    'time_frame' => '7 days',
                    'severity' => 'high',
                ];
            }
            
            return [];
            
        } catch (Exception $e) {
            return [];
        }
    }
    
    /**
     * Extract TTPs (Tactics, Techniques, Procedures)
     */
    private function extractTTPs($threatType) {
        $ttps = [
            'sql_injection' => ['Initial Access', 'Execution', 'Data Exfiltration'],
            'xss' => ['Execution', 'Persistence'],
            'brute_force' => ['Credential Access', 'Initial Access'],
            'ddos' => ['Impact'],
            'path_traversal' => ['Discovery', 'Execution'],
        ];
        
        return $ttps[$threatType] ?? ['Execution'];
    }
    
    /**
     * Get full analysis
     */
    public function getAnalysis() {
        return $this->analysis;
    }
    
    /**
     * Get severity level
     */
    public function getSeverityLevel() {
        return $this->analysis['severity']['level'] ?? 'unknown';
    }
    
    /**
     * Get recommended action
     */
    public function getRecommendedAction() {
        return $this->analysis['recommended_action']['primary'] ?? 'log_only';
    }
    
    /**
     * Is coordinated attack
     */
    public function isCoordinatedAttack() {
        return $this->analysis['coordination']['is_coordinated_attack'] ?? false;
    }
}

?>
