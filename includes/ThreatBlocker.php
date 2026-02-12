<?php
/**
 * SMV Security - Threat Blocker Class
 * 
 * Handles IP blocking, firewall rule creation and management
 * Supports multiple blocking methods: .htaccess, iptables, nginx
 */

class ThreatBlocker {
    
    private $db;
    private $blockMethods = [];
    private $blockedIPs = [];
    
    /**
     * Constructor
     */
    public function __construct($db) {
        $this->db = $db;
        $this->initializeBlockMethods();
        $this->loadBlockedIPs();
    }
    
    /**
     * Initialize available blocking methods
     */
    private function initializeBlockMethods() {
        $methods = BLOCKING_METHODS;
        
        if (isset($methods['htaccess']) && $methods['htaccess']) {
            $this->blockMethods['htaccess'] = true;
        }
        
        if (isset($methods['nginx_rules']) && $methods['nginx_rules']) {
            $this->blockMethods['nginx_rules'] = true;
        }
        
        if (isset($methods['iptables']) && $methods['iptables']) {
            $this->blockMethods['iptables'] = true;
        }
    }
    
    /**
     * Load currently blocked IPs from database
     */
    private function loadBlockedIPs() {
        try {
            $stmt = $this->db->prepare(
                "SELECT ip_address, reason, block_type, expires_at FROM blocked_ips 
                WHERE (expires_at IS NULL OR expires_at > NOW()) AND block_type IN ('permanent', 'temporary')"
            );
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            while ($row = $result->fetch_assoc()) {
                $this->blockedIPs[$row['ip_address']] = [
                    'reason' => $row['reason'],
                    'type' => $row['block_type'],
                    'expires' => $row['expires_at'],
                ];
            }
            
        } catch (Exception $e) {
            logDaemon("Error loading blocked IPs: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Block an IP address
     */
    public function blockIP($ip, $reason = '', $blockType = 'temporary', $duration = 7) {
        // Validate IP
        if (!$this->isValidIP($ip)) {
            logDaemon("Invalid IP address: $ip", 'warning');
            return false;
        }
        
        // Don't block localhost or internal IPs
        if ($this->isInternalIP($ip)) {
            logDaemon("Cannot block internal IP: $ip", 'warning');
            return false;
        }
        
        try {
            // Calculate expiration
            $expiresAt = null;
            if ($blockType === 'temporary') {
                $expiresAt = date('Y-m-d H:i:s', strtotime("+$duration days"));
            }
            
            // Insert into database
            $stmt = $this->db->prepare(
                "INSERT INTO blocked_ips (ip_address, reason, threat_type, block_type, blocked_at, expires_at)
                VALUES (?, ?, ?, ?, NOW(), ?)
                ON DUPLICATE KEY UPDATE 
                block_hit_count = block_hit_count + 1, 
                last_attempt = NOW(),
                expires_at = VALUES(expires_at)"
            );
            
            $threatType = $reason;
            $stmt->bind_param('sssss', $ip, $reason, $threatType, $blockType, $expiresAt);
            
            if (!$stmt->execute()) {
                logDaemon("Failed to insert blocked IP: " . $this->db->error, 'error');
                return false;
            }
            
            // Apply block to firewall
            $this->applyBlockMethods($ip);
            
            // Cache it
            $this->blockedIPs[$ip] = [
                'reason' => $reason,
                'type' => $blockType,
                'expires' => $expiresAt,
            ];
            
            logDaemon("Blocked IP: $ip - Reason: $reason", 'info');
            return true;
            
        } catch (Exception $e) {
            logDaemon("Error blocking IP $ip: " . $e->getMessage(), 'error');
            return false;
        }
    }
    
    /**
     * Unblock an IP address
     */
    public function unblockIP($ip) {
        try {
            $stmt = $this->db->prepare("DELETE FROM blocked_ips WHERE ip_address = ?");
            $stmt->bind_param('s', $ip);
            
            if ($stmt->execute()) {
                // Remove from firewall
                $this->removeBlockMethods($ip);
                
                // Remove from cache
                unset($this->blockedIPs[$ip]);
                
                logDaemon("Unblocked IP: $ip", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error unblocking IP $ip: " . $e->getMessage(), 'error');
        }
        
        return false;
    }
    
    /**
     * Check if IP is blocked
     */
    public function isBlocked($ip) {
        return isset($this->blockedIPs[$ip]);
    }
    
    /**
     * Get all blocked IPs
     */
    public function getBlockedIPs() {
        return $this->blockedIPs;
    }
    
    /**
     * Get blocked IP info
     */
    public function getBlockedIPInfo($ip) {
        return $this->blockedIPs[$ip] ?? null;
    }
    
    /**
     * Apply blocking methods
     */
    private function applyBlockMethods($ip) {
        // Try each blocking method
        if (isset($this->blockMethods['htaccess'])) {
            $this->blockViaHTAccess($ip);
        }
        
        if (isset($this->blockMethods['nginx_rules'])) {
            $this->blockViaNginx($ip);
        }
        
        if (isset($this->blockMethods['iptables'])) {
            $this->blockViaIPTables($ip);
        }
    }
    
    /**
     * Remove blocking methods
     */
    private function removeBlockMethods($ip) {
        if (isset($this->blockMethods['htaccess'])) {
            $this->unblockViaHTAccess($ip);
        }
        
        if (isset($this->blockMethods['nginx_rules'])) {
            $this->unblockViaNginx($ip);
        }
        
        if (isset($this->blockMethods['iptables'])) {
            $this->unblockViaIPTables($ip);
        }
    }
    
    /**
     * Block IP via .htaccess
     */
    private function blockViaHTAccess($ip) {
        try {
            $htaccessFile = HTACCESS_FILE;
            
            if (!file_exists($htaccessFile)) {
                return false;
            }
            
            $content = file_get_contents($htaccessFile);
            
            // Check if already blocked
            if (strpos($content, "Deny from $ip") !== false) {
                return true;
            }
            
            // Add deny rule
            $rule = "\n# SMV WAF Block - " . date('Y-m-d H:i:s') . "\nDeny from $ip\n";
            
            if (file_put_contents($htaccessFile, $rule, FILE_APPEND | LOCK_EX)) {
                logDaemon("Applied .htaccess block for IP: $ip", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error applying .htaccess block: " . $e->getMessage(), 'warning');
        }
        
        return false;
    }
    
    /**
     * Unblock IP via .htaccess
     */
    private function unblockViaHTAccess($ip) {
        try {
            $htaccessFile = HTACCESS_FILE;
            
            if (!file_exists($htaccessFile)) {
                return false;
            }
            
            $content = file_get_contents($htaccessFile);
            
            // Remove deny rule
            $pattern = "/Deny from $ip/";
            $newContent = preg_replace($pattern, '', $content);
            
            if (file_put_contents($htaccessFile, $newContent, LOCK_EX)) {
                logDaemon("Removed .htaccess block for IP: $ip", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error removing .htaccess block: " . $e->getMessage(), 'warning');
        }
        
        return false;
    }
    
    /**
     * Block IP via Nginx
     */
    private function blockViaNginx($ip) {
        try {
            $nginxBlockFile = BASE_DIR . '/nginx-blocked-ips.conf';
            
            // Check if already blocked
            if (file_exists($nginxBlockFile)) {
                $content = file_get_contents($nginxBlockFile);
                if (strpos($content, "deny $ip;") !== false) {
                    return true;
                }
            }
            
            // Add deny rule
            $rule = "deny $ip; # SMV WAF - " . date('Y-m-d H:i:s') . "\n";
            
            if (file_put_contents($nginxBlockFile, $rule, FILE_APPEND | LOCK_EX)) {
                logDaemon("Applied nginx block for IP: $ip", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error applying nginx block: " . $e->getMessage(), 'warning');
        }
        
        return false;
    }
    
    /**
     * Unblock IP via Nginx
     */
    private function unblockViaNginx($ip) {
        try {
            $nginxBlockFile = BASE_DIR . '/nginx-blocked-ips.conf';
            
            if (!file_exists($nginxBlockFile)) {
                return false;
            }
            
            $content = file_get_contents($nginxBlockFile);
            
            // Remove deny rule
            $pattern = "/deny $ip;.*\n/";
            $newContent = preg_replace($pattern, '', $content);
            
            if (file_put_contents($nginxBlockFile, $newContent, LOCK_EX)) {
                logDaemon("Removed nginx block for IP: $ip", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error removing nginx block: " . $e->getMessage(), 'warning');
        }
        
        return false;
    }
    
    /**
     * Block IP via iptables
     */
    private function blockViaIPTables($ip) {
        try {
            // Only run if we have shell access and are root
            if (php_uname('s') !== 'Linux' || posix_getuid() !== 0) {
                logDaemon("Cannot use iptables - not running as root on Linux", 'warning');
                return false;
            }
            
            // Add iptables rule
            $command = "iptables -A INPUT -s $ip -j DROP";
            $output = shell_exec($command . ' 2>&1');
            
            if (strpos($output, 'No such file') === false) {
                logDaemon("Applied iptables block for IP: $ip", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error applying iptables block: " . $e->getMessage(), 'warning');
        }
        
        return false;
    }
    
    /**
     * Unblock IP via iptables
     */
    private function unblockViaIPTables($ip) {
        try {
            // Only run if we have shell access and are root
            if (php_uname('s') !== 'Linux' || posix_getuid() !== 0) {
                return false;
            }
            
            // Remove iptables rule
            $command = "iptables -D INPUT -s $ip -j DROP";
            shell_exec($command . ' 2>&1');
            
            logDaemon("Removed iptables block for IP: $ip", 'info');
            return true;
            
        } catch (Exception $e) {
            logDaemon("Error removing iptables block: " . $e->getMessage(), 'warning');
        }
        
        return false;
    }
    
    /**
     * Create firewall rule
     */
    public function createRule($ruleName, $ruleType, $matchPattern, $action, $source = 'manual') {
        try {
            $stmt = $this->db->prepare(
                "INSERT INTO firewall_rules 
                (rule_name, rule_type, match_pattern, action, source, is_active)
                VALUES (?, ?, ?, ?, ?, 1)"
            );
            
            $stmt->bind_param('sssss', $ruleName, $ruleType, $matchPattern, $action, $source);
            
            if ($stmt->execute()) {
                logDaemon("Created firewall rule: $ruleName", 'info');
                return $this->db->insert_id;
            }
            
        } catch (Exception $e) {
            logDaemon("Error creating rule: " . $e->getMessage(), 'error');
        }
        
        return false;
    }
    
    /**
     * Delete firewall rule
     */
    public function deleteRule($ruleID) {
        try {
            $stmt = $this->db->prepare("DELETE FROM firewall_rules WHERE id = ?");
            $stmt->bind_param('i', $ruleID);
            
            if ($stmt->execute()) {
                logDaemon("Deleted firewall rule: $ruleID", 'info');
                return true;
            }
            
        } catch (Exception $e) {
            logDaemon("Error deleting rule: " . $e->getMessage(), 'error');
        }
        
        return false;
    }
    
    /**
     * Enable rule
     */
    public function enableRule($ruleID) {
        return $this->setRuleStatus($ruleID, true);
    }
    
    /**
     * Disable rule
     */
    public function disableRule($ruleID) {
        return $this->setRuleStatus($ruleID, false);
    }
    
    /**
     * Set rule status
     */
    private function setRuleStatus($ruleID, $isActive) {
        try {
            $active = $isActive ? 1 : 0;
            $stmt = $this->db->prepare("UPDATE firewall_rules SET is_active = ? WHERE id = ?");
            $stmt->bind_param('ii', $active, $ruleID);
            return $stmt->execute();
            
        } catch (Exception $e) {
            logDaemon("Error updating rule status: " . $e->getMessage(), 'error');
            return false;
        }
    }
    
    /**
     * Get all rules
     */
    public function getRules() {
        try {
            $stmt = $this->db->prepare(
                "SELECT id, rule_name, rule_type, action, is_active, hit_count, last_hit 
                FROM firewall_rules ORDER BY priority DESC"
            );
            
            $stmt->execute();
            return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
            
        } catch (Exception $e) {
            logDaemon("Error getting rules: " . $e->getMessage(), 'warning');
            return [];
        }
    }
    
    /**
     * Validate IP address
     */
    private function isValidIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * Check if IP is internal/private
     */
    private function isInternalIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, 
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
            && filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * Cleanup expired blocks
     */
    public function cleanupExpiredBlocks() {
        try {
            // Get expired blocks
            $stmt = $this->db->prepare(
                "SELECT ip_address FROM blocked_ips 
                WHERE block_type = 'temporary' AND expires_at < NOW()"
            );
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            $count = 0;
            while ($row = $result->fetch_assoc()) {
                if ($this->unblockIP($row['ip_address'])) {
                    $count++;
                }
            }
            
            if ($count > 0) {
                logDaemon("Cleaned up $count expired IP blocks", 'info');
            }
            
        } catch (Exception $e) {
            logDaemon("Error during cleanup: " . $e->getMessage(), 'warning');
        }
    }
    
    /**
     * Get blocking stats
     */
    public function getBlockingStats() {
        try {
            $stats = [];
            
            // Total blocked IPs
            $result = $this->db->query("SELECT COUNT(*) as count FROM blocked_ips");
            $stats['total_blocked'] = $result->fetch_assoc()['count'];
            
            // Permanent blocks
            $result = $this->db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE block_type = 'permanent'");
            $stats['permanent_blocks'] = $result->fetch_assoc()['count'];
            
            // Temporary blocks
            $result = $this->db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE block_type = 'temporary' AND expires_at > NOW()");
            $stats['temporary_blocks'] = $result->fetch_assoc()['count'];
            
            // Active rules
            $result = $this->db->query("SELECT COUNT(*) as count FROM firewall_rules WHERE is_active = 1");
            $stats['active_rules'] = $result->fetch_assoc()['count'];
            
            // Top threat types
            $result = $this->db->query(
                "SELECT threat_type, COUNT(*) as count FROM blocked_ips 
                WHERE threat_type IS NOT NULL GROUP BY threat_type ORDER BY count DESC LIMIT 5"
            );
            $stats['top_threats'] = $result->fetch_all(MYSQLI_ASSOC);
            
            return $stats;
            
        } catch (Exception $e) {
            logDaemon("Error getting stats: " . $e->getMessage(), 'warning');
            return [];
        }
    }
}

?>
