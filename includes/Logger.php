<?php
/**
 * SMV Security - Logger Class
 * 
 * Centralized logging system
 * Log rotation, formatting, and statistics
 * Threat reporting and analytics
 */

class Logger {
    
    private $logDir;
    private $logFiles = [
        'app' => 'waf.log',
        'error' => 'errors.log',
        'threat' => 'threats.log',
        'daemon' => 'daemon.log',
        'sync' => 'sync.log',
    ];
    
    private $logLevel = 'info';
    private $logLevels = [
        'debug' => 0,
        'info' => 1,
        'warning' => 2,
        'error' => 3,
    ];
    
    /**
     * Constructor
     */
    public function __construct($logDir = null) {
        $this->logDir = $logDir ?? LOG_DIR;
        $this->logLevel = LOG_LEVEL ?? 'info';
        
        // Ensure log directory exists
        if (!is_dir($this->logDir)) {
            @mkdir($this->logDir, 0755, true);
        }
    }
    
    /**
     * Log message
     */
    public function log($message, $type = 'info', $logFile = 'app') {
        // Check if message should be logged based on level
        if (!$this->shouldLog($type)) {
            return false;
        }
        
        try {
            $file = $this->logDir . $this->logFiles[$logFile] ?? 'waf.log';
            $timestamp = date('Y-m-d H:i:s');
            
            // Format message
            $logEntry = "[" . strtoupper($timestamp) . "] [" . strtoupper($type) . "] " . $message . "\n";
            
            // Check file size and rotate if needed
            if (file_exists($file) && filesize($file) > MAX_LOG_SIZE_MB * 1024 * 1024) {
                $this->rotateLog($file);
            }
            
            // Write to file
            error_log($logEntry, 3, $file);
            
            return true;
            
        } catch (Exception $e) {
            // Fallback to error_log
            error_log("Logger error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Log application message
     */
    public function info($message) {
        return $this->log($message, 'info', 'app');
    }
    
    /**
     * Log debug message
     */
    public function debug($message) {
        return $this->log($message, 'debug', 'app');
    }
    
    /**
     * Log warning
     */
    public function warning($message) {
        return $this->log($message, 'warning', 'app');
    }
    
    /**
     * Log error
     */
    public function error($message) {
        return $this->log($message, 'error', 'error');
    }
    
    /**
     * Log threat
     */
    public function logThreat($threatType, $severity, $sourceIP, $details = '') {
        try {
            $timestamp = date('Y-m-d H:i:s');
            
            $threatData = [
                'timestamp' => $timestamp,
                'type' => $threatType,
                'severity' => $severity,
                'source_ip' => $sourceIP,
                'details' => $details,
            ];
            
            $logEntry = json_encode($threatData) . "\n";
            
            // Check rotation
            $file = $this->logDir . $this->logFiles['threat'];
            if (file_exists($file) && filesize($file) > MAX_LOG_SIZE_MB * 1024 * 1024) {
                $this->rotateLog($file);
            }
            
            // Write threat log
            error_log($logEntry, 3, $file);
            
            // Also store in database
            $this->storeThreatInDB($threatType, $severity, $sourceIP, $details);
            
            return true;
            
        } catch (Exception $e) {
            $this->error("Failed to log threat: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Log daemon execution
     */
    public function logDaemonExecution($duration, $logsScanned, $threatsDetected, $status = 'success', $error = '') {
        try {
            $executionData = [
                'timestamp' => date('Y-m-d H:i:s'),
                'duration_ms' => $duration,
                'logs_scanned' => $logsScanned,
                'threats_detected' => $threatsDetected,
                'status' => $status,
                'error' => $error,
            ];
            
            $logEntry = json_encode($executionData) . "\n";
            
            // Check rotation
            $file = $this->logDir . $this->logFiles['daemon'];
            if (file_exists($file) && filesize($file) > MAX_LOG_SIZE_MB * 1024 * 1024) {
                $this->rotateLog($file);
            }
            
            // Write daemon log
            error_log($logEntry, 3, $file);
            
            return true;
            
        } catch (Exception $e) {
            $this->error("Failed to log daemon execution: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Log API sync
     */
    public function logAPISync($endpoint, $method, $success, $responseTime = 0, $error = '') {
        try {
            $syncData = [
                'timestamp' => date('Y-m-d H:i:s'),
                'endpoint' => $endpoint,
                'method' => $method,
                'success' => $success ? 'YES' : 'NO',
                'response_time_ms' => $responseTime,
                'error' => $error,
            ];
            
            $logEntry = json_encode($syncData) . "\n";
            
            // Check rotation
            $file = $this->logDir . $this->logFiles['sync'];
            if (file_exists($file) && filesize($file) > MAX_LOG_SIZE_MB * 1024 * 1024) {
                $this->rotateLog($file);
            }
            
            // Write sync log
            error_log($logEntry, 3, $file);
            
            return true;
            
        } catch (Exception $e) {
            $this->error("Failed to log API sync: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Rotate log file
     */
    private function rotateLog($logFile) {
        try {
            if (!file_exists($logFile)) {
                return false;
            }
            
            // Create backup filename
            $timestamp = date('Y-m-d-His');
            $backupFile = $logFile . '.' . $timestamp . '.gz';
            
            // Read original file
            $content = file_get_contents($logFile);
            
            // Compress and save
            file_put_contents('compress.zlib://' . $backupFile, $content);
            
            // Clear original file
            file_put_contents($logFile, '');
            
            // Delete old backups (keep last 10)
            $this->deleteOldBackups($logFile);
            
            $this->info("Log rotated: " . basename($logFile));
            return true;
            
        } catch (Exception $e) {
            $this->error("Error rotating log: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Delete old backup logs
     */
    private function deleteOldBackups($logFile, $keepCount = 10) {
        try {
            $dir = dirname($logFile);
            $pattern = basename($logFile) . '.*\\.gz';
            
            $files = glob($dir . '/' . $pattern);
            
            if (count($files) > $keepCount) {
                // Sort by timestamp (newest first)
                arsort($files);
                
                // Delete old ones
                for ($i = $keepCount; $i < count($files); $i++) {
                    @unlink($files[$i]);
                }
            }
            
        } catch (Exception $e) {
            // Non-critical
        }
    }
    
    /**
     * Check if message should be logged
     */
    private function shouldLog($type) {
        $typeLevel = $this->logLevels[$type] ?? 1;
        $minLevel = $this->logLevels[$this->logLevel] ?? 1;
        return $typeLevel >= $minLevel;
    }
    
    /**
     * Store threat in database
     */
    private function storeThreatInDB($threatType, $severity, $sourceIP, $details = '') {
        try {
            $db = getDB();
            
            $stmt = $db->prepare(
                "INSERT INTO local_threats 
                (threat_type, severity, source_ip, attack_pattern, detected_at)
                VALUES (?, ?, ?, ?, NOW())"
            );
            
            $stmt->bind_param('ssss', $threatType, $severity, $sourceIP, $details);
            $stmt->execute();
            
        } catch (Exception $e) {
            // Non-critical
        }
    }
    
    /**
     * Get log entries
     */
    public function getLogEntries($logFile = 'app', $lines = 100) {
        try {
            $file = $this->logDir . ($this->logFiles[$logFile] ?? 'waf.log');
            
            if (!file_exists($file)) {
                return [];
            }
            
            // Read last N lines
            $command = "tail -n $lines " . escapeshellarg($file);
            $output = shell_exec($command);
            
            return array_filter(explode("\n", $output));
            
        } catch (Exception $e) {
            $this->error("Error reading log: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get recent threats
     */
    public function getRecentThreats($limit = 100) {
        try {
            $db = getDB();
            
            $stmt = $db->prepare(
                "SELECT threat_type, severity, source_ip, detected_at 
                FROM local_threats 
                ORDER BY detected_at DESC 
                LIMIT ?"
            );
            
            $stmt->bind_param('i', $limit);
            $stmt->execute();
            $result = $stmt->get_result();
            
            return $result->fetch_all(MYSQLI_ASSOC);
            
        } catch (Exception $e) {
            $this->error("Error getting threats: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get threat statistics
     */
    public function getThreatStats($period = 'day') {
        try {
            $db = getDB();
            
            // Determine date range
            $dateRange = match($period) {
                'hour' => 'INTERVAL 1 HOUR',
                'day' => 'INTERVAL 1 DAY',
                'week' => 'INTERVAL 1 WEEK',
                'month' => 'INTERVAL 1 MONTH',
                default => 'INTERVAL 1 DAY',
            };
            
            $stats = [];
            
            // Total threats
            $result = $db->query(
                "SELECT COUNT(*) as count FROM local_threats 
                WHERE detected_at >= DATE_SUB(NOW(), $dateRange)"
            );
            $stats['total_threats'] = $result->fetch_assoc()['count'];
            
            // Threats by severity
            $result = $db->query(
                "SELECT severity, COUNT(*) as count FROM local_threats 
                WHERE detected_at >= DATE_SUB(NOW(), $dateRange)
                GROUP BY severity"
            );
            $stats['by_severity'] = [];
            while ($row = $result->fetch_assoc()) {
                $stats['by_severity'][$row['severity']] = $row['count'];
            }
            
            // Threats by type
            $result = $db->query(
                "SELECT threat_type, COUNT(*) as count FROM local_threats 
                WHERE detected_at >= DATE_SUB(NOW(), $dateRange)
                GROUP BY threat_type 
                ORDER BY count DESC LIMIT 10"
            );
            $stats['by_type'] = $result->fetch_all(MYSQLI_ASSOC);
            
            // Top source IPs
            $result = $db->query(
                "SELECT source_ip, COUNT(*) as count FROM local_threats 
                WHERE detected_at >= DATE_SUB(NOW(), $dateRange)
                GROUP BY source_ip 
                ORDER BY count DESC LIMIT 10"
            );
            $stats['top_ips'] = $result->fetch_all(MYSQLI_ASSOC);
            
            // Blocked IPs
            $result = $db->query(
                "SELECT COUNT(*) as count FROM blocked_ips 
                WHERE blocked_at >= DATE_SUB(NOW(), $dateRange)"
            );
            $stats['ips_blocked'] = $result->fetch_assoc()['count'];
            
            // Average threat score
            $result = $db->query(
                "SELECT AVG(severity) as avg_severity FROM local_threats 
                WHERE detected_at >= DATE_SUB(NOW(), $dateRange)"
            );
            $avgSeverity = $result->fetch_assoc()['avg_severity'];
            $stats['avg_severity'] = round($avgSeverity, 2);
            
            return $stats;
            
        } catch (Exception $e) {
            $this->error("Error getting stats: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get daemon statistics
     */
    public function getDaemonStats($limit = 100) {
        try {
            $db = getDB();
            
            $stmt = $db->prepare(
                "SELECT execution_time, execution_duration_ms, logs_scanned, 
                        threats_detected, rules_applied, status 
                FROM daemon_logs 
                ORDER BY execution_time DESC 
                LIMIT ?"
            );
            
            $stmt->bind_param('i', $limit);
            $stmt->execute();
            $result = $stmt->get_result();
            
            return $result->fetch_all(MYSQLI_ASSOC);
            
        } catch (Exception $e) {
            $this->error("Error getting daemon stats: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get system health
     */
    public function getSystemHealth() {
        try {
            $health = [
                'status' => 'healthy',
                'issues' => [],
                'warnings' => [],
            ];
            
            $db = getDB();
            
            // Check last daemon run
            $result = $db->query(
                "SELECT execution_time FROM daemon_logs 
                ORDER BY execution_time DESC LIMIT 1"
            );
            
            $row = $result->fetch_assoc();
            if (!$row) {
                $health['issues'][] = 'Daemon has never run';
                $health['status'] = 'unhealthy';
            } else {
                $lastRun = strtotime($row['execution_time']);
                $minutesAgo = (time() - $lastRun) / 60;
                
                if ($minutesAgo > 30) {
                    $health['issues'][] = "Daemon hasn't run in " . round($minutesAgo, 0) . " minutes";
                    $health['status'] = 'unhealthy';
                } elseif ($minutesAgo > 15) {
                    $health['warnings'][] = "Daemon last ran " . round($minutesAgo, 0) . " minutes ago";
                }
            }
            
            // Check disk space
            $diskFree = disk_free_space($this->logDir);
            $diskTotal = disk_total_space($this->logDir);
            $diskUsage = 100 - ($diskFree / $diskTotal * 100);
            
            $health['disk_usage'] = round($diskUsage, 2);
            
            if ($diskUsage > 90) {
                $health['issues'][] = "Disk usage critical: " . $health['disk_usage'] . "%";
                $health['status'] = 'unhealthy';
            } elseif ($diskUsage > 75) {
                $health['warnings'][] = "Disk usage high: " . $health['disk_usage'] . "%";
            }
            
            // Check recent errors
            $result = $db->query(
                "SELECT COUNT(*) as count FROM daemon_logs 
                WHERE status = 'error' 
                AND execution_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
            );
            
            $errorCount = $result->fetch_assoc()['count'];
            if ($errorCount > 0) {
                $health['warnings'][] = "$errorCount errors in last 24 hours";
            }
            
            return $health;
            
        } catch (Exception $e) {
            $this->error("Error checking health: " . $e->getMessage());
            return ['status' => 'unknown', 'issues' => [$e->getMessage()]];
        }
    }
    
    /**
     * Generate report
     */
    public function generateReport($period = 'day') {
        try {
            $stats = $this->getThreatStats($period);
            $health = $this->getSystemHealth();
            $daemon = $this->getDaemonStats(5);
            
            return [
                'generated_at' => date('Y-m-d H:i:s'),
                'period' => $period,
                'statistics' => $stats,
                'system_health' => $health,
                'daemon_activity' => $daemon,
            ];
            
        } catch (Exception $e) {
            $this->error("Error generating report: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Cleanup old logs
     */
    public function cleanup() {
        try {
            $db = getDB();
            $days = THREAT_RETENTION_DAYS;
            
            // Delete old threats
            $stmt = $db->prepare(
                "DELETE FROM local_threats WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)"
            );
            $stmt->bind_param('i', $days);
            $stmt->execute();
            
            // Delete old daemon logs
            $stmt = $db->prepare(
                "DELETE FROM daemon_logs WHERE execution_time < DATE_SUB(NOW(), INTERVAL ? DAY)"
            );
            $stmt->bind_param('i', $days);
            $stmt->execute();
            
            $this->info("Cleanup completed - removed logs older than $days days");
            return true;
            
        } catch (Exception $e) {
            $this->error("Error during cleanup: " . $e->getMessage());
            return false;
        }
    }
}

?>
