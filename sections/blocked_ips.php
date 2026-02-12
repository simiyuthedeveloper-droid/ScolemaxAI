<!-- BLOCKED IPS MANAGEMENT -->

<?php
// Helper function for sanitization if not defined
if (!function_exists('sanitize')) {
    function sanitize($input) {
        return htmlspecialchars(stripslashes(trim($input)), ENT_QUOTES, 'UTF-8');
    }
}

// Initialize ThreatBlocker and Logger if available
$blocker = null;
$logger = null;

if (class_exists('ThreatBlocker')) {
    $blocker = new ThreatBlocker($db);
}

if (class_exists('Logger')) {
    $logger = new Logger();
}

// Handle POST actions
$actionMessage = '';
$actionType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    // UNBLOCK IP
    if ($action === 'unblock_ip' && !empty($_POST['ip_address'])) {
        $ip = sanitize($_POST['ip_address']);
        
        if ($blocker && $blocker->unblockIP($ip)) {
            $actionMessage = "Successfully unblocked IP: $ip";
            $actionType = 'success';
            if ($logger) {
                $logger->info("Admin unblocked IP: $ip from WebUI");
            }
        } else {
            $actionMessage = "Failed to unblock IP: $ip";
            $actionType = 'danger';
        }
    }
    
    // BLOCK IP MANUALLY
    elseif ($action === 'block_ip' && !empty($_POST['new_ip'])) {
        $newIP = sanitize($_POST['new_ip']);
        $reason = sanitize($_POST['reason'] ?? 'Manual block from WebUI');
        $blockType = sanitize($_POST['block_type'] ?? 'temporary');
        $duration = intval($_POST['duration'] ?? 7);
        
        // Validate IP
        if (filter_var($newIP, FILTER_VALIDATE_IP)) {
            if ($blocker && $blocker->blockIP($newIP, $reason, $blockType, $duration)) {
                $actionMessage = "Successfully blocked IP: $newIP";
                $actionType = 'success';
                if ($logger) {
                    $logger->info("Admin manually blocked IP: $newIP - Reason: $reason");
                }
            } else {
                $actionMessage = "Failed to block IP: $newIP";
                $actionType = 'danger';
            }
        } else {
            $actionMessage = "Invalid IP address: $newIP";
            $actionType = 'danger';
        }
    }
    
    // BULK UNBLOCK
    elseif ($action === 'bulk_unblock' && !empty($_POST['selected_ips'])) {
        $selectedIPs = $_POST['selected_ips'];
        $unblockedCount = 0;
        
        if ($blocker) {
            foreach ($selectedIPs as $ip) {
                $ip = sanitize($ip);
                if ($blocker->unblockIP($ip)) {
                    $unblockedCount++;
                }
            }
        }
        
        $actionMessage = "Successfully unblocked $unblockedCount IP(s)";
        $actionType = 'success';
        if ($logger) {
            $logger->info("Admin bulk unblocked $unblockedCount IPs from WebUI");
        }
    }
    
    // CLEANUP EXPIRED BLOCKS
    elseif ($action === 'cleanup_expired') {
        if ($blocker) {
            $blocker->cleanupExpiredBlocks();
        }
        $actionMessage = "Expired blocks cleaned up successfully";
        $actionType = 'success';
        if ($logger) {
            $logger->info("Admin triggered expired blocks cleanup from WebUI");
        }
    }
}

// Get filter parameters
$filterType = isset($_GET['filter']) ? $_GET['filter'] : 'all';
$searchIP = isset($_GET['search']) ? $_GET['search'] : '';
$sortBy = isset($_GET['sort']) ? $_GET['sort'] : 'blocked_at';
$sortOrder = isset($_GET['order']) && $_GET['order'] === 'ASC' ? 'ASC' : 'DESC';
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$perPage = 20;
$offset = ($page - 1) * $perPage;

// Build SQL query based on filters
$whereConditions = [];
$params = [];
$paramTypes = '';

if ($filterType === 'permanent') {
    $whereConditions[] = "block_type = 'permanent'";
} elseif ($filterType === 'temporary') {
    $whereConditions[] = "block_type = 'temporary' AND (expires_at IS NULL OR expires_at > NOW())";
} elseif ($filterType === 'expired') {
    $whereConditions[] = "block_type = 'temporary' AND expires_at < NOW()";
}

if (!empty($searchIP)) {
    $whereConditions[] = "ip_address LIKE ?";
    $params[] = "%$searchIP%";
    $paramTypes .= 's';
}

$whereSQL = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';

// Get total count
$countQuery = "SELECT COUNT(*) as total FROM blocked_ips $whereSQL";
$stmt = $db->prepare($countQuery);
if (!empty($params)) {
    $stmt->bind_param($paramTypes, ...$params);
}
$stmt->execute();
$totalBlocked = $stmt->get_result()->fetch_assoc()['total'];
$totalPages = ceil($totalBlocked / $perPage);

// Get blocked IPs with pagination
$validSortColumns = ['ip_address', 'blocked_at', 'expires_at', 'block_hit_count', 'threat_type'];
$sortBy = in_array($sortBy, $validSortColumns) ? $sortBy : 'blocked_at';

$query = "SELECT ip_address, reason, threat_type, block_type, blocked_at, expires_at, 
          block_hit_count, last_attempt, notes
          FROM blocked_ips 
          $whereSQL 
          ORDER BY $sortBy $sortOrder 
          LIMIT ? OFFSET ?";

$stmt = $db->prepare($query);
$params[] = $perPage;
$params[] = $offset;
$paramTypes .= 'ii';

if (!empty($params)) {
    $stmt->bind_param($paramTypes, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();
$blockedIPs = $result->fetch_all(MYSQLI_ASSOC);

// Get statistics
$blockingStats = [];
if ($blocker) {
    $blockingStats = $blocker->getBlockingStats();
} else {
    // Fallback: get basic stats from database
    try {
        $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips");
        $blockingStats['total_blocked'] = $result ? $result->fetch_assoc()['count'] : 0;
        
        $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE block_type = 'permanent'");
        $blockingStats['permanent_blocks'] = $result ? $result->fetch_assoc()['count'] : 0;
        
        $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE block_type = 'temporary' AND (expires_at IS NULL OR expires_at > NOW())");
        $blockingStats['temporary_blocks'] = $result ? $result->fetch_assoc()['count'] : 0;
        
        $result = $db->query("SELECT COUNT(*) as count FROM firewall_rules WHERE is_active = 1");
        $blockingStats['active_rules'] = $result ? $result->fetch_assoc()['count'] : 0;
        
        $result = $db->query("SELECT threat_type, COUNT(*) as count FROM blocked_ips WHERE threat_type IS NOT NULL GROUP BY threat_type ORDER BY count DESC LIMIT 5");
        $blockingStats['top_threats'] = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
    } catch (Exception $e) {
        $blockingStats = [
            'total_blocked' => 0,
            'permanent_blocks' => 0,
            'temporary_blocks' => 0,
            'active_rules' => 0,
            'top_threats' => []
        ];
    }
}
?>

<!-- Action Message -->
<?php if (!empty($actionMessage)): ?>
<div class="card" style="background:<?php echo $actionType === 'success' ? 'rgba(74,222,128,0.1)' : 'rgba(239,68,68,0.1)'; ?>;border-color:<?php echo $actionType === 'success' ? 'var(--success)' : 'var(--danger)'; ?>;margin-bottom:1.5rem">
    <div class="card-body" style="padding:1rem">
        <i class="fas <?php echo $actionType === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'; ?>" style="color:<?php echo $actionType === 'success' ? 'var(--success)' : 'var(--danger)'; ?>"></i>
        <strong><?php echo htmlspecialchars($actionMessage); ?></strong>
    </div>
</div>
<?php endif; ?>

<!-- Statistics Overview -->
<div class="stats-grid" style="margin-bottom:1.5rem">
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($blockingStats['total_blocked'] ?? 0); ?></div>
                <div class="stat-label">Total Blocked IPs</div>
            </div>
            <div class="stat-icon blue"><i class="fas fa-ban"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($blockingStats['permanent_blocks'] ?? 0); ?></div>
                <div class="stat-label">Permanent Blocks</div>
            </div>
            <div class="stat-icon red"><i class="fas fa-shield-alt"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($blockingStats['temporary_blocks'] ?? 0); ?></div>
                <div class="stat-label">Temporary Blocks</div>
            </div>
            <div class="stat-icon yellow"><i class="fas fa-clock"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($blockingStats['active_rules'] ?? 0); ?></div>
                <div class="stat-label">Active Rules</div>
            </div>
            <div class="stat-icon purple"><i class="fas fa-fire"></i></div>
        </div>
    </div>
</div>

<!-- Top Threat Types -->
<?php if (!empty($blockingStats['top_threats'])): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 class="card-title">Top Threat Types</h3>
    </div>
    <div class="card-body">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0.75rem">
            <?php foreach ($blockingStats['top_threats'] as $threat): ?>
            <div style="background:rgba(59,130,246,0.05);padding:0.75rem;border-radius:6px;border:1px solid var(--border)">
                <div style="font-size:1.25rem;font-weight:700;color:var(--accent)"><?php echo $threat['count']; ?></div>
                <div style="font-size:0.8rem;color:var(--text-muted);text-transform:uppercase"><?php echo htmlspecialchars($threat['threat_type']); ?></div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Manual Block Form -->
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-plus-circle"></i> Block New IP</h3>
    </div>
    <div class="card-body">
        <form method="POST" action="">
            <input type="hidden" name="action" value="block_ip">
            
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem">
                <div class="form-group">
                    <label class="form-label">IP Address *</label>
                    <input type="text" name="new_ip" class="form-control" placeholder="192.168.1.100" required pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Block Type *</label>
                    <select name="block_type" class="form-control" id="blockTypeSelect">
                        <option value="temporary">Temporary</option>
                        <option value="permanent">Permanent</option>
                    </select>
                </div>
                
                <div class="form-group" id="durationGroup">
                    <label class="form-label">Duration (Days)</label>
                    <input type="number" name="duration" class="form-control" value="7" min="1" max="365">
                </div>
                
                <div class="form-group" style="grid-column:1/-1">
                    <label class="form-label">Reason *</label>
                    <input type="text" name="reason" class="form-control" placeholder="Manual block - Suspicious activity" required>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-ban"></i> Block IP
            </button>
        </form>
    </div>
</div>

<!-- Filter and Search -->
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem">
        <h3 class="card-title">Blocked IPs (<?php echo number_format($totalBlocked); ?>)</h3>
        
        <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
            <!-- Filter Dropdown -->
            <select class="form-control" style="width:auto;min-width:150px" onchange="window.location.href='?section=blocked_ips&filter='+this.value">
                <option value="all" <?php echo $filterType === 'all' ? 'selected' : ''; ?>>All Blocks</option>
                <option value="permanent" <?php echo $filterType === 'permanent' ? 'selected' : ''; ?>>Permanent</option>
                <option value="temporary" <?php echo $filterType === 'temporary' ? 'selected' : ''; ?>>Temporary</option>
                <option value="expired" <?php echo $filterType === 'expired' ? 'selected' : ''; ?>>Expired</option>
            </select>
            
            <!-- Search -->
            <form method="GET" style="display:flex;gap:0.5rem">
                <input type="hidden" name="section" value="blocked_ips">
                <input type="hidden" name="filter" value="<?php echo htmlspecialchars($filterType); ?>">
                <input type="text" name="search" class="form-control" placeholder="Search IP..." value="<?php echo htmlspecialchars($searchIP); ?>" style="width:200px">
                <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i></button>
            </form>
            
            <!-- Cleanup Button -->
            <form method="POST" style="display:inline" onsubmit="return confirm('Clean up expired blocks?')">
                <input type="hidden" name="action" value="cleanup_expired">
                <button type="submit" class="btn btn-secondary" title="Cleanup Expired Blocks">
                    <i class="fas fa-broom"></i> Cleanup
                </button>
            </form>
        </div>
    </div>
    
    <div class="card-body" style="padding:0">
        <?php if (empty($blockedIPs)): ?>
        <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <p>No blocked IPs found</p>
            <?php if (!empty($searchIP)): ?>
            <p><a href="?section=blocked_ips" class="btn btn-secondary">Clear Search</a></p>
            <?php endif; ?>
        </div>
        <?php else: ?>
        
        <form method="POST" id="bulkForm">
            <input type="hidden" name="action" value="bulk_unblock">
            
            <div style="overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th style="width:40px">
                            <input type="checkbox" id="selectAll" onclick="toggleSelectAll(this)">
                        </th>
                        <th>
                            <a href="?section=blocked_ips&sort=ip_address&order=<?php echo $sortBy === 'ip_address' && $sortOrder === 'ASC' ? 'DESC' : 'ASC'; ?>&filter=<?php echo $filterType; ?>" style="color:inherit;text-decoration:none">
                                IP Address <?php if ($sortBy === 'ip_address') echo $sortOrder === 'ASC' ? 'â†‘' : 'â†“'; ?>
                            </a>
                        </th>
                        <th>Threat Type</th>
                        <th>Reason</th>
                        <th>Type</th>
                        <th>
                            <a href="?section=blocked_ips&sort=blocked_at&order=<?php echo $sortBy === 'blocked_at' && $sortOrder === 'ASC' ? 'DESC' : 'ASC'; ?>&filter=<?php echo $filterType; ?>" style="color:inherit;text-decoration:none">
                                Blocked At <?php if ($sortBy === 'blocked_at') echo $sortOrder === 'ASC' ? 'â†‘' : 'â†“'; ?>
                            </a>
                        </th>
                        <th>Expires</th>
                        <th>Hits</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($blockedIPs as $blocked): ?>
                    <?php
                    // Determine if block is expired
                    $isExpired = false;
                    $expiresIn = '';
                    if ($blocked['block_type'] === 'temporary' && !empty($blocked['expires_at'])) {
                        $expiresTimestamp = strtotime($blocked['expires_at']);
                        $now = time();
                        
                        if ($expiresTimestamp < $now) {
                            $isExpired = true;
                            $expiresIn = 'Expired';
                        } else {
                            $diff = $expiresTimestamp - $now;
                            $days = floor($diff / 86400);
                            $hours = floor(($diff % 86400) / 3600);
                            
                            if ($days > 0) {
                                $expiresIn = $days . 'd ' . $hours . 'h';
                            } else {
                                $expiresIn = $hours . 'h';
                            }
                        }
                    } else {
                        $expiresIn = 'Never';
                    }
                    ?>
                    <tr style="<?php echo $isExpired ? 'opacity:0.6' : ''; ?>">
                        <td>
                            <input type="checkbox" name="selected_ips[]" value="<?php echo htmlspecialchars($blocked['ip_address']); ?>" class="ip-checkbox">
                        </td>
                        <td>
                            <strong style="font-family:monospace;color:var(--accent)"><?php echo htmlspecialchars($blocked['ip_address']); ?></strong>
                            <?php if ($blocked['block_hit_count'] > 5): ?>
                            <span class="badge badge-warning" style="margin-left:0.5rem" title="Multiple block attempts">
                                ðŸ”¥ <?php echo $blocked['block_hit_count']; ?>
                            </span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!empty($blocked['threat_type'])): ?>
                            <span class="badge badge-danger">
                                <?php echo htmlspecialchars($blocked['threat_type']); ?>
                            </span>
                            <?php else: ?>
                            <span style="color:var(--text-muted)">-</span>
                            <?php endif; ?>
                        </td>
                        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?php echo htmlspecialchars($blocked['reason']); ?>">
                            <?php echo htmlspecialchars($blocked['reason']); ?>
                        </td>
                        <td>
                            <?php if ($blocked['block_type'] === 'permanent'): ?>
                            <span class="badge badge-critical">PERMANENT</span>
                            <?php else: ?>
                            <span class="badge badge-warning">TEMPORARY</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div style="font-size:0.8rem"><?php echo date('M d', strtotime($blocked['blocked_at'])); ?></div>
                            <div style="font-size:0.75rem;color:var(--text-muted)"><?php echo date('H:i', strtotime($blocked['blocked_at'])); ?></div>
                        </td>
                        <td>
                            <?php if ($isExpired): ?>
                            <span class="badge badge-danger">Expired</span>
                            <?php else: ?>
                            <span style="font-size:0.8rem;color:<?php echo $blocked['block_type'] === 'permanent' ? 'var(--text-muted)' : 'var(--warning)'; ?>">
                                <?php echo $expiresIn; ?>
                            </span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="badge badge-info"><?php echo $blocked['block_hit_count']; ?></span>
                        </td>
                        <td>
                            <form method="POST" style="display:inline" onsubmit="return confirm('Unblock IP: <?php echo htmlspecialchars($blocked['ip_address']); ?>?')">
                                <input type="hidden" name="action" value="unblock_ip">
                                <input type="hidden" name="ip_address" value="<?php echo htmlspecialchars($blocked['ip_address']); ?>">
                                <button type="submit" class="btn btn-danger" style="padding:0.3rem 0.6rem;font-size:0.75rem">
                                    <i class="fas fa-unlock"></i>
                                </button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            
            <!-- Bulk Actions -->
            <div style="padding:1rem;border-top:1px solid var(--border);display:flex;gap:1rem;align-items:center">
                <button type="submit" class="btn btn-danger" onclick="return confirm('Unblock selected IPs?')">
                    <i class="fas fa-unlock"></i> Unblock Selected
                </button>
                <span id="selectedCount" style="color:var(--text-muted);font-size:0.875rem">0 selected</span>
            </div>
        </form>
        
        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
        <div style="padding:1rem;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
            <div style="color:var(--text-muted);font-size:0.875rem">
                Showing <?php echo number_format($offset + 1); ?> - <?php echo number_format(min($offset + $perPage, $totalBlocked)); ?> of <?php echo number_format($totalBlocked); ?>
            </div>
            <div style="display:flex;gap:0.5rem">
                <?php if ($page > 1): ?>
                <a href="?section=blocked_ips&page=<?php echo $page - 1; ?>&filter=<?php echo $filterType; ?>&search=<?php echo urlencode($searchIP); ?>&sort=<?php echo $sortBy; ?>&order=<?php echo $sortOrder; ?>" class="btn btn-secondary">
                    <i class="fas fa-chevron-left"></i>
                </a>
                <?php endif; ?>
                
                <div style="display:flex;gap:0.25rem">
                    <?php
                    $startPage = max(1, $page - 2);
                    $endPage = min($totalPages, $page + 2);
                    
                    for ($i = $startPage; $i <= $endPage; $i++):
                    ?>
                        <a href="?section=blocked_ips&page=<?php echo $i; ?>&filter=<?php echo $filterType; ?>&search=<?php echo urlencode($searchIP); ?>&sort=<?php echo $sortBy; ?>&order=<?php echo $sortOrder; ?>" 
                           class="btn <?php echo $i === $page ? 'btn-primary' : 'btn-secondary'; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
                
                <?php if ($page < $totalPages): ?>
                <a href="?section=blocked_ips&page=<?php echo $page + 1; ?>&filter=<?php echo $filterType; ?>&search=<?php echo urlencode($searchIP); ?>&sort=<?php echo $sortBy; ?>&order=<?php echo $sortOrder; ?>" class="btn btn-secondary">
                    <i class="fas fa-chevron-right"></i>
                </a>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <?php endif; ?>
    </div>
</div>

<script>
// Toggle duration field based on block type
document.getElementById('blockTypeSelect')?.addEventListener('change', function() {
    const durationGroup = document.getElementById('durationGroup');
    if (this.value === 'permanent') {
        durationGroup.style.display = 'none';
    } else {
        durationGroup.style.display = 'block';
    }
});

// Select all checkboxes
function toggleSelectAll(source) {
    const checkboxes = document.querySelectorAll('.ip-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.checked = source.checked;
    });
    updateSelectedCount();
}

// Update selected count
function updateSelectedCount() {
    const checked = document.querySelectorAll('.ip-checkbox:checked').length;
    const countEl = document.getElementById('selectedCount');
    if (countEl) {
        countEl.textContent = checked + ' selected';
    }
}

// Listen for checkbox changes
document.querySelectorAll('.ip-checkbox').forEach(checkbox => {
    checkbox.addEventListener('change', updateSelectedCount);
});
</script>
