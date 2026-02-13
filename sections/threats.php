<!-- ADVANCED THREATS VIEW -->

<?php
// Initialize Logger and ThreatAnalyzer if available
$logger = null;
$analyzer = null;

if (class_exists('Logger')) {
    $logger = new Logger();
}

if (class_exists('ThreatAnalyzer')) {
    $analyzer = new ThreatAnalyzer($db);
}

// Handle threat actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    $response = ['success' => false, 'message' => ''];
    
    if ($action === 'analyze_threat' && isset($_POST['threat_id'])) {
        $threatId = intval($_POST['threat_id']);
        
        // Get threat data
        $stmt = $db->prepare("SELECT * FROM local_threats WHERE id = ?");
        $stmt->bind_param('i', $threatId);
        $stmt->execute();
        $threat = $stmt->get_result()->fetch_assoc();
        
        if ($threat && $analyzer) {
            $analysis = $analyzer->analyze($threat);
            $response['success'] = true;
            $response['analysis'] = $analysis;
        }
    }
    
    if ($action === 'delete_threat' && isset($_POST['threat_id'])) {
        $threatId = intval($_POST['threat_id']);
        $stmt = $db->prepare("DELETE FROM local_threats WHERE id = ?");
        $stmt->bind_param('i', $threatId);
        if ($stmt->execute()) {
            $response['success'] = true;
            $response['message'] = 'Threat deleted successfully';
        }
    }
}

// Get filter parameters
$filterSeverity = isset($_GET['severity']) ? $_GET['severity'] : 'all';
$filterType = isset($_GET['type']) ? $_GET['type'] : 'all';
$filterPeriod = isset($_GET['period']) ? $_GET['period'] : '24h';
$sortBy = isset($_GET['sort']) ? $_GET['sort'] : 'detected_at';
$sortOrder = isset($_GET['order']) && $_GET['order'] === 'asc' ? 'ASC' : 'DESC';
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$perPage = 20;
$offset = ($page - 1) * $perPage;

// Build query based on filters
$whereConditions = [];
$queryParams = [];
$paramTypes = '';

// Period filter
if ($filterPeriod !== 'all') {
    $periodMap = [
        '1h' => 'INTERVAL 1 HOUR',
        '24h' => 'INTERVAL 24 HOUR',
        '7d' => 'INTERVAL 7 DAY',
        '30d' => 'INTERVAL 30 DAY',
    ];
    
    if (isset($periodMap[$filterPeriod])) {
        $whereConditions[] = "detected_at >= DATE_SUB(NOW(), {$periodMap[$filterPeriod]})";
    }
}

// Severity filter
if ($filterSeverity !== 'all') {
    $whereConditions[] = "severity = ?";
    $queryParams[] = $filterSeverity;
    $paramTypes .= 's';
}

// Type filter
if ($filterType !== 'all') {
    $whereConditions[] = "threat_type = ?";
    $queryParams[] = $filterType;
    $paramTypes .= 's';
}

$whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';

// Get total count
$countQuery = "SELECT COUNT(*) as total FROM local_threats $whereClause";
$countStmt = $db->prepare($countQuery);
if (!empty($queryParams)) {
    $countStmt->bind_param($paramTypes, ...$queryParams);
}
$countStmt->execute();
$totalThreats = $countStmt->get_result()->fetch_assoc()['total'];
$totalPages = ceil($totalThreats / $perPage);

// Get threats with pagination
$allowedSortColumns = ['detected_at', 'severity', 'threat_type', 'source_ip'];
$sortColumn = in_array($sortBy, $allowedSortColumns) ? $sortBy : 'detected_at';

$threatsQuery = "SELECT * FROM local_threats $whereClause ORDER BY $sortColumn $sortOrder LIMIT ? OFFSET ?";
$threatsStmt = $db->prepare($threatsQuery);

$queryParams[] = $perPage;
$queryParams[] = $offset;
$paramTypes .= 'ii';

if (!empty($queryParams)) {
    $threatsStmt->bind_param($paramTypes, ...$queryParams);
}
$threatsStmt->execute();
$threats = $threatsStmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Get unique threat types for filter
$typesResult = $db->query("SELECT DISTINCT threat_type FROM local_threats ORDER BY threat_type");
$threatTypes = [];
while ($row = $typesResult->fetch_assoc()) {
    $threatTypes[] = $row['threat_type'];
}

// Get threat statistics
$statsQuery = "SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count,
    COUNT(DISTINCT source_ip) as unique_ips,
    COUNT(DISTINCT threat_type) as unique_types
    FROM local_threats $whereClause";

$statsStmt = $db->prepare($statsQuery);
if (!empty($whereConditions)) {
    // Remove the last two params (limit and offset) for stats
    $statsParams = array_slice($queryParams, 0, -2);
    $statsTypes = substr($paramTypes, 0, -2);
    if (!empty($statsParams)) {
        $statsStmt->bind_param($statsTypes, ...$statsParams);
    }
}
$statsStmt->execute();
$threatStats = $statsStmt->get_result()->fetch_assoc();
?>

<!-- Threat Statistics Cards -->
<div class="stats-grid" style="margin-bottom:1.5rem">
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($threatStats['total']); ?></div>
                <div class="stat-label">Total Threats</div>
            </div>
            <div class="stat-icon yellow"><i class="fas fa-exclamation-triangle"></i></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($threatStats['critical_count']); ?></div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-icon red"><i class="fas fa-skull-crossbones"></i></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($threatStats['unique_ips']); ?></div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-icon cyan"><i class="fas fa-network-wired"></i></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($threatStats['unique_types']); ?></div>
                <div class="stat-label">Attack Types</div>
            </div>
            <div class="stat-icon purple"><i class="fas fa-shield-virus"></i></div>
        </div>
    </div>
</div>

<!-- Filters and Actions -->
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-body" style="padding:1rem">
        <form method="GET" action="webui.php" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;align-items:end">
            <input type="hidden" name="section" value="threats">
            
            <div class="form-group" style="margin:0">
                <label class="form-label" style="margin-bottom:0.25rem">Period</label>
                <select name="period" class="form-control" onchange="this.form.submit()">
                    <option value="1h" <?php echo $filterPeriod === '1h' ? 'selected' : ''; ?>>Last Hour</option>
                    <option value="24h" <?php echo $filterPeriod === '24h' ? 'selected' : ''; ?>>Last 24 Hours</option>
                    <option value="7d" <?php echo $filterPeriod === '7d' ? 'selected' : ''; ?>>Last 7 Days</option>
                    <option value="30d" <?php echo $filterPeriod === '30d' ? 'selected' : ''; ?>>Last 30 Days</option>
                    <option value="all" <?php echo $filterPeriod === 'all' ? 'selected' : ''; ?>>All Time</option>
                </select>
            </div>
            
            <div class="form-group" style="margin:0">
                <label class="form-label" style="margin-bottom:0.25rem">Severity</label>
                <select name="severity" class="form-control" onchange="this.form.submit()">
                    <option value="all" <?php echo $filterSeverity === 'all' ? 'selected' : ''; ?>>All Severities</option>
                    <option value="critical" <?php echo $filterSeverity === 'critical' ? 'selected' : ''; ?>>Critical</option>
                    <option value="high" <?php echo $filterSeverity === 'high' ? 'selected' : ''; ?>>High</option>
                    <option value="medium" <?php echo $filterSeverity === 'medium' ? 'selected' : ''; ?>>Medium</option>
                    <option value="low" <?php echo $filterSeverity === 'low' ? 'selected' : ''; ?>>Low</option>
                </select>
            </div>
            
            <div class="form-group" style="margin:0">
                <label class="form-label" style="margin-bottom:0.25rem">Threat Type</label>
                <select name="type" class="form-control" onchange="this.form.submit()">
                    <option value="all" <?php echo $filterType === 'all' ? 'selected' : ''; ?>>All Types</option>
                    <?php foreach ($threatTypes as $type): ?>
                        <option value="<?php echo htmlspecialchars($type); ?>" <?php echo $filterType === $type ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $type))); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            
            <div class="form-group" style="margin:0">
                <label class="form-label" style="margin-bottom:0.25rem">Sort By</label>
                <select name="sort" class="form-control" onchange="this.form.submit()">
                    <option value="detected_at" <?php echo $sortBy === 'detected_at' ? 'selected' : ''; ?>>Time Detected</option>
                    <option value="severity" <?php echo $sortBy === 'severity' ? 'selected' : ''; ?>>Severity</option>
                    <option value="threat_type" <?php echo $sortBy === 'threat_type' ? 'selected' : ''; ?>>Threat Type</option>
                    <option value="source_ip" <?php echo $sortBy === 'source_ip' ? 'selected' : ''; ?>>Source IP</option>
                </select>
            </div>
            
            <div style="display:flex;gap:0.5rem">
                <button type="submit" class="btn btn-primary" style="flex:1">
                    <i class="fas fa-filter"></i> Filter
                </button>
                <a href="webui.php?section=threats" class="btn btn-secondary">
                    <i class="fas fa-redo"></i>
                </a>
            </div>
        </form>
    </div>
</div>

<!-- Threats Table -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Detected Threats (<?php echo number_format($totalThreats); ?>)</h3>
        <div style="display:flex;gap:0.5rem">
            <button class="btn btn-secondary" onclick="window.location.reload()" title="Refresh">
                <i class="fas fa-sync-alt"></i>
            </button>
        </div>
    </div>
    <div class="card-body" style="padding:0">
        <?php if (!empty($threats)): ?>
        <div style="overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th style="width:40px">#</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Target</th>
                        <th>Pattern</th>
                        <th>Detected</th>
                        <th style="width:120px">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($threats as $index => $threat): ?>
                    <tr id="threat-<?php echo $threat['id']; ?>">
                        <td style="color:var(--text-muted)"><?php echo $offset + $index + 1; ?></td>
                        
                        <td>
                            <div style="display:flex;align-items:center;gap:0.5rem">
                                <?php
                                $typeIcons = [
                                    'sql_injection' => 'database',
                                    'xss' => 'code',
                                    'brute_force' => 'user-lock',
                                    'ddos' => 'bomb',
                                    'path_traversal' => 'folder-open',
                                    'command_injection' => 'terminal',
                                    'file_upload' => 'file-upload',
                                ];
                                $icon = $typeIcons[$threat['threat_type']] ?? 'shield-alt';
                                ?>
                                <i class="fas fa-<?php echo $icon; ?>" style="color:var(--warning)"></i>
                                <span style="font-weight:500"><?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $threat['threat_type']))); ?></span>
                            </div>
                        </td>
                        
                        <td>
                            <span class="badge badge-<?php echo $threat['severity']; ?>">
                                <?php echo ucfirst($threat['severity']); ?>
                            </span>
                        </td>
                        
                        <td>
                            <code style="font-size:0.8rem"><?php echo htmlspecialchars($threat['source_ip']); ?></code>
                        </td>
                        
                        <td style="max-width:200px">
                            <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?php echo htmlspecialchars($threat['target_path'] ?? '/'); ?>">
                                <?php echo htmlspecialchars(substr($threat['target_path'] ?? '/', 0, 30)); ?>
                            </div>
                        </td>
                        
                        <td style="max-width:250px">
                            <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:0.75rem;color:var(--text-muted)" 
                                 title="<?php echo htmlspecialchars($threat['attack_pattern'] ?? ''); ?>">
                                <?php echo htmlspecialchars(substr($threat['attack_pattern'] ?? '-', 0, 40)); ?>
                            </div>
                        </td>
                        
                        <td>
                            <div style="font-size:0.8rem"><?php echo date('M d', strtotime($threat['detected_at'])); ?></div>
                            <div style="font-size:0.75rem;color:var(--text-muted)"><?php echo date('H:i:s', strtotime($threat['detected_at'])); ?></div>
                        </td>
                        
                        <td>
                            <div style="display:flex;gap:0.25rem">
                                <button class="btn btn-primary" style="padding:0.3rem 0.6rem;font-size:0.75rem" 
                                        onclick="viewThreatDetails(<?php echo $threat['id']; ?>)" title="View Details">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-secondary" style="padding:0.3rem 0.6rem;font-size:0.75rem" 
                                        onclick="analyzeThreat(<?php echo $threat['id']; ?>)" title="Analyze">
                                    <i class="fas fa-brain"></i>
                                </button>
                                <button class="btn btn-danger" style="padding:0.3rem 0.6rem;font-size:0.75rem" 
                                        onclick="deleteThreat(<?php echo $threat['id']; ?>)" title="Delete">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        
        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
        <div style="padding:1rem;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
            <div style="color:var(--text-muted);font-size:0.875rem">
                Showing <?php echo number_format($offset + 1); ?> - <?php echo number_format(min($offset + $perPage, $totalThreats)); ?> of <?php echo number_format($totalThreats); ?>
            </div>
            <div style="display:flex;gap:0.5rem">
                <?php if ($page > 1): ?>
                    <a href="?section=threats&period=<?php echo $filterPeriod; ?>&severity=<?php echo $filterSeverity; ?>&type=<?php echo $filterType; ?>&sort=<?php echo $sortBy; ?>&page=<?php echo $page - 1; ?>" 
                       class="btn btn-secondary">
                        <i class="fas fa-chevron-left"></i>
                    </a>
                <?php endif; ?>
                
                <div style="display:flex;gap:0.25rem">
                    <?php
                    $startPage = max(1, $page - 2);
                    $endPage = min($totalPages, $page + 2);
                    
                    for ($i = $startPage; $i <= $endPage; $i++):
                    ?>
                        <a href="?section=threats&period=<?php echo $filterPeriod; ?>&severity=<?php echo $filterSeverity; ?>&type=<?php echo $filterType; ?>&sort=<?php echo $sortBy; ?>&page=<?php echo $i; ?>" 
                           class="btn <?php echo $i === $page ? 'btn-primary' : 'btn-secondary'; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
                
                <?php if ($page < $totalPages): ?>
                    <a href="?section=threats&period=<?php echo $filterPeriod; ?>&severity=<?php echo $filterSeverity; ?>&type=<?php echo $filterType; ?>&sort=<?php echo $sortBy; ?>&page=<?php echo $page + 1; ?>" 
                       class="btn btn-secondary">
                        <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <?php else: ?>
        <div class="empty-state">
            <i class="fas fa-shield-check"></i>
            <p>No threats found matching your filters</p>
            <p style="margin-top:0.5rem">
                <a href="webui.php?section=threats" class="btn btn-primary">Clear Filters</a>
            </p>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- Threat Details Modal (Hidden by default) -->
<div id="threatModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:9999;overflow-y:auto">
    <div style="max-width:800px;margin:2rem auto;background:var(--card-bg);border-radius:8px;border:1px solid var(--border)">
        <div style="padding:1.25rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
            <h3 style="color:var(--text);margin:0">Threat Details</h3>
            <button onclick="closeModal()" style="background:none;border:none;color:var(--text);font-size:1.5rem;cursor:pointer">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div id="modalContent" style="padding:1.25rem">
            <!-- Content loaded via JavaScript -->
        </div>
    </div>
</div>

<script>
function viewThreatDetails(threatId) {
    const threats = <?php echo json_encode($threats); ?>;
    const threat = threats.find(t => t.id == threatId);
    
    if (!threat) return;
    
    document.getElementById('threatModal').style.display = 'block';
    displayThreatDetails(threat);
}

function displayThreatDetails(threat) {
    const html = `
        <div style="display:grid;gap:1rem">
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Threat ID:</div>
                <div style="color:var(--text)">${threat.id}</div>
            </div>
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Type:</div>
                <div style="color:var(--text)">${threat.threat_type.replace(/_/g, ' ').toUpperCase()}</div>
            </div>
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Severity:</div>
                <div><span class="badge badge-${threat.severity}">${threat.severity.toUpperCase()}</span></div>
            </div>
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Source IP:</div>
                <div style="color:var(--text);font-family:monospace">${threat.source_ip}</div>
            </div>
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Target Path:</div>
                <div style="color:var(--text);word-break:break-all">${threat.target_path || 'N/A'}</div>
            </div>
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Attack Pattern:</div>
                <div style="color:var(--text);font-family:monospace;font-size:0.8rem;word-break:break-all">${threat.attack_pattern || 'N/A'}</div>
            </div>
            <div style="display:grid;grid-template-columns:150px 1fr;gap:0.5rem;padding:0.75rem;background:rgba(59,130,246,0.05);border-radius:6px">
                <div style="font-weight:600;color:var(--text)">Detected:</div>
                <div style="color:var(--text)">${threat.detected_at}</div>
            </div>
        </div>
    `;
    
    document.getElementById('modalContent').innerHTML = html;
}

function analyzeThreat(threatId) {
    alert('Threat analysis feature - Coming soon!\nThis will provide detailed AI-powered threat analysis.');
}

function deleteThreat(threatId) {
    if (!confirm('Delete this threat record?')) return;
    
    const formData = new FormData();
    formData.append('action', 'delete_threat');
    formData.append('threat_id', threatId);
    
    fetch(window.location.href, {
        method: 'POST',
        body: formData
    })
    .then(() => {
        document.getElementById('threat-' + threatId).remove();
        window.location.reload();
    });
}

function closeModal() {
    document.getElementById('threatModal').style.display = 'none';
}

// Close modal on outside click
document.getElementById('threatModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});

// Close modal on ESC key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeModal();
});
</script>
