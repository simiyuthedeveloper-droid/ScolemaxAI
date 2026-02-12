<!-- ANALYTICS DASHBOARD -->

<?php
// Initialize Logger if available
$logger = null;

if (class_exists('Logger')) {
    $logger = new Logger();
}

// Get time period filter
$period = isset($_GET['period']) ? $_GET['period'] : '7d';

// Map period to SQL interval
$periodMap = [
    '24h' => 'INTERVAL 24 HOUR',
    '7d' => 'INTERVAL 7 DAY',
    '30d' => 'INTERVAL 30 DAY',
    '90d' => 'INTERVAL 90 DAY',
];

$sqlInterval = $periodMap[$period] ?? 'INTERVAL 7 DAY';

// Get overall statistics
$stats = [
    'total_threats' => 0,
    'total_blocked_ips' => 0,
    'critical_threats' => 0,
    'unique_attackers' => 0,
    'blocked_attacks' => 0,
    'avg_threats_per_day' => 0,
];

try {
    // Total threats in period
    $result = $db->query("SELECT COUNT(*) as count FROM local_threats WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)");
    if ($result) {
        $stats['total_threats'] = $result->fetch_assoc()['count'];
    }
    
    // Total blocked IPs
    $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE blocked_at >= DATE_SUB(NOW(), $sqlInterval)");
    if ($result) {
        $stats['total_blocked_ips'] = $result->fetch_assoc()['count'];
    }
    
    // Critical threats
    $result = $db->query("SELECT COUNT(*) as count FROM local_threats WHERE severity = 'critical' AND detected_at >= DATE_SUB(NOW(), $sqlInterval)");
    if ($result) {
        $stats['critical_threats'] = $result->fetch_assoc()['count'];
    }
    
    // Unique attackers
    $result = $db->query("SELECT COUNT(DISTINCT source_ip) as count FROM local_threats WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)");
    if ($result) {
        $stats['unique_attackers'] = $result->fetch_assoc()['count'];
    }
    
    // Blocked attacks (threats that resulted in IP blocks)
    $result = $db->query("SELECT COUNT(DISTINCT lt.source_ip) as count FROM local_threats lt INNER JOIN blocked_ips bi ON lt.source_ip = bi.ip_address WHERE lt.detected_at >= DATE_SUB(NOW(), $sqlInterval)");
    if ($result) {
        $stats['blocked_attacks'] = $result->fetch_assoc()['count'];
    }
    
    // Calculate average per day
    $days = match($period) {
        '24h' => 1,
        '7d' => 7,
        '30d' => 30,
        '90d' => 90,
        default => 7,
    };
    $stats['avg_threats_per_day'] = $stats['total_threats'] > 0 ? round($stats['total_threats'] / $days, 1) : 0;
    
} catch (Exception $e) {
    // Error handling
}

// Get threat trends by day
$threatTrends = [];
try {
    $result = $db->query("
        SELECT DATE(detected_at) as date, COUNT(*) as count, 
               SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count
        FROM local_threats 
        WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)
        GROUP BY DATE(detected_at)
        ORDER BY date ASC
    ");
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $threatTrends[] = $row;
        }
    }
} catch (Exception $e) {
    // Error handling
}

// Get threat type breakdown
$threatTypeBreakdown = [];
try {
    $result = $db->query("
        SELECT threat_type, COUNT(*) as count,
               SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
               SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
               SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
               SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM local_threats
        WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)
        GROUP BY threat_type
        ORDER BY count DESC
        LIMIT 10
    ");
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $threatTypeBreakdown[] = $row;
        }
    }
} catch (Exception $e) {
    // Error handling
}

// Get severity distribution
$severityDistribution = [];
try {
    $result = $db->query("
        SELECT severity, COUNT(*) as count
        FROM local_threats
        WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)
        GROUP BY severity
        ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low')
    ");
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $severityDistribution[] = $row;
        }
    }
} catch (Exception $e) {
    // Error handling
}

// Get top attacking IPs
$topAttackers = [];
try {
    $result = $db->query("
        SELECT source_ip, COUNT(*) as attack_count,
               MAX(severity) as max_severity,
               MIN(detected_at) as first_seen,
               MAX(detected_at) as last_seen,
               GROUP_CONCAT(DISTINCT threat_type) as threat_types
        FROM local_threats
        WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)
        GROUP BY source_ip
        ORDER BY attack_count DESC
        LIMIT 10
    ");
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $topAttackers[] = $row;
        }
    }
} catch (Exception $e) {
    // Error handling
}

// Get hourly distribution
$hourlyDistribution = [];
try {
    $result = $db->query("
        SELECT HOUR(detected_at) as hour, COUNT(*) as count
        FROM local_threats
        WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval)
        GROUP BY HOUR(detected_at)
        ORDER BY hour ASC
    ");
    
    if ($result) {
        // Initialize all 24 hours
        for ($i = 0; $i < 24; $i++) {
            $hourlyDistribution[$i] = 0;
        }
        
        while ($row = $result->fetch_assoc()) {
            $hourlyDistribution[$row['hour']] = $row['count'];
        }
    }
} catch (Exception $e) {
    // Error handling
}

// Get target path analysis
$targetPaths = [];
try {
    $result = $db->query("
        SELECT target_path, COUNT(*) as hit_count,
               COUNT(DISTINCT source_ip) as unique_ips,
               MAX(severity) as max_severity
        FROM local_threats
        WHERE detected_at >= DATE_SUB(NOW(), $sqlInterval) AND target_path IS NOT NULL
        GROUP BY target_path
        ORDER BY hit_count DESC
        LIMIT 10
    ");
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $targetPaths[] = $row;
        }
    }
} catch (Exception $e) {
    // Error handling
}
?>

<!-- Period Filter -->
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-body" style="padding:1rem">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem">
            <h3 class="card-title" style="margin:0">Analytics Period</h3>
            <form method="GET" action="webui.php">
                <input type="hidden" name="section" value="analytics">
                <select name="period" class="form-control" onchange="this.form.submit()" style="min-width:150px">
                    <option value="24h" <?php echo $period === '24h' ? 'selected' : ''; ?>>Last 24 Hours</option>
                    <option value="7d" <?php echo $period === '7d' ? 'selected' : ''; ?>>Last 7 Days</option>
                    <option value="30d" <?php echo $period === '30d' ? 'selected' : ''; ?>>Last 30 Days</option>
                    <option value="90d" <?php echo $period === '90d' ? 'selected' : ''; ?>>Last 90 Days</option>
                </select>
            </form>
        </div>
    </div>
</div>

<!-- Key Metrics -->
<div class="stats-grid" style="margin-bottom:1.5rem">
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($stats['total_threats']); ?></div>
                <div class="stat-label">Total Threats</div>
            </div>
            <div class="stat-icon yellow"><i class="fas fa-exclamation-triangle"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($stats['critical_threats']); ?></div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-icon red"><i class="fas fa-skull-crossbones"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($stats['unique_attackers']); ?></div>
                <div class="stat-label">Unique Attackers</div>
            </div>
            <div class="stat-icon cyan"><i class="fas fa-user-secret"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($stats['total_blocked_ips']); ?></div>
                <div class="stat-label">Blocked IPs</div>
            </div>
            <div class="stat-icon blue"><i class="fas fa-ban"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($stats['avg_threats_per_day']); ?></div>
                <div class="stat-label">Avg Threats/Day</div>
            </div>
            <div class="stat-icon purple"><i class="fas fa-chart-line"></i></div>
        </div>
    </div>
    
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo number_format($stats['blocked_attacks']); ?></div>
                <div class="stat-label">Blocked Attacks</div>
            </div>
            <div class="stat-icon green"><i class="fas fa-shield-alt"></i></div>
        </div>
    </div>
</div>

<!-- Threat Trends Chart -->
<?php if (!empty($threatTrends)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-chart-area"></i> Threat Trends</h3>
    </div>
    <div class="card-body">
        <div style="height:300px;display:flex;align-items:end;gap:0.5rem;padding:1rem">
            <?php
            $maxCount = max(array_column($threatTrends, 'count'));
            foreach ($threatTrends as $trend):
                $height = $maxCount > 0 ? ($trend['count'] / $maxCount) * 100 : 0;
                $criticalPercent = $trend['count'] > 0 ? ($trend['critical_count'] / $trend['count']) * 100 : 0;
            ?>
            <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:0.25rem">
                <div style="font-size:0.7rem;color:var(--text-muted)"><?php echo $trend['count']; ?></div>
                <div style="width:100%;height:<?php echo $height; ?>%;background:linear-gradient(to top, <?php echo $criticalPercent > 50 ? 'var(--danger)' : 'var(--accent)'; ?>, var(--info));border-radius:4px 4px 0 0;min-height:2px" title="<?php echo $trend['count']; ?> threats (<?php echo $trend['critical_count']; ?> critical)"></div>
                <div style="font-size:0.65rem;color:var(--text-muted);writing-mode:vertical-rl;transform:rotate(180deg)">
                    <?php echo date('M d', strtotime($trend['date'])); ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Two Column Layout -->
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:1.5rem;margin-bottom:1.5rem">
    
    <!-- Severity Distribution -->
    <div class="card">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-chart-pie"></i> Severity Distribution</h3>
        </div>
        <div class="card-body">
            <?php if (!empty($severityDistribution)): ?>
            <?php
            $totalSeverity = array_sum(array_column($severityDistribution, 'count'));
            $severityColors = [
                'critical' => 'var(--danger)',
                'high' => 'var(--warning)',
                'medium' => 'var(--info)',
                'low' => 'var(--success)',
            ];
            ?>
            <div style="display:grid;gap:0.75rem">
                <?php foreach ($severityDistribution as $sev): ?>
                <?php
                $percentage = $totalSeverity > 0 ? ($sev['count'] / $totalSeverity) * 100 : 0;
                $color = $severityColors[$sev['severity']] ?? 'var(--accent)';
                ?>
                <div>
                    <div style="display:flex;justify-content:space-between;margin-bottom:0.25rem">
                        <span class="badge badge-<?php echo $sev['severity']; ?>" style="text-transform:uppercase">
                            <?php echo $sev['severity']; ?>
                        </span>
                        <span style="font-weight:600;color:var(--text)">
                            <?php echo number_format($sev['count']); ?> (<?php echo number_format($percentage, 1); ?>%)
                        </span>
                    </div>
                    <div style="background:rgba(59,130,246,0.1);border-radius:4px;height:8px;overflow:hidden">
                        <div style="background:<?php echo $color; ?>;height:100%;width:<?php echo $percentage; ?>%;transition:width 0.3s"></div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php else: ?>
            <div class="empty-state">
                <p>No severity data available</p>
            </div>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Hourly Distribution -->
    <div class="card">
        <div class="card-header">
            <h3 class="card-title"><i class="fas fa-clock"></i> Hourly Distribution (24h)</h3>
        </div>
        <div class="card-body">
            <?php if (!empty($hourlyDistribution)): ?>
            <?php $maxHourly = max($hourlyDistribution); ?>
            <div style="display:flex;align-items:end;gap:2px;height:150px">
                <?php for ($h = 0; $h < 24; $h++): ?>
                <?php
                $count = $hourlyDistribution[$h] ?? 0;
                $height = $maxHourly > 0 ? ($count / $maxHourly) * 100 : 0;
                ?>
                <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:0.25rem">
                    <div style="font-size:0.65rem;color:var(--text-muted)"><?php echo $count > 0 ? $count : ''; ?></div>
                    <div style="width:100%;height:<?php echo $height; ?>%;background:var(--accent);border-radius:2px 2px 0 0;min-height:<?php echo $count > 0 ? '2px' : '0'; ?>" title="<?php echo $count; ?> threats at <?php echo str_pad($h, 2, '0', STR_PAD_LEFT); ?>:00"></div>
                    <?php if ($h % 3 === 0): ?>
                    <div style="font-size:0.6rem;color:var(--text-muted)"><?php echo str_pad($h, 2, '0', STR_PAD_LEFT); ?></div>
                    <?php endif; ?>
                </div>
                <?php endfor; ?>
            </div>
            <?php else: ?>
            <div class="empty-state">
                <p>No hourly data available</p>
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Threat Type Breakdown -->
<?php if (!empty($threatTypeBreakdown)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-virus"></i> Threat Type Breakdown</h3>
    </div>
    <div class="card-body" style="padding:0">
        <div style="overflow-x:auto">
        <table>
            <thead>
                <tr>
                    <th>Threat Type</th>
                    <th>Total</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>Distribution</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($threatTypeBreakdown as $threat): ?>
                <tr>
                    <td>
                        <strong><?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $threat['threat_type']))); ?></strong>
                    </td>
                    <td><span class="badge badge-info"><?php echo number_format($threat['count']); ?></span></td>
                    <td><?php echo $threat['critical'] > 0 ? '<span class="badge badge-critical">' . $threat['critical'] . '</span>' : '-'; ?></td>
                    <td><?php echo $threat['high'] > 0 ? '<span class="badge badge-warning">' . $threat['high'] . '</span>' : '-'; ?></td>
                    <td><?php echo $threat['medium'] > 0 ? '<span class="badge badge-info">' . $threat['medium'] . '</span>' : '-'; ?></td>
                    <td><?php echo $threat['low'] > 0 ? '<span class="badge badge-success">' . $threat['low'] . '</span>' : '-'; ?></td>
                    <td style="width:200px">
                        <?php
                        $total = $threat['count'];
                        $crit = ($threat['critical'] / $total) * 100;
                        $high = ($threat['high'] / $total) * 100;
                        $med = ($threat['medium'] / $total) * 100;
                        $low = ($threat['low'] / $total) * 100;
                        ?>
                        <div style="display:flex;height:20px;border-radius:4px;overflow:hidden">
                            <?php if ($crit > 0): ?>
                            <div style="width:<?php echo $crit; ?>%;background:var(--danger)" title="<?php echo number_format($crit, 1); ?>% Critical"></div>
                            <?php endif; ?>
                            <?php if ($high > 0): ?>
                            <div style="width:<?php echo $high; ?>%;background:var(--warning)" title="<?php echo number_format($high, 1); ?>% High"></div>
                            <?php endif; ?>
                            <?php if ($med > 0): ?>
                            <div style="width:<?php echo $med; ?>%;background:var(--info)" title="<?php echo number_format($med, 1); ?>% Medium"></div>
                            <?php endif; ?>
                            <?php if ($low > 0): ?>
                            <div style="width:<?php echo $low; ?>%;background:var(--success)" title="<?php echo number_format($low, 1); ?>% Low"></div>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Top Attackers -->
<?php if (!empty($topAttackers)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-user-secret"></i> Top Attackers</h3>
    </div>
    <div class="card-body" style="padding:0">
        <div style="overflow-x:auto">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>IP Address</th>
                    <th>Attacks</th>
                    <th>Threat Types</th>
                    <th>Max Severity</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topAttackers as $index => $attacker): ?>
                <tr>
                    <td style="color:var(--text-muted)"><?php echo $index + 1; ?></td>
                    <td>
                        <code style="font-size:0.85rem"><?php echo htmlspecialchars($attacker['source_ip']); ?></code>
                    </td>
                    <td>
                        <span class="badge badge-danger" style="font-size:0.85rem">
                            <?php echo number_format($attacker['attack_count']); ?> attacks
                        </span>
                    </td>
                    <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis">
                        <?php
                        $types = explode(',', $attacker['threat_types']);
                        echo htmlspecialchars(implode(', ', array_slice($types, 0, 3)));
                        if (count($types) > 3) echo '...';
                        ?>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $attacker['max_severity']; ?>">
                            <?php echo ucfirst($attacker['max_severity']); ?>
                        </span>
                    </td>
                    <td style="font-size:0.8rem;color:var(--text-muted)">
                        <?php echo date('M d, H:i', strtotime($attacker['first_seen'])); ?>
                    </td>
                    <td style="font-size:0.8rem;color:var(--text-muted)">
                        <?php echo date('M d, H:i', strtotime($attacker['last_seen'])); ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Most Targeted Paths -->
<?php if (!empty($targetPaths)): ?>
<div class="card" style="margin-bottom:1.5rem">
    <div class="card-header">
        <h3 class="card-title"><i class="fas fa-crosshairs"></i> Most Targeted Paths</h3>
    </div>
    <div class="card-body" style="padding:0">
        <div style="overflow-x:auto">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Target Path</th>
                    <th>Hit Count</th>
                    <th>Unique IPs</th>
                    <th>Max Severity</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($targetPaths as $index => $path): ?>
                <tr>
                    <td style="color:var(--text-muted)"><?php echo $index + 1; ?></td>
                    <td style="font-family:monospace;font-size:0.8rem;max-width:400px;overflow:hidden;text-overflow:ellipsis" title="<?php echo htmlspecialchars($path['target_path']); ?>">
                        <?php echo htmlspecialchars($path['target_path']); ?>
                    </td>
                    <td>
                        <span class="badge badge-warning"><?php echo number_format($path['hit_count']); ?></span>
                    </td>
                    <td>
                        <span class="badge badge-info"><?php echo number_format($path['unique_ips']); ?></span>
                    </td>
                    <td>
                        <span class="badge badge-<?php echo $path['max_severity']; ?>">
                            <?php echo ucfirst($path['max_severity']); ?>
                        </span>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Export Button -->
<div class="card">
    <div class="card-body" style="padding:1rem;text-align:center">
        <p style="color:var(--text-muted);margin-bottom:1rem">
            <i class="fas fa-info-circle"></i> Export analytics data for further analysis
        </p>
        <button class="btn btn-primary" onclick="alert('Export feature coming soon!')">
            <i class="fas fa-download"></i> Export Analytics Report
        </button>
    </div>
</div>
