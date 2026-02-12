<!-- DASHBOARD VIEW -->

<!-- Stats Grid -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo intval($stats['total_threats_24h']); ?></div>
                <div class="stat-label">Threats (24h)</div>
            </div>
            <div class="stat-icon yellow"><i class="fas fa-exclamation-triangle"></i></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo intval($stats['critical_threats']); ?></div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-icon cyan"><i class="fas fa-fire"></i></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value"><?php echo intval($stats['blocked_ips_24h']); ?></div>
                <div class="stat-label">IPs Blocked</div>
            </div>
            <div class="stat-icon blue"><i class="fas fa-shield-alt"></i></div>
        </div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div>
                <div class="stat-value">Active</div>
                <div class="stat-label">WAF Status</div>
            </div>
            <div class="stat-icon green"><i class="fas fa-check-circle"></i></div>
        </div>
    </div>
</div>

<!-- Recent Threats -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Recent Threats</h3>
        <a href="webui.php?section=threats" style="color:var(--accent);text-decoration:none;font-weight:600">View All →</a>
    </div>
    <div class="card-body">
        <?php if (!empty($stats['recent_threats'])): ?>
        <div style="overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Target</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($stats['recent_threats'] as $threat): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($threat['threat_type']); ?></td>
                        <td><span class="badge badge-<?php echo $threat['severity']; ?>"><?php echo ucfirst($threat['severity']); ?></span></td>
                        <td><code><?php echo htmlspecialchars($threat['source_ip']); ?></code></td>
                        <td><?php echo htmlspecialchars(substr($threat['target_path'] ?? '/unknown', 0, 30)); ?></td>
                        <td><?php echo date('M d H:i', strtotime($threat['detected_at'])); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php else: ?>
        <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <p>No threats detected in the last 24 hours</p>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- Blocked IPs -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Blocked IPs</h3>
        <a href="webui.php?section=blocked_ips" style="color:var(--accent);text-decoration:none;font-weight:600">View All →</a>
    </div>
    <div class="card-body">
        <?php if (!empty($stats['blocked_ips'])): ?>
        <div style="overflow-x:auto">
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Threat Type</th>
                        <th>Reason</th>
                        <th>Blocked</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($stats['blocked_ips'] as $block): ?>
                    <tr>
                        <td><code><?php echo htmlspecialchars($block['ip_address']); ?></code></td>
                        <td><?php echo htmlspecialchars($block['threat_type'] ?? 'Unknown'); ?></td>
                        <td><?php echo htmlspecialchars($block['reason'] ?? '-'); ?></td>
                        <td><?php echo date('M d H:i', strtotime($block['blocked_at'])); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php else: ?>
        <div class="empty-state">
            <i class="fas fa-shield-check"></i>
            <p>No IPs blocked in the last 24 hours</p>
        </div>
        <?php endif; ?>
    </div>
</div>
