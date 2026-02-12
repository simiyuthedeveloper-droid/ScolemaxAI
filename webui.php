<?php
/**
 * SMV Security - WAF WebUI Dashboard
 * Professional customer interface for monitoring WAF threats
 * Displays threats, blocked IPs, and analytics in real-time
 */

// Start session FIRST
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if customer is logged in
if (!isset($_SESSION['webui_customer_id']) || empty($_SESSION['webui_customer_id'])) {
    header('Location: webui-auth.php?page=login');
    exit;
}

// Get customer info from session
$customer_id = $_SESSION['webui_customer_id'];
$company_name = $_SESSION['webui_company'] ?? 'Unknown Company';
$customer_email = $_SESSION['webui_email'] ?? '';

// Get current section from URL
$current_section = isset($_GET['section']) ? preg_replace('/[^a-z_]/', '', $_GET['section']) : 'dashboard';
if (empty($current_section)) {
    $current_section = 'dashboard';
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: webui-auth.php?page=login&message=Logged out successfully');
    exit;
}

// Database connection - try to load from config.php first
$db_host = 'localhost';
$db_user = 'scolema3_wafuser';
$db_pass = 'wafuser@2026';
$db_name = 'scolema3_waf';

// Try to load config.php if it exists
if (file_exists('config.php')) {
    require_once 'config.php';
    $db_host = defined('DB_HOST') ? DB_HOST : 'localhost';
    $db_user = defined('DB_USER') ? DB_USER : 'root';
    $db_pass = defined('DB_PASS') ? DB_PASS : '';
    $db_name = defined('DB_NAME') ? DB_NAME : 'scolema3_waf';
}

$db = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($db->connect_error) {
    die('<h2 style="color:red">Database Connection Error</h2>' .
        '<p>Host: ' . htmlspecialchars($db_host) . '</p>' .
        '<p>User: ' . htmlspecialchars($db_user) . '</p>' .
        '<p>Error: ' . htmlspecialchars($db->connect_error) . '</p>' .
        '<p><strong>Solution:</strong></p>' .
        '<ol>' .
        '<li>Check your config.php file for correct DB_PASS</li>' .
        '<li>Make sure MySQL/MariaDB is running</li>' .
        '<li>Verify database name exists: ' . htmlspecialchars($db_name) . '</li>' .
        '</ol>');
}
$db->set_charset('utf8mb4');

// Get dashboard statistics (available to all sections)
$stats = [
    'total_threats_24h' => 0,
    'critical_threats' => 0,
    'blocked_ips_24h' => 0,
    'recent_threats' => [],
    'threat_breakdown' => [],
    'blocked_ips' => [],
];

try {
    // Threats in last 24 hours
    $result = $db->query("SELECT COUNT(*) as count FROM local_threats WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    if ($result) {
        $row = $result->fetch_assoc();
        $stats['total_threats_24h'] = $row['count'] ?? 0;
    }
    
    // Critical threats
    $result = $db->query("SELECT COUNT(*) as count FROM local_threats WHERE severity = 'critical' AND detected_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    if ($result) {
        $row = $result->fetch_assoc();
        $stats['critical_threats'] = $row['count'] ?? 0;
    }
    
    // Blocked IPs in last 24 hours
    $result = $db->query("SELECT COUNT(*) as count FROM blocked_ips WHERE blocked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    if ($result) {
        $row = $result->fetch_assoc();
        $stats['blocked_ips_24h'] = $row['count'] ?? 0;
    }
    
    // Recent threats
    $result = $db->query("SELECT id, threat_type, severity, source_ip, target_path, detected_at FROM local_threats ORDER BY detected_at DESC LIMIT 5");
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $stats['recent_threats'][] = $row;
        }
    }
    
    // Threat type breakdown
    $result = $db->query("SELECT threat_type, COUNT(*) as count, severity FROM local_threats WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY threat_type, severity ORDER BY count DESC LIMIT 10");
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $stats['threat_breakdown'][] = $row;
        }
    }
    
    // Recently blocked IPs
    $result = $db->query("SELECT ip_address, reason, threat_type, blocked_at FROM blocked_ips ORDER BY blocked_at DESC LIMIT 5");
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $stats['blocked_ips'][] = $row;
        }
    }
    
} catch (Exception $e) {
    error_log("Dashboard stats error: " . $e->getMessage());
}


// Load Logger logic class for Logger sections
if (in_array($current_section, ['blocked_ips', 'threats', 'analytics'])) {
    require_once 'includes/Logger.php';
}

// Load threat analyzer logic class for IP Blocker sections
if (in_array($current_section, ['blocked_ips', 'threats', 'analytics'])) {
    require_once 'includes/ThreatAnalyzer.php';
}

// Load threat blocker logic class for Threat analysis sections
if (in_array($current_section, ['blocked_ips', 'threats', 'analytics'])) {
    require_once 'includes/ThreatBlocker.php';
}

// Load threat Scolemax api class for Automated response sections
if (in_array($current_section, ['integrations', 'settings'])) {
    require_once 'includes/ScoleMaxControlAPI.php';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $current_section))); ?> - SMV Security WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--primary:#0a0e1a;--card-bg:#111827;--accent:#3b82f6;--success:#4ade80;--danger:#ef4444;--warning:#fbbf24;--info:#60a5fa;--border:rgba(59,130,246,0.1);--text:#e5e7eb;--text-muted:#9ca3af;--sidebar-width:260px;--topbar-height:60px}
body{font-family:'Inter',sans-serif;font-size:13px;line-height:1.6;background:var(--primary);color:var(--text);background-image:radial-gradient(circle at 20% 50%,rgba(37,99,235,.05) 0%,transparent 50%),radial-gradient(circle at 80% 80%,rgba(59,130,246,.05) 0%,transparent 50%)}
.sidebar{position:fixed;top:0;left:0;height:100vh;width:var(--sidebar-width);background:var(--card-bg);border-right:1px solid var(--border);z-index:1000;overflow-y:auto}
.sidebar-brand{padding:1.2rem 1.5rem;border-bottom:1px solid var(--border);background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)}
.sidebar-brand h2{color:#fff;font-size:1.3rem;font-weight:700;letter-spacing:-0.5px;margin-bottom:0.25rem}
.sidebar-brand p{color:rgba(255,255,255,0.9);font-size:0.75rem;font-weight:500}
.sidebar-nav{padding:0.75rem 0}
.nav-section{padding:0.5rem 1.5rem 0.25rem;color:var(--text-muted);font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.nav-item{margin:0.15rem 0.75rem}
.nav-link{display:flex;align-items:center;padding:0.65rem 1rem;color:var(--text);text-decoration:none;border-radius:6px;transition:all 0.2s ease;font-size:0.875rem;font-weight:500}
.nav-link:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.nav-link.active{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;font-weight:600;box-shadow:0 4px 12px rgba(59,130,246,0.3)}
.nav-link i{width:18px;margin-right:0.75rem;font-size:0.95rem;text-align:center}
.nav-badge{margin-left:auto;background:var(--danger);color:#fff;font-size:0.7rem;padding:0.15rem 0.5rem;border-radius:10px;font-weight:600}
.main-wrapper{margin-left:var(--sidebar-width);min-height:100vh;transition:margin-left 0.3s ease}
.topbar{background:var(--card-bg);height:var(--topbar-height);border-bottom:1px solid var(--border);padding:0 1.5rem;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}
.topbar-left{display:flex;align-items:center;gap:1rem}
.topbar-right{display:flex;align-items:center;gap:1.5rem}
.topbar-icon{background:none;border:none;color:var(--text);cursor:pointer;font-size:1.1rem;padding:0.5rem;border-radius:6px;transition:all 0.2s}
.topbar-icon:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.topbar-user{display:flex;align-items:center;gap:0.75rem;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;transition:background 0.2s}
.user-avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:0.8rem}
.user-info{display:flex;flex-direction:column}
.user-name{font-weight:600;font-size:0.85rem;color:var(--text)}
.user-role{font-size:0.75rem;color:var(--text-muted)}
.content{padding:1.5rem}
.page-header{margin-bottom:1.5rem}
.page-title{font-size:1.5rem;font-weight:700;color:var(--text);margin-bottom:0.25rem;background:linear-gradient(135deg,#3b82f6 0%,#60a5fa 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.page-subtitle{font-size:0.875rem;color:var(--text-muted)}
.card{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;margin-bottom:1.5rem;transition:all 0.3s}
.card:hover{border-color:rgba(59,130,246,0.3);box-shadow:0 4px 16px rgba(59,130,246,0.1)}
.card-header{padding:1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.card-title{font-size:1rem;font-weight:600;color:var(--text)}
.card-body{padding:1.25rem}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.25rem;margin-bottom:1.5rem}
.stat-card{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:1.25rem;transition:all 0.3s;cursor:pointer;position:relative;overflow:hidden}
.stat-card:hover{transform:translateY(-2px);border-color:rgba(59,130,246,0.4);box-shadow:0 8px 24px rgba(59,130,246,0.15)}
.stat-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.75rem}
.stat-icon{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:#fff;box-shadow:0 4px 12px rgba(0,0,0,0.2)}
.stat-icon.blue{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)}
.stat-icon.green{background:linear-gradient(135deg,#4ade80 0%,#22c55e 100%)}
.stat-icon.yellow{background:linear-gradient(135deg,#fbbf24 0%,#f59e0b 100%)}
.stat-icon.cyan{background:linear-gradient(135deg,#06b6d4 0%,#0891b2 100%)}
.stat-icon.red{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%)}
.stat-icon.purple{background:linear-gradient(135deg,#a855f7 0%,#9333ea 100%)}
.stat-value{font-size:1.75rem;font-weight:700;color:var(--text);line-height:1}
.stat-label{font-size:0.8rem;color:var(--text-muted);margin-top:0.25rem}
.badge{display:inline-flex;align-items:center;padding:0.3rem 0.65rem;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
.badge-critical{background:rgba(239,68,68,0.2);color:var(--danger)}
.badge-high{background:rgba(251,191,36,0.2);color:var(--warning)}
.badge-medium{background:rgba(59,130,246,0.2);color:var(--info)}
.badge-low{background:rgba(74,222,128,0.2);color:var(--success)}
.badge-success{background:rgba(74,222,128,0.2);color:var(--success)}
.badge-warning{background:rgba(251,191,36,0.2);color:var(--warning)}
.badge-danger{background:rgba(239,68,68,0.2);color:var(--danger)}
.badge-info{background:rgba(59,130,246,0.2);color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:0.875rem}
table thead{background:rgba(59,130,246,0.05)}
table th{padding:0.75rem;text-align:left;color:var(--text);font-weight:600;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.3px;border-bottom:2px solid var(--border)}
table td{padding:0.875rem 0.75rem;border-bottom:1px solid var(--border);vertical-align:middle;color:var(--text)}
table tbody tr:hover{background:rgba(59,130,246,0.05)}
.empty-state{text-align:center;padding:2rem;color:var(--text-muted)}
.empty-state i{font-size:2rem;opacity:0.5;margin-bottom:0.5rem;display:block}
.btn{display:inline-block;padding:0.5rem 1rem;border:none;border-radius:6px;font-size:0.875rem;font-weight:600;cursor:pointer;transition:all 0.2s;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff}
.btn-primary:hover{box-shadow:0 4px 12px rgba(59,130,246,0.4)}
.btn-success{background:var(--success);color:#fff}
.btn-danger{background:var(--danger);color:#fff}
.btn-secondary{background:rgba(59,130,246,0.1);color:var(--accent)}
.form-group{margin-bottom:1rem}
.form-label{display:block;margin-bottom:0.5rem;color:var(--text);font-weight:500;font-size:0.875rem}
.form-control{width:100%;padding:0.65rem;background:rgba(59,130,246,0.05);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.875rem}
.form-control:focus{outline:none;border-color:var(--accent);background:rgba(59,130,246,0.1)}
@media(max-width:768px){
.sidebar{transform:translateX(-100%)}
.main-wrapper{margin-left:0}
.stats-grid{grid-template-columns:1fr}
}
    </style>
</head>
<body>
<!-- Sidebar -->
<aside class="sidebar">
    <div class="sidebar-brand">
        <h2>ЁЯЫбя╕П SMV Security</h2>
        <p>WAF Dashboard</p>
    </div>

    <nav class="sidebar-nav">
        <div class="nav-section">Dashboard</div>
        <div class="nav-item">
            <a href="webui.php?section=dashboard" class="nav-link <?php echo $current_section === 'dashboard' ? 'active' : ''; ?>">
                <i class="fas fa-chart-line"></i>
                <span>Overview</span>
            </a>
        </div>

        <div class="nav-section">Monitoring</div>
        <div class="nav-item">
            <a href="webui.php?section=threats" class="nav-link <?php echo $current_section === 'threats' ? 'active' : ''; ?>">
                <i class="fas fa-shield-alt"></i>
                <span>Threats</span>
                <?php if ($stats['total_threats_24h'] > 0): ?>
                    <span class="nav-badge"><?php echo $stats['total_threats_24h']; ?></span>
                <?php endif; ?>
            </a>
        </div>

        <div class="nav-item">
            <a href="webui.php?section=blocked_ips" class="nav-link <?php echo $current_section === 'blocked_ips' ? 'active' : ''; ?>">
                <i class="fas fa-ban"></i>
                <span>Blocked IPs</span>
            </a>
        </div>

        <div class="nav-item">
            <a href="webui.php?section=analytics" class="nav-link <?php echo $current_section === 'analytics' ? 'active' : ''; ?>">
                <i class="fas fa-chart-bar"></i>
                <span>Analytics</span>
            </a>
        </div>

        <div class="nav-section">Configuration</div>
        <div class="nav-item">
            <a href="webui.php?section=integrations" class="nav-link <?php echo $current_section === 'integrations' ? 'active' : ''; ?>">
                <i class="fas fa-plug"></i>
                <span>Integrations</span>
            </a>
        </div>

        <div class="nav-item">
            <a href="webui.php?section=settings" class="nav-link <?php echo $current_section === 'settings' ? 'active' : ''; ?>">
                <i class="fas fa-cog"></i>
                <span>Settings</span>
            </a>
        </div>

        <div class="nav-section">Account</div>
        <div class="nav-item">
            <a href="webui.php?logout=1" class="nav-link" style="color:var(--danger)" onclick="return confirm('Logout?')">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
            </a>
        </div>
    </nav>
</aside>

<!-- Main Wrapper -->
<div class="main-wrapper">
    <!-- Top Bar -->
    <header class="topbar">
        <div class="topbar-left">
            <span style="color:var(--accent);font-weight:600"><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $current_section))); ?></span>
        </div>

        <div class="topbar-right">
            <button class="topbar-icon" title="Notifications">
                <i class="fas fa-bell"></i>
            </button>
            <div class="topbar-user">
                <div class="user-avatar">
                    <?php echo strtoupper(substr($company_name, 0, 2)); ?>
                </div>
                <div class="user-info">
                    <div class="user-name"><?php echo htmlspecialchars($company_name); ?></div>
                    <div class="user-role">Customer</div>
                </div>
            </div>
        </div>
    </header>

    <!-- Content Area -->
    <div class="content">
        <div class="page-header">
            <h1 class="page-title"><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $current_section))); ?></h1>
            <p class="page-subtitle">Welcome back, <?php echo htmlspecialchars($company_name); ?>!</p>
        </div>

        <!-- Dynamic Section Loading -->
        <?php
        // Define section file mapping
        $section_file = "sections/{$current_section}.php";
        
        // Check if section file exists
        if (file_exists($section_file)) {
            // Include the section file
            require_once $section_file;
        } else {
            // Section not found - show error
            ?>
            <div class="card">
                <div class="card-body">
                    <div class="empty-state">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>Section not found: <?php echo htmlspecialchars($current_section); ?></p>
                        <p style="margin-top:1rem"><a href="webui.php?section=dashboard" class="btn btn-primary">Go to Dashboard</a></p>
                    </div>
                </div>
            </div>
            <?php
        }
        ?>
    </div>
</div>
</body>
</html>
