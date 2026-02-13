<?php
/**
 * SMV Security - Control Center Staff Dashboard
 * Main dashboard for staff monitoring and management
 */

// Start output buffering FIRST (before anything else)
ob_start();

// Start session FIRST before any includes
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'config.php';

// Debug: Check session data
// error_log("Session data: " . json_encode($_SESSION));

// Check if staff is logged in
if (!isset($_SESSION['staff_id']) || empty($_SESSION['staff_id'])) {
    header('Location: auth.php?page=login');
    exit;
}

// Get current staff info
$staff_id = $_SESSION['staff_id'];
$staff_email = $_SESSION['staff_email'] ?? '';
$staff_name = $_SESSION['staff_name'] ?? '';
$staff_role = $_SESSION['staff_role'] ?? '';

// Get current section from URL
$current_section = sanitize($_GET['section'] ?? 'dashboard');

// Validate section name (security)
if (!preg_match('/^[a-z_]+$/', $current_section)) {
    $current_section = 'dashboard';
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: auth.php?page=login&message=Logged out successfully');
    exit;
}

// Get staff info from database
$admin = null;
try {
    $db = getDB();
    $stmt = $db->prepare(
        "SELECT id, username, email, full_name, role, is_active, last_login FROM staff_users WHERE id = ?"
    );
    
    $stmt->bind_param("i", $staff_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $admin = $result->fetch_assoc();
    
    if (!$admin) {
        logMessage("Staff member not found: $staff_id", 'warning');
        session_destroy();
        header('Location: auth.php?page=login&message=Account not found');
        exit;
    }
    
    if (!$admin['is_active']) {
        logMessage("Staff member deactivated: $staff_id", 'warning');
        session_destroy();
        header('Location: auth.php?page=login&message=Your account has been deactivated');
        exit;
    }
} catch (Exception $e) {
    logMessage("Dashboard error: " . $e->getMessage(), 'error');
    $admin = ['username' => 'Admin', 'full_name' => 'Administrator', 'role' => 'admin', 'id' => $staff_id];
}

// Get dashboard statistics
function getDashboardStats($db) {
    try {
        $stats = [
            'total_customers' => 0,
            'total_threats_24h' => 0,
            'critical_threats' => 0,
            'active_waf_systems' => 0,
            'pending_escalations' => 0,
            'recent_threats' => []
        ];
        
        // Total customers
        $result = $db->query("SELECT COUNT(*) as count FROM customers WHERE is_active = 1");
        if ($result) {
            $row = $result->fetch_assoc();
            $stats['total_customers'] = $row['count'] ?? 0;
        }
        
        // Threats in last 24 hours
        $result = $db->query(
            "SELECT COUNT(*) as count FROM threat_intelligence WHERE reported_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
        if ($result) {
            $row = $result->fetch_assoc();
            $stats['total_threats_24h'] = $row['count'] ?? 0;
        }
        
        // Critical threats
        $result = $db->query(
            "SELECT COUNT(*) as count FROM threat_intelligence WHERE severity = 'critical' AND reported_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
        if ($result) {
            $row = $result->fetch_assoc();
            $stats['critical_threats'] = $row['count'] ?? 0;
        }
        
        // Active WAF systems
        $result = $db->query("SELECT COUNT(*) as count FROM customers WHERE installation_status = 'installed' AND is_active = 1");
        if ($result) {
            $row = $result->fetch_assoc();
            $stats['active_waf_systems'] = $row['count'] ?? 0;
        }
        
        // Pending NIS escalations
        $result = $db->query("SELECT COUNT(*) as count FROM nis_escalations WHERE status = 'pending'");
        if ($result) {
            $row = $result->fetch_assoc();
            $stats['pending_escalations'] = $row['count'] ?? 0;
        }
        
        // Recent threats
        $result = $db->query(
            "SELECT id, threat_type, severity, source_country, reported_at FROM threat_intelligence ORDER BY reported_at DESC LIMIT 5"
        );
        
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $stats['recent_threats'][] = $row;
            }
        }
        
        return $stats;
    } catch (Exception $e) {
        logMessage("Error getting dashboard stats: " . $e->getMessage(), 'error');
        return null;
    }
}

$stats = getDashboardStats($db);


// Load Email logic class for Email sections
if (in_array($current_section, ['email_config', 'email_test', 'email_manage'])) {
    require_once 'integrations/email.php';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo ucfirst(str_replace('_', ' ', $current_section)); ?> - <?php echo APP_NAME; ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--primary:#0a0e1a;--primary-dark:#060913;--card-bg:#111827;--accent:#3b82f6;--accent-hover:#2563eb;--success:#4ade80;--danger:#ef4444;--warning:#fbbf24;--info:#60a5fa;--border:rgba(59,130,246,0.1);--text:#e5e7eb;--text-muted:#9ca3af;--sidebar-width:260px;--topbar-height:60px}
body{font-family:'Inter',sans-serif;font-size:13px;line-height:1.6;background:var(--primary);color:var(--text);background-image:radial-gradient(circle at 20% 50%,rgba(37,99,235,.05) 0%,transparent 50%),radial-gradient(circle at 80% 80%,rgba(59,130,246,.05) 0%,transparent 50%)}
.sidebar{position:fixed;top:0;left:0;height:100vh;width:var(--sidebar-width);background:var(--card-bg);border-right:1px solid var(--border);transition:transform 0.3s ease;z-index:1000;overflow-y:auto}
.sidebar.mobile-hidden{transform:translateX(-100%)}
.sidebar-brand{padding:1.2rem 1.5rem;border-bottom:1px solid var(--border);background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);position:relative;overflow:hidden}
.sidebar-brand::before{content:'';position:absolute;top:0;left:0;width:100%;height:100%;background:linear-gradient(135deg,rgba(255,255,255,0.1) 0%,transparent 100%);pointer-events:none}
.sidebar-brand h2{color:#fff;font-size:1.3rem;font-weight:700;letter-spacing:0.5px;position:relative;z-index:1}
.sidebar-brand .brand-sub{color:rgba(255,255,255,0.9);font-size:0.75rem;font-weight:500;margin-top:0.25rem;position:relative;z-index:1}
.sidebar-nav{padding:0.75rem 0}
.nav-section{padding:0.5rem 1.5rem 0.25rem;color:var(--text-muted);font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.nav-item{margin:0.15rem 0.75rem}
.nav-link{display:flex;align-items:center;padding:0.65rem 1rem;color:var(--text);text-decoration:none;border-radius:6px;transition:all 0.2s ease;font-size:0.875rem;font-weight:500}
.nav-link:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.nav-link.active{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;font-weight:600;box-shadow:0 4px 12px rgba(59,130,246,0.3)}
.nav-link i{width:18px;margin-right:0.75rem;font-size:0.95rem;text-align:center}
.nav-badge{margin-left:auto;background:var(--danger);color:#fff;font-size:0.7rem;padding:0.15rem 0.5rem;border-radius:10px;font-weight:600}
.nav-dropdown{position:relative}
.nav-toggle{position:relative;cursor:pointer}
.nav-arrow{margin-left:auto;font-size:0.7rem;transition:transform 0.3s}
.nav-dropdown.open .nav-arrow{transform:rotate(180deg)}
.nav-submenu{display:none;padding-left:0.5rem;margin-top:0.25rem}
.nav-submenu.show{display:block}
.nav-sublink{display:flex;align-items:center;padding:0.5rem 1rem;padding-left:2.5rem;color:var(--text-muted);text-decoration:none;border-radius:6px;transition:all 0.2s ease;font-size:0.8125rem;font-weight:500}
.nav-sublink:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.nav-sublink.active{color:var(--accent);font-weight:600;background:rgba(59,130,246,0.05)}
.nav-sublink i{width:14px;margin-right:0.5rem;font-size:0.8rem}
.main-wrapper{margin-left:var(--sidebar-width);min-height:100vh;transition:margin-left 0.3s ease}
.topbar{background:var(--card-bg);height:var(--topbar-height);border-bottom:1px solid var(--border);padding:0 1.5rem;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100;backdrop-filter:blur(10px)}
.topbar-left{display:flex;align-items:center;gap:1rem}
.menu-toggle{display:none;background:none;border:none;font-size:1.3rem;color:var(--text);cursor:pointer;padding:0.5rem;transition:color 0.2s}
.menu-toggle:hover{color:var(--accent)}
.breadcrumb{display:flex;align-items:center;gap:0.5rem;color:var(--text-muted);font-size:0.85rem}
.breadcrumb a{color:var(--accent);text-decoration:none;font-weight:500;transition:color 0.2s}
.breadcrumb a:hover{color:var(--info);text-decoration:underline}
.breadcrumb-separator{color:var(--text-muted)}
.topbar-right{display:flex;align-items:center;gap:1.5rem}
.topbar-icon{background:none;border:none;color:var(--text);cursor:pointer;font-size:1.1rem;padding:0.5rem;border-radius:6px;transition:all 0.2s;position:relative}
.topbar-icon:hover{background:rgba(59,130,246,0.1);color:var(--accent)}
.topbar-icon .badge-dot{position:absolute;top:8px;right:8px;width:8px;height:8px;background:var(--danger);border-radius:50%;border:2px solid var(--card-bg)}
.topbar-user{display:flex;align-items:center;gap:0.75rem;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;transition:background 0.2s;border:1px solid transparent}
.topbar-user:hover{background:rgba(59,130,246,0.1);border-color:var(--border)}
.user-avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:0.8rem;box-shadow:0 2px 8px rgba(59,130,246,0.3)}
.user-info{display:flex;flex-direction:column}
.user-name{font-weight:600;font-size:0.85rem;color:var(--text)}
.user-role{font-size:0.75rem;color:var(--text-muted);text-transform:capitalize}
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
.stat-card::before{content:'';position:absolute;top:0;left:0;width:100%;height:3px;background:linear-gradient(90deg,transparent,var(--accent),transparent);transform:translateX(-100%);transition:transform 0.6s}
.stat-card:hover{transform:translateY(-2px);border-color:rgba(59,130,246,0.4);box-shadow:0 8px 24px rgba(59,130,246,0.15)}
.stat-card:hover::before{transform:translateX(100%)}
.stat-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.75rem}
.stat-icon{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:#fff;box-shadow:0 4px 12px rgba(0,0,0,0.2)}
.stat-icon.blue{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)}
.stat-icon.green{background:linear-gradient(135deg,#4ade80 0%,#22c55e 100%)}
.stat-icon.yellow{background:linear-gradient(135deg,#fbbf24 0%,#f59e0b 100%)}
.stat-icon.cyan{background:linear-gradient(135deg,#06b6d4 0%,#0891b2 100%)}
.stat-icon.red{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%)}
.stat-value{font-size:1.75rem;font-weight:700;color:var(--text);line-height:1}
.stat-label{font-size:0.8rem;color:var(--text-muted);margin-top:0.25rem}
.alert{padding:0.875rem 1rem;border-radius:6px;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.75rem;border-left:3px solid;font-size:0.875rem;animation:slideIn 0.3s ease}
@keyframes slideIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.alert-success{background:rgba(74,222,128,0.1);color:var(--success);border-color:var(--success)}
.alert-danger{background:rgba(239,68,68,0.1);color:var(--danger);border-color:var(--danger)}
.alert-warning{background:rgba(251,191,36,0.1);color:var(--warning);border-color:var(--warning)}
.alert-info{background:rgba(59,130,246,0.1);color:var(--info);border-color:var(--info)}
.badge{display:inline-flex;align-items:center;padding:0.3rem 0.65rem;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
.badge-success{background:rgba(74,222,128,0.2);color:var(--success)}
.badge-danger{background:rgba(239,68,68,0.2);color:var(--danger)}
.badge-warning{background:rgba(251,191,36,0.2);color:var(--warning)}
.badge-info{background:rgba(59,130,246,0.2);color:var(--info)}
.badge-critical{background:rgba(239,68,68,0.2);color:var(--danger)}
.badge-high{background:rgba(251,191,36,0.2);color:var(--warning)}
.badge-medium{background:rgba(59,130,246,0.2);color:var(--info)}
.badge-low{background:rgba(74,222,128,0.2);color:var(--success)}
table{width:100%;border-collapse:collapse;font-size:0.875rem}
table thead{background:rgba(59,130,246,0.05)}
table th{padding:0.75rem;text-align:left;color:var(--text);font-weight:600;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.3px;border-bottom:2px solid var(--border)}
table td{padding:0.875rem 0.75rem;border-bottom:1px solid var(--border);vertical-align:middle;color:var(--text)}
table tbody tr:hover{background:rgba(59,130,246,0.05)}
.sidebar-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:999;backdrop-filter:blur(4px)}
.sidebar-overlay.active{display:block}
@media(max-width:992px){
.sidebar{transform:translateX(-100%)}
.sidebar.active{transform:translateX(0)}
.main-wrapper{margin-left:0}
.menu-toggle{display:block}
.topbar-user .user-info{display:none}
.stats-grid{grid-template-columns:1fr}
}
@media(max-width:576px){
.topbar{padding:0 1rem}
.content{padding:1rem}
.stat-card{padding:1rem}
.stat-value{font-size:1.5rem}
.card-body{padding:1rem}
}
    </style>
</head>
<body>
<!-- Sidebar Overlay -->
<div class="sidebar-overlay" id="sidebarOverlay"></div>

<!-- Sidebar -->
<aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
        <h2>ЁЯЫбя╕П SMV Security</h2>
        <div class="brand-sub">Control Center</div>
    </div>

    <nav class="sidebar-nav">
        <!-- MAIN SECTION -->
        <div class="nav-section">Dashboard</div>
        <div class="nav-item">
            <a href="dashboard.php?section=dashboard" class="nav-link <?php echo $current_section === 'dashboard' ? 'active' : ''; ?>">
                <i class="fas fa-chart-line"></i>
                <span>Overview</span>
            </a>
        </div>

        <!-- THREAT INTELLIGENCE -->
        <div class="nav-section">Threat Intelligence</div>
        <div class="nav-item">
            <div class="nav-dropdown <?php echo in_array($current_section, ['threats', 'threat_analytics']) ? 'open' : ''; ?>">
                <a href="#" class="nav-link nav-toggle <?php echo in_array($current_section, ['threats', 'threat_analytics']) ? 'active' : ''; ?>">
                    <i class="fas fa-shield-alt"></i>
                    <span>Threats</span>
                    <i class="fas fa-chevron-down nav-arrow"></i>
                </a>
                <div class="nav-submenu <?php echo in_array($current_section, ['threats', 'threat_analytics']) ? 'show' : ''; ?>">
                    <a href="dashboard.php?section=threats" class="nav-sublink <?php echo $current_section === 'threats' ? 'active' : ''; ?>">
                        <i class="fas fa-list"></i>All Threats
                    </a>
                    <a href="dashboard.php?section=threat_analytics" class="nav-sublink <?php echo $current_section === 'threat_analytics' ? 'active' : ''; ?>">
                        <i class="fas fa-chart-bar"></i>Analytics
                    </a>
                </div>
            </div>
        </div>

        <!-- WAF MANAGEMENT -->
        <div class="nav-section">WAF Management</div>
        <div class="nav-item">
            <div class="nav-dropdown <?php echo in_array($current_section, ['customers', 'waf_analytics', 'waf_file']) ? 'open' : ''; ?>">
                <a href="#" class="nav-link nav-toggle <?php echo in_array($current_section, ['customers', 'waf_analytics', 'waf_file']) ? 'active' : ''; ?>">
                    <i class="fas fa-server"></i>
                    <span>Customers</span>
                    <i class="fas fa-chevron-down nav-arrow"></i>
                </a>
                <div class="nav-submenu <?php echo in_array($current_section, ['customers', 'waf_analytics', 'waf_file']) ? 'show' : ''; ?>">
                    <a href="dashboard.php?section=customers" class="nav-sublink <?php echo $current_section === 'customers' ? 'active' : ''; ?>">
                        <i class="fas fa-list"></i>All Customers
                    </a>
                    <a href="dashboard.php?section=waf_analytics" class="nav-sublink <?php echo $current_section === 'waf_analytics' ? 'active' : ''; ?>">
                        <i class="fas fa-chart-pie"></i>Analytics
                    </a>
                    <a href="dashboard.php?section=waf_file" class="nav-sublink <?php echo $current_section === 'waf_file' ? 'active' : ''; ?>">
                        <i class="fas fa-file-upload"></i>WAF File
                    </a>
                </div>
            </div>
        </div>

        <!-- NIS INTEGRATION -->
        <div class="nav-section">NIS Integration</div>
        <div class="nav-item">
            <div class="nav-dropdown <?php echo in_array($current_section, ['escalations', 'nis_reports']) ? 'open' : ''; ?>">
                <a href="#" class="nav-link nav-toggle <?php echo in_array($current_section, ['escalations', 'nis_reports']) ? 'active' : ''; ?>">
                    <i class="fas fa-flag"></i>
                    <span>Escalations</span>
                    <i class="fas fa-chevron-down nav-arrow"></i>
                </a>
                <div class="nav-submenu <?php echo in_array($current_section, ['escalations', 'nis_reports']) ? 'show' : ''; ?>">
                    <a href="dashboard.php?section=escalations" class="nav-sublink <?php echo $current_section === 'escalations' ? 'active' : ''; ?>">
                        <i class="fas fa-exclamation-circle"></i>Pending
                        <?php if ($stats && $stats['pending_escalations'] > 0): ?>
                            <span class="nav-badge"><?php echo $stats['pending_escalations']; ?></span>
                        <?php endif; ?>
                    </a>
                    <a href="dashboard.php?section=nis_reports" class="nav-sublink <?php echo $current_section === 'nis_reports' ? 'active' : ''; ?>">
                        <i class="fas fa-file-alt"></i>Reports
                    </a>
                </div>
            </div>
        </div>

        <!-- EMAIL INTEGRATION -->
        <div class="nav-item">
            <div class="nav-dropdown <?php echo in_array($current_section, ['email_integration', 'email_config', 'email_test', 'email_manage']) ? 'open' : ''; ?>">
                <a href="#" class="nav-link nav-toggle <?php echo in_array($current_section, ['email_integration', 'email_config', 'email_test', 'email_manage']) ? 'active' : ''; ?>">
                    <i class="fas fa-envelope"></i>
                    <span>Email Integration</span>
                    <i class="fas fa-chevron-down nav-arrow"></i>
                </a>
                <div class="nav-submenu <?php echo in_array($current_section, ['email_integration', 'email_config', 'email_test', 'email_manage']) ? 'show' : ''; ?>">
                    <a href="dashboard.php?section=email_config" class="nav-sublink <?php echo $current_section === 'email_config' ? 'active' : ''; ?>">
                        <i class="fas fa-cogs"></i>Configuration
                    </a>
                    <a href="dashboard.php?section=email_test" class="nav-sublink <?php echo $current_section === 'email_test' ? 'active' : ''; ?>">
                        <i class="fas fa-vial"></i>Test
                    </a>
                    <a href="dashboard.php?section=email_manage" class="nav-sublink <?php echo $current_section === 'email_manage' ? 'active' : ''; ?>">
                        <i class="fas fa-inbox"></i>Manage Emails
                    </a>
                </div>
            </div>
        </div>

        <!-- AI MANAGEMENT -->
        <div class="nav-section">AI System</div>
        <div class="nav-item">
            <a href="dashboard.php?section=llama_status" class="nav-link <?php echo $current_section === 'llama_status' ? 'active' : ''; ?>">
                <i class="fas fa-robot"></i>
                <span>LLAMA Status</span>
            </a>
        </div>

        <!-- SYSTEM -->
        <div class="nav-section">System</div>
        <div class="nav-item">
            <a href="dashboard.php?section=settings" class="nav-link <?php echo $current_section === 'settings' ? 'active' : ''; ?>">
                <i class="fas fa-cog"></i>
                <span>Settings</span>
            </a>
        </div>

        <div class="nav-item" style="margin-top:1rem">
            <a href="dashboard.php?logout=1" class="nav-link" style="color:var(--danger)" onclick="return confirm('Are you sure you want to logout?')">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
            </a>
        </div>
    </nav>
</aside>

<!-- Main Wrapper -->
<div class="main-wrapper" id="mainWrapper">
    <!-- Top Bar -->
    <header class="topbar">
        <div class="topbar-left">
            <button class="menu-toggle" id="menuToggle">
                <i class="fas fa-bars"></i>
            </button>
            <div class="breadcrumb">
                <a href="dashboard.php?section=dashboard"><i class="fas fa-home"></i> Home</a>
                <span class="breadcrumb-separator">/</span>
                <span><?php echo ucfirst(str_replace('_', ' ', $current_section)); ?></span>
            </div>
        </div>

        <div class="topbar-right">
            <button class="topbar-icon" title="Notifications">
                <i class="fas fa-bell"></i>
                <span class="badge-dot"></span>
            </button>
            <div class="topbar-user">
                <div class="user-avatar">
                    <?php echo strtoupper(substr($admin['username'] ?? 'A', 0, 2)); ?>
                </div>
                <div class="user-info">
                    <div class="user-name"><?php echo htmlspecialchars($admin['full_name'] ?? $admin['username'] ?? 'Admin'); ?></div>
                    <div class="user-role"><?php echo htmlspecialchars($admin['role'] ?? 'analyst'); ?></div>
                </div>
            </div>
        </div>
    </header>

    <!-- Content Area -->
    <div class="content">
        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-title"><?php echo ucfirst(str_replace('_', ' ', $current_section)); ?></h1>
            <p class="page-subtitle">Welcome back, <?php echo htmlspecialchars($admin['full_name'] ?? $admin['username'] ?? 'Administrator'); ?>!</p>
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
            // Show placeholder for missing sections
            ?>
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                <div>
                    <strong>Section Under Development</strong><br>
                    The <strong><?php echo htmlspecialchars(str_replace('_', ' ', $current_section)); ?></strong> section is being developed. Check back soon!
                </div>
            </div>
            <?php
        }
        ?>
    </div>
</div>

<script>
    // Mobile menu toggle
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            sidebar.classList.toggle('active');
            sidebarOverlay.classList.toggle('active');
        });
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', () => {
            sidebar.classList.remove('active');
            sidebarOverlay.classList.remove('active');
        });
    }

    // Close sidebar when clicking nav links on mobile
    document.querySelectorAll('.nav-link, .nav-sublink').forEach(link => {
        link.addEventListener('click', (e) => {
            if (window.innerWidth <= 992) {
                if (!e.target.closest('.nav-toggle')) {
                    sidebar.classList.remove('active');
                    sidebarOverlay.classList.remove('active');
                }
            }
        });
    });

    // Auto-hide alerts after 5 seconds
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    });

    // Dropdown menu functionality
    document.querySelectorAll('.nav-toggle').forEach(toggle => {
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            const dropdown = toggle.closest('.nav-dropdown');
            const submenu = dropdown.querySelector('.nav-submenu');
            
            // Close all other dropdowns
            document.querySelectorAll('.nav-submenu').forEach(s => {
                if (s !== submenu) s.classList.remove('show');
            });
            document.querySelectorAll('.nav-dropdown').forEach(d => {
                if (d !== dropdown) d.classList.remove('open');
            });
            
            // Toggle current dropdown
            submenu.classList.toggle('show');
            dropdown.classList.toggle('open');
        });
    });
</script>
</body>
</html>
<?php ob_end_flush(); ?>
