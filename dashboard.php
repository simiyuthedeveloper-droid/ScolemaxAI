<?php
ob_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config.php';

// Require login
requireLogin();

$user = getCurrentUser();
if (!$user) {
    redirect('login.php');
}

$message = '';

// Get current section - simplified routing
$current_section = isset($_GET['section']) ? $_GET['section'] : 'overview';

// Define allowed sections based on user role
$allowed_sections = [
    'overview',
    
    // Monitoring
    'monitoring', 'add_target', 'edit_target', 'view_target',
    
    // Threats
    'threats', 'view_threat', 'threat_analysis',
    
    // Responses
    'responses', 'response_logs',
    
    // Intelligence Hub
    'intelligence', 'threat_map', 'attack_trends',
    
    // Blocked IPs
    'blocked_ips', 'block_ip', 'unblock_ip',
    
    // Departments (Super Admin & Managers only)
    'departments', 'create_department', 'edit_department',
    
    // Users (Super Admin & Managers only)
    'users', 'create_user', 'edit_user', 'view_user',
    
    // API Management
    'add_api', 'manage_api',
    
    // Reports
    'reports', 'compliance_reports', 'security_audit',
    
    // Settings
    'settings', 'alert_settings', 'system_settings'
];

// Validate section
if (!in_array($current_section, $allowed_sections)) {
    $current_section = 'overview';
}

// Handle logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    redirect('login.php', 'Logged out successfully', 'success');
}

// Log section access
logActivity('access_section', "Accessed $current_section section");

// Get license status
$license = getLicenseStatus();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo ucfirst($current_section); ?> - <?php echo SITE_NAME; ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        :root{--primary:#1a1d2e;--primary-dark:#0f1119;--accent:#ff6b6b;--accent-hover:#ff5252;--success:#4ade80;--danger:#ef4444;--warning:#fbbf24;--info:#3b82f6;--light:#f8f9fa;--border:#2d3354;--text:#e1e4ed;--text-muted:#a0a4b8;--sidebar-width:240px;--topbar-height:60px;--card-bg:#242842}
        body{font-family:'Inter',sans-serif;font-size:13px;line-height:1.6;background:var(--primary);color:var(--text)}
        .sidebar{position:fixed;top:0;left:0;height:100vh;width:var(--sidebar-width);background:var(--card-bg);border-right:1px solid var(--border);transition:transform 0.3s;z-index:1000;overflow-y:auto}
        .sidebar.mobile-hidden{transform:translateX(-100%)}
        .sidebar-header{padding:1.2rem 1.5rem;border-bottom:1px solid var(--border);background:linear-gradient(135deg,var(--accent) 0%,var(--accent-hover) 100%)}
        .sidebar-header h2{color:#fff;font-size:1.3rem;font-weight:700;display:flex;align-items:center;justify-content:center;gap:0.5rem;letter-spacing:0.5px}
        .sidebar-header .logo-icon{width:38px;height:38px;background:rgba(255,255,255,0.2);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:1.1rem}
        .license-badge{background:rgba(255,107,107,0.15);padding:0.5rem 0.75rem;border-radius:6px;margin:0.75rem 1rem;text-align:center;border:1px solid rgba(255,107,107,0.3)}
        .license-badge.warning{border-color:var(--warning);background:rgba(251,191,36,0.15)}
        .license-badge.active{border-color:var(--success);background:rgba(74,222,128,0.1)}
        .license-badge.expired{border-color:var(--danger);background:rgba(239,68,68,0.1)}
        .license-badge p{color:var(--text);font-size:0.75rem;margin:0.25rem 0}
        .license-badge .status{font-weight:600;text-transform:uppercase;font-size:0.8rem}
        .sidebar-nav{padding:0.75rem 0}
        .nav-section{padding:0.5rem 1.5rem 0.25rem;color:var(--text-muted);font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
        .nav-item{margin:0.15rem 0.75rem}
        .nav-link{display:flex;align-items:center;padding:0.65rem 1rem;color:var(--text);text-decoration:none;border-radius:6px;transition:all 0.2s;font-size:0.875rem;font-weight:500;position:relative}
        .nav-link:hover{background:rgba(255,107,107,0.1);color:var(--accent)}
        .nav-link.active{background:var(--accent);color:#fff;font-weight:600}
        .nav-link i{width:18px;margin-right:0.75rem;font-size:0.95rem;text-align:center}
        .nav-link .submenu-arrow{margin-left:auto;transition:transform 0.3s;font-size:0.8rem}
        .nav-link.expanded .submenu-arrow{transform:rotate(90deg)}
        .submenu{max-height:0;overflow:hidden;transition:max-height 0.3s;margin-left:0.75rem}
        .submenu.expanded{max-height:800px}
        .submenu-link{display:flex;align-items:center;padding:0.6rem 1rem;padding-left:2.5rem;color:var(--text-muted);text-decoration:none;border-radius:6px;transition:all 0.2s;font-size:0.8125rem;margin:0.15rem 0}
        .submenu-link:hover{background:rgba(255,107,107,0.1);color:var(--accent);padding-left:2.75rem}
        .submenu-link.active{background:rgba(255,107,107,0.2);color:var(--accent);font-weight:600}
        .submenu-link i{width:16px;margin-right:0.5rem;font-size:0.85rem}
        .main-content{margin-left:var(--sidebar-width);min-height:100vh;transition:margin-left 0.3s}
        .main-content.full-width{margin-left:0}
        .top-navbar{background:var(--card-bg);padding:1rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}
        .navbar-left{display:flex;align-items:center;gap:1rem}
        .menu-toggle{display:none;background:none;border:none;font-size:1.3rem;color:var(--text);cursor:pointer;padding:0.5rem}
        .navbar-title{font-size:1.15rem;color:var(--text);font-weight:600}
        .navbar-right{display:flex;align-items:center;gap:1rem}
        .user-info{display:flex;align-items:center;gap:0.5rem;color:var(--text);padding:0.5rem 1rem;background:rgba(255,107,107,0.1);border-radius:6px;border:1px solid var(--border)}
        .user-info .role-badge{background:var(--accent);color:#fff;padding:0.25rem 0.5rem;border-radius:4px;font-size:0.7rem;text-transform:uppercase;font-weight:600}
        .logout-btn{background:var(--danger);color:#fff;border:none;padding:0.5rem 1.25rem;border-radius:6px;text-decoration:none;font-size:0.875rem;transition:all 0.2s;display:inline-flex;align-items:center;gap:0.5rem;font-weight:600}
        .logout-btn:hover{background:#dc2626;transform:translateY(-1px)}
        .content-area{padding:2rem}
        .alert{padding:0.875rem 1rem;border-radius:6px;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.75rem;border-left:3px solid;font-size:0.875rem;animation:slideDown 0.3s}
        @keyframes slideDown{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
        .alert-success{background:rgba(74,222,128,0.15);color:var(--success);border-color:var(--success)}
        .alert-danger{background:rgba(239,68,68,0.15);color:var(--danger);border-color:var(--danger)}
        .alert-warning{background:rgba(251,191,36,0.15);color:var(--warning);border-color:var(--warning)}
        .alert-info{background:rgba(59,130,246,0.15);color:var(--info);border-color:var(--info)}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.25rem;margin-bottom:1.5rem}
        .stat-card{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:1.25rem;transition:all 0.3s;cursor:pointer}
        .stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
        .stat-card.danger{border-left:3px solid var(--danger)}
        .stat-card.success{border-left:3px solid var(--success)}
        .stat-card.warning{border-left:3px solid var(--warning)}
        .stat-card.info{border-left:3px solid var(--info)}
        .stat-content{display:flex;justify-content:space-between;align-items:center}
        .stat-info h3{font-size:1.75rem;font-weight:700;color:var(--text);margin-bottom:0.25rem}
        .stat-card.danger .stat-info h3{color:var(--danger)}
        .stat-card.success .stat-info h3{color:var(--success)}
        .stat-card.warning .stat-info h3{color:var(--warning)}
        .stat-card.info .stat-info h3{color:var(--info)}
        .stat-info p{color:var(--text-muted);font-size:0.8rem;font-weight:500}
        .stat-icon{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:#fff}
        .stat-icon{background:var(--accent)}
        .stat-card.danger .stat-icon{background:var(--danger)}
        .stat-card.success .stat-icon{background:var(--success)}
        .stat-card.warning .stat-icon{background:var(--warning)}
        .stat-card.info .stat-icon{background:var(--info)}
        .section-card{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:1.5rem}
        .section-header{background:rgba(255,107,107,0.1);border-bottom:1px solid var(--border);color:var(--text);padding:1rem 1.25rem;display:flex;justify-content:space-between;align-items:center}
        .section-header h2{font-size:1rem;font-weight:600}
        .section-body{padding:1.25rem}
        .table-responsive{overflow-x:auto}
        table{width:100%;border-collapse:collapse;font-size:0.875rem}
        table thead{background:rgba(255,107,107,0.1)}
        table th{padding:0.75rem;text-align:left;color:var(--text);font-weight:600;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.3px;border-bottom:2px solid var(--border)}
        table td{padding:0.875rem 0.75rem;border-bottom:1px solid var(--border);vertical-align:middle;color:var(--text)}
        table tbody tr:hover{background:rgba(255,107,107,0.05)}
        .badge{display:inline-block;padding:0.3rem 0.65rem;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.3px}
        .badge.low{background:rgba(74,222,128,0.2);color:var(--success)}
        .badge.medium{background:rgba(251,191,36,0.2);color:var(--warning)}
        .badge.high{background:rgba(255,107,107,0.2);color:#ff6b6b}
        .badge.critical{background:rgba(239,68,68,0.2);color:var(--danger)}
        .badge.active{background:rgba(74,222,128,0.2);color:var(--success)}
        .badge.inactive{background:rgba(160,164,184,0.2);color:var(--text-muted)}
        .badge.paused{background:rgba(251,191,36,0.2);color:var(--warning)}
        .badge.detected{background:rgba(239,68,68,0.2);color:var(--danger)}
        .badge.resolved{background:rgba(74,222,128,0.2);color:var(--success)}
        .btn{padding:0.5rem 1rem;border:1px solid transparent;border-radius:6px;font-size:0.875rem;font-weight:600;cursor:pointer;transition:all 0.2s;display:inline-flex;align-items:center;gap:0.5rem;text-decoration:none}
        .btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
        .btn-primary:hover{background:var(--accent-hover)}
        .btn-success{background:var(--success);color:#fff}
        .btn-danger{background:var(--danger);color:#fff}
        .btn-warning{background:var(--warning);color:#000}
        .btn-small{padding:0.375rem 0.75rem;font-size:0.8125rem}
        .sidebar-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:999}
        .sidebar-overlay.active{display:block}
        .empty-state{text-align:center;padding:3rem 2rem;color:var(--text-muted)}
        .empty-state i{font-size:3.5rem;color:var(--border);margin-bottom:1rem}
        .empty-state h3{font-size:1.1rem;color:var(--text);margin-bottom:0.5rem;font-weight:600}
        @media(max-width:992px){.sidebar{transform:translateX(-100%)}.sidebar.active{transform:translateX(0)}.main-content{margin-left:0}.menu-toggle{display:block}.content-area{padding:1rem}.stats-grid{grid-template-columns:1fr;gap:1rem}.navbar-title{font-size:1rem}.user-info span{display:none}}
    </style>
</head>
<body>
    <!-- Sidebar Overlay -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <!-- Sidebar -->
    <aside class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h2><span class="logo-icon">S</span> ScolemaxAI</h2>
        </div>
        
        
        <nav class="sidebar-nav">
            <!-- Dashboard -->
            <div class="nav-item">
                <a href="?section=overview" class="nav-link <?php echo $current_section === 'overview' ? 'active' : ''; ?>">
                    <i class="fas fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </a>
            </div>
            
            <!-- Monitoring Targets -->
            <div class="nav-item">
                <a href="javascript:void(0)" class="nav-link <?php echo in_array($current_section, ['monitoring', 'add_target', 'edit_target', 'view_target']) ? 'active' : ''; ?>" id="monitoringToggle">
                    <i class="fas fa-satellite-dish"></i>
                    <span>Monitoring Targets</span>
                    <i class="fas fa-chevron-right submenu-arrow"></i>
                </a>
                <div class="submenu" id="monitoringSubmenu">
                    <a href="?section=monitoring" class="submenu-link <?php echo $current_section === 'monitoring' ? 'active' : ''; ?>">
                        <i class="fas fa-list"></i>
                        <span>All Targets</span>
                    </a>
                    <a href="?section=add_target" class="submenu-link <?php echo $current_section === 'add_target' ? 'active' : ''; ?>">
                        <i class="fas fa-plus"></i>
                        <span>Add New Target</span>
                    </a>
                </div>
            </div>
            
            <!-- Threats -->
            <div class="nav-item">
                <a href="javascript:void(0)" class="nav-link <?php echo in_array($current_section, ['threats', 'view_threat', 'threat_analysis']) ? 'active' : ''; ?>" id="threatsToggle">
                    <i class="fas fa-shield-alt"></i>
                    <span>Threats Detected</span>
                    <i class="fas fa-chevron-right submenu-arrow"></i>
                </a>
                <div class="submenu" id="threatsSubmenu">
                    <a href="?section=threats" class="submenu-link <?php echo $current_section === 'threats' ? 'active' : ''; ?>">
                        <i class="fas fa-list"></i>
                        <span>All Threats</span>
                    </a>
                    <a href="?section=threat_analysis" class="submenu-link <?php echo $current_section === 'threat_analysis' ? 'active' : ''; ?>">
                        <i class="fas fa-chart-line"></i>
                        <span>Threat Analysis</span>
                    </a>
                </div>
            </div>
            
            <!-- Automated Responses -->
            <div class="nav-item">
                <a href="?section=responses" class="nav-link <?php echo in_array($current_section, ['responses', 'response_logs']) ? 'active' : ''; ?>">
                    <i class="fas fa-bolt"></i>
                    <span>Auto Responses</span>
                </a>
            </div>
            
            <!-- Intelligence Hub -->
            <div class="nav-item">
                <a href="javascript:void(0)" class="nav-link <?php echo in_array($current_section, ['intelligence', 'threat_map', 'attack_trends']) ? 'active' : ''; ?>" id="intelligenceToggle">
                    <i class="fas fa-brain"></i>
                    <span>Intelligence Hub</span>
                    <i class="fas fa-chevron-right submenu-arrow"></i>
                </a>
                <div class="submenu" id="intelligenceSubmenu">
                    <a href="?section=intelligence" class="submenu-link <?php echo $current_section === 'intelligence' ? 'active' : ''; ?>">
                        <i class="fas fa-globe"></i>
                        <span>Threat Intelligence</span>
                    </a>
                    <a href="?section=threat_map" class="submenu-link <?php echo $current_section === 'threat_map' ? 'active' : ''; ?>">
                        <i class="fas fa-map"></i>
                        <span>Threat Map</span>
                    </a>
                    <a href="?section=attack_trends" class="submenu-link <?php echo $current_section === 'attack_trends' ? 'active' : ''; ?>">
                        <i class="fas fa-chart-area"></i>
                        <span>Attack Trends</span>
                    </a>
                </div>
            </div>
            
            <!-- Blocked IPs -->
            <div class="nav-item">
                <a href="?section=blocked_ips" class="nav-link <?php echo $current_section === 'blocked_ips' ? 'active' : ''; ?>">
                    <i class="fas fa-ban"></i>
                    <span>Blocked IPs</span>
                </a>
            </div>
            
            <?php if (isSuperAdmin() || isManagerOrAbove()): ?>
            <!-- Departments -->
            <div class="nav-item">
                <a href="?section=departments" class="nav-link <?php echo in_array($current_section, ['departments', 'create_department', 'edit_department']) ? 'active' : ''; ?>">
                    <i class="fas fa-building"></i>
                    <span>Departments</span>
                </a>
            </div>
            
            <!-- Users -->
            <div class="nav-item">
                <a href="?section=users" class="nav-link <?php echo in_array($current_section, ['users', 'create_user', 'edit_user', 'view_user']) ? 'active' : ''; ?>">
                    <i class="fas fa-users"></i>
                    <span>User Management</span>
                </a>
            </div>
            <?php endif; ?>
            
            <!-- Add API -->
            <div class="nav-item">
                <a href="?section=add_api" class="nav-link <?php echo $current_section === 'add_api' ? 'active' : ''; ?>">
                    <i class="fas fa-plug"></i>
                    <span>Add API</span>
                </a>
            </div>
            
            <!-- Reports -->
            <div class="nav-item">
                <a href="javascript:void(0)" class="nav-link <?php echo in_array($current_section, ['reports', 'compliance_reports', 'security_audit']) ? 'active' : ''; ?>" id="reportsToggle">
                    <i class="fas fa-file-alt"></i>
                    <span>Reports</span>
                    <i class="fas fa-chevron-right submenu-arrow"></i>
                </a>
                <div class="submenu" id="reportsSubmenu">
                    <a href="?section=reports" class="submenu-link <?php echo $current_section === 'reports' ? 'active' : ''; ?>">
                        <i class="fas fa-chart-bar"></i>
                        <span>All Reports</span>
                    </a>
                    <a href="?section=compliance_reports" class="submenu-link <?php echo $current_section === 'compliance_reports' ? 'active' : ''; ?>">
                        <i class="fas fa-clipboard-check"></i>
                        <span>Compliance Reports</span>
                    </a>
                    <a href="?section=security_audit" class="submenu-link <?php echo $current_section === 'security_audit' ? 'active' : ''; ?>">
                        <i class="fas fa-search"></i>
                        <span>Security Audit</span>
                    </a>
                </div>
            </div>
            
            <!-- Settings -->
            <div class="nav-item">
                <a href="javascript:void(0)" class="nav-link <?php echo in_array($current_section, ['settings', 'alert_settings', 'system_settings']) ? 'active' : ''; ?>" id="settingsToggle">
                    <i class="fas fa-cog"></i>
                    <span>Settings</span>
                    <i class="fas fa-chevron-right submenu-arrow"></i>
                </a>
                <div class="submenu" id="settingsSubmenu">
                    <a href="?section=settings" class="submenu-link <?php echo $current_section === 'settings' ? 'active' : ''; ?>">
                        <i class="fas fa-sliders-h"></i>
                        <span>General Settings</span>
                    </a>
                    <a href="?section=alert_settings" class="submenu-link <?php echo $current_section === 'alert_settings' ? 'active' : ''; ?>">
                        <i class="fas fa-bell"></i>
                        <span>Alert Settings</span>
                    </a>
                    <?php if (isSuperAdmin()): ?>
                    <a href="?section=system_settings" class="submenu-link <?php echo $current_section === 'system_settings' ? 'active' : ''; ?>">
                        <i class="fas fa-tools"></i>
                        <span>System Settings</span>
                    </a>
                    <?php endif; ?>
                </div>
            </div>
        </nav>
    </aside>

    <!-- Main Content -->
    <main class="main-content" id="mainContent">
        <!-- Top Navigation -->
        <nav class="top-navbar">
            <div class="navbar-left">
                <button class="menu-toggle" id="menuToggle">
                    <i class="fas fa-bars"></i>
                </button>
                <h1 class="navbar-title">ScolemaxAI-Kenya Dashboard</h1>
            </div>
            <div class="navbar-right">
                <div class="user-info">
                    <i class="fas fa-user-shield"></i>
                    <span><?php echo htmlspecialchars($user['full_name']); ?></span>
                    <span class="role-badge"><?php echo str_replace('_', ' ', $user['role']); ?></span>
                </div>
                <a href="?logout=1" class="logout-btn">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Logout</span>
                </a>
            </div>
        </nav>

        <!-- Content Area -->
        <div class="content-area">
            <?php 
            $flash = getFlashMessage();
            if ($flash): 
            ?>
                <div class="alert alert-<?php echo $flash['type']; ?>">
                    <i class="fas fa-info-circle"></i>
                    <span><?php echo htmlspecialchars($flash['text']); ?></span>
                </div>
            <?php endif; ?>

            <!-- Route to sections -->
            <?php
            $section_file = __DIR__ . '/sections/' . $current_section . '.php';
            if (file_exists($section_file)) {
                include $section_file;
            } else {
                // Default overview if file doesn't exist
                include __DIR__ . '/sections/overview.php';
            }
            ?>
        </div>
    </main>

    <script>
        // Sidebar toggle
        const menuToggle=document.getElementById('menuToggle'),sidebar=document.getElementById('sidebar'),sidebarOverlay=document.getElementById('sidebarOverlay');
        menuToggle.addEventListener('click',()=>{sidebar.classList.toggle('active'),sidebarOverlay.classList.toggle('active')});
        sidebarOverlay.addEventListener('click',()=>{sidebar.classList.remove('active'),sidebarOverlay.classList.remove('active')});
        
        // Close sidebar on link click (mobile)
        document.querySelectorAll('.nav-link, .submenu-link').forEach(link=>{link.addEventListener('click',()=>{window.innerWidth<=992&&(sidebar.classList.remove('active'),sidebarOverlay.classList.remove('active'))})});
        
        // Auto-dismiss alerts
        document.querySelectorAll('.alert').forEach(alert=>{setTimeout(()=>{alert.style.transition='opacity 0.5s',alert.style.opacity='0',setTimeout(()=>alert.remove(),500)},5000)});
        
        // Submenu toggles
        const monitoringActive=<?php echo in_array($current_section,['monitoring','add_target','edit_target','view_target'])?'true':'false'; ?>;
        const threatsActive=<?php echo in_array($current_section,['threats','view_threat','threat_analysis'])?'true':'false'; ?>;
        const intelligenceActive=<?php echo in_array($current_section,['intelligence','threat_map','attack_trends'])?'true':'false'; ?>;
        const reportsActive=<?php echo in_array($current_section,['reports','compliance_reports','security_audit'])?'true':'false'; ?>;
        const settingsActive=<?php echo in_array($current_section,['settings','alert_settings','system_settings'])?'true':'false'; ?>;
        
        function setupSubmenu(toggleId,submenuId,isActive){
            const toggle=document.getElementById(toggleId),submenu=document.getElementById(submenuId);
            if(isActive){submenu.classList.add('expanded'),toggle.classList.add('expanded')}
            toggle.addEventListener('click',e=>{e.preventDefault(),submenu.classList.toggle('expanded'),toggle.classList.toggle('expanded')})
        }
        
        setupSubmenu('monitoringToggle','monitoringSubmenu',monitoringActive);
        setupSubmenu('threatsToggle','threatsSubmenu',threatsActive);
        setupSubmenu('intelligenceToggle','intelligenceSubmenu',intelligenceActive);
        setupSubmenu('reportsToggle','reportsSubmenu',reportsActive);
        setupSubmenu('settingsToggle','settingsSubmenu',settingsActive);
    </script>
</body>
</html>
<?php ob_end_flush(); ?>