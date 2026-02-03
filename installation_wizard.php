<?php
/**
 * ScolemaxAI-Kenya Installation Wizard
 * Version: 1.0.0
 */

// Prevent access if already installed
if (file_exists('installed.lock')) {
    header('Location: login.php');
    exit();
}

$error = '';
$success = '';
$step = isset($_GET['step']) ? (int)$_GET['step'] : 1;

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['test_db'])) {
        // Step 1: Test database connection
        $host = trim($_POST['db_host']);
        $name = trim($_POST['db_name']);
        $user = trim($_POST['db_user']);
        $pass = $_POST['db_pass'];
        
        try {
            $dsn = "mysql:host=$host;dbname=$name;charset=utf8mb4";
            $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $success = 'Database connection successful!';
            $_SESSION['db_config'] = ['host' => $host, 'name' => $name, 'user' => $user, 'pass' => $pass];
        } catch (PDOException $e) {
            $error = 'Connection failed: ' . $e->getMessage();
        }
    } elseif (isset($_POST['install_db'])) {
        // Step 2: Import database
        session_start();
        if (!isset($_SESSION['db_config'])) {
            $error = 'Database configuration missing. Please go back to Step 1.';
        } else {
            $cfg = $_SESSION['db_config'];
            try {
                $pdo = new PDO("mysql:host={$cfg['host']};dbname={$cfg['name']};charset=utf8mb4", $cfg['user'], $cfg['pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
                
                // Read SQL file
                $sqlFile = 'scolema3_ai.sql';
                if (!file_exists($sqlFile)) {
                    $error = 'SQL file not found. Please upload scolema3_ai.sql to the root directory.';
                } else {
                    $sql = file_get_contents($sqlFile);
                    
                    // Remove comments and split by semicolon
                    $sql = preg_replace('/^--.*$/m', '', $sql);
                    $sql = preg_replace('/\/\*.*?\*\//s', '', $sql);
                    $statements = array_filter(array_map('trim', explode(';', $sql)));
                    
                    // Execute each statement
                    foreach ($statements as $stmt) {
                        if (!empty($stmt)) {
                            $pdo->exec($stmt);
                        }
                    }
                    
                    $success = 'Database installed successfully!';
                    $_SESSION['db_installed'] = true;
                }
            } catch (PDOException $e) {
                $error = 'Installation failed: ' . $e->getMessage();
            }
        }
    } elseif (isset($_POST['finalize'])) {
        // Step 3: Finalize installation
        session_start();
        if (!isset($_SESSION['db_installed'])) {
            $error = 'Database not installed. Please complete previous steps.';
        } else {
            // Create installed.lock file
            file_put_contents('installed.lock', date('Y-m-d H:i:s'));
            
            // Clear session
            session_destroy();
            
            // Redirect to register
            header('Location: register.php');
            exit();
        }
    }
}

// Start session if not started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Get config values for pre-fill
$dbHost = defined('DB_HOST') ? DB_HOST : 'localhost';
$dbName = defined('DB_NAME') ? DB_NAME : 'scolema3_ai';
$dbUser = defined('DB_USER') ? DB_USER : 'scolema3_ai25';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScolemaxAI Installation Wizard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Open Sans',Arial,sans-serif;font-size:13px;line-height:1.5;color:#333;background:linear-gradient(135deg,#1a2a4a 0%,#0f1e38 100%);min-height:100vh}
.container{max-width:700px;margin:40px auto;padding:0 15px}
.card{background:#fff;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.12);margin-bottom:20px}
.card-header{background:linear-gradient(135deg,#ff6b35 0%,#ffc837 100%);border-bottom:1px solid #ff6b35;padding:15px 20px;border-radius:4px 4px 0 0}
.card-header h2{font-size:16px;font-weight:600;color:#fff}
.card-body{padding:20px}
.logo{text-align:center;margin-bottom:30px}
.logo h1{font-size:24px;color:#fff;font-weight:700;margin-bottom:5px}
.logo p{font-size:12px;color:rgba(255,255,255,0.8)}
.alert{padding:12px 15px;margin-bottom:20px;border-radius:4px;font-size:13px}
.alert-success{background:#d4edda;border:1px solid #c3e6cb;color:#155724}
.alert-danger{background:#f8d7da;border:1px solid #f5c6cb;color:#721c24}
.form-group{margin-bottom:18px}
.form-group label{display:block;margin-bottom:6px;font-weight:600;font-size:12px;color:#495057}
.form-control{width:100%;padding:8px 12px;font-size:13px;border:1px solid #d5dce5;border-radius:3px;transition:border .15s}
.form-control:focus{outline:0;border-color:#ff6b35;box-shadow:0 0 0 2px rgba(255,107,53,.1)}
.btn{display:inline-block;padding:10px 20px;font-size:13px;font-weight:600;text-align:center;border:none;border-radius:4px;cursor:pointer;transition:all .2s;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,#ff6b35,#ffc837);color:#fff}
.btn-primary:hover{background:linear-gradient(135deg,#e55a2a,#ffb82e);transform:translateY(-2px);box-shadow:0 4px 12px rgba(255,107,53,0.3)}
.btn-success{background:#28a745;color:#fff}
.btn-success:hover{background:#218838;transform:translateY(-2px)}
.btn-secondary{background:#6c757d;color:#fff}
.btn-secondary:hover{background:#5a6268;transform:translateY(-2px)}
.btn-block{display:block;width:100%}
.steps{display:flex;justify-content:space-between;margin-bottom:30px;padding:0;list-style:none}
.steps li{flex:1;text-align:center;position:relative;font-size:12px}
.steps li:not(:last-child):after{content:'';position:absolute;top:15px;left:50%;width:100%;height:2px;background:#e3e6ea;z-index:-1}
.steps li .step-num{display:inline-block;width:30px;height:30px;line-height:30px;background:#e3e6ea;color:#7f8c8d;border-radius:50%;margin-bottom:8px;font-weight:600}
.steps li.active .step-num{background:linear-gradient(135deg,#ff6b35,#ffc837);color:#fff}
.steps li.completed .step-num{background:#28a745;color:#fff}
.steps li.active:not(:last-child):after{background:linear-gradient(135deg,#ff6b35,#ffc837)}
.steps li.completed:not(:last-child):after{background:#28a745}
.text-center{text-align:center}
.text-muted{color:#6c757d;font-size:12px}
.mt-3{margin-top:20px}
.mb-0{margin-bottom:0}
.info-box{background:#fff3e0;border-left:4px solid #ff6b35;padding:12px 15px;margin-bottom:20px;font-size:12px;border-radius:3px}
.feature-list{list-style:none;padding:0}
.feature-list li{padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:12px}
.feature-list li:last-child{border:0}
.feature-list li:before{content:'✓';color:#28a745;font-weight:700;margin-right:8px}
</style>
</head>
<body>
<div class="container">
<div class="logo">
<h1>🛡️ ScolemaxAI-Kenya</h1>
<p>AI-Powered Security & Threat Detection System</p>
</div>

<div class="card">
<div class="card-header">
<h2>Installation Wizard</h2>
</div>
<div class="card-body">
<ul class="steps">
<li class="<?php echo $step >= 1 ? 'active' : ''; ?> <?php echo isset($_SESSION['db_config']) ? 'completed' : ''; ?>">
<span class="step-num">1</span>
<div>Database</div>
</li>
<li class="<?php echo $step >= 2 ? 'active' : ''; ?> <?php echo isset($_SESSION['db_installed']) ? 'completed' : ''; ?>">
<span class="step-num">2</span>
<div>Install</div>
</li>
<li class="<?php echo $step >= 3 ? 'active' : ''; ?>">
<span class="step-num">3</span>
<div>Complete</div>
</li>
</ul>

<?php if ($error): ?>
<div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>

<?php if ($success): ?>
<div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
<?php endif; ?>

<?php if ($step === 1): ?>
<h3 class="mb-0" style="font-size:15px;margin-bottom:15px">Step 1: Database Configuration</h3>
<div class="info-box">Enter your database credentials. Make sure the database exists before proceeding.</div>

<form method="POST">
<div class="form-group">
<label>Database Host</label>
<input type="text" name="db_host" class="form-control" value="<?php echo htmlspecialchars($dbHost); ?>" required>
</div>

<div class="form-group">
<label>Database Name</label>
<input type="text" name="db_name" class="form-control" value="<?php echo htmlspecialchars($dbName); ?>" required>
</div>

<div class="form-group">
<label>Database Username</label>
<input type="text" name="db_user" class="form-control" value="<?php echo htmlspecialchars($dbUser); ?>" required>
</div>

<div class="form-group">
<label>Database Password</label>
<input type="password" name="db_pass" class="form-control" value="" required>
</div>

<button type="submit" name="test_db" class="btn btn-primary btn-block">Test Connection</button>

<?php if (isset($_SESSION['db_config'])): ?>
<a href="?step=2" class="btn btn-success btn-block mt-3">Continue to Installation →</a>
<?php endif; ?>
</form>

<?php elseif ($step === 2): ?>
<h3 class="mb-0" style="font-size:15px;margin-bottom:15px">Step 2: Install Database</h3>
<div class="info-box">This will create all required tables and import initial data.</div>

<ul class="feature-list">
<li>Organizations & Users Management</li>
<li>Threat Detection & Monitoring</li>
<li>Activity Logs & API Tracking</li>
<li>Department & Role Management</li>
<li>Security Response System</li>
</ul>

<form method="POST" class="mt-3">
<button type="submit" name="install_db" class="btn btn-success btn-block">Install Database</button>
<a href="?step=1" class="btn btn-secondary btn-block mt-3">← Back</a>

<?php if (isset($_SESSION['db_installed'])): ?>
<a href="?step=3" class="btn btn-primary btn-block mt-3">Continue to Finalization →</a>
<?php endif; ?>
</form>

<?php elseif ($step === 3): ?>
<h3 class="mb-0" style="font-size:15px;margin-bottom:15px">Step 3: Installation Complete</h3>
<div class="alert alert-success">
<strong>Congratulations!</strong> ScolemaxAI has been installed successfully.
</div>

<div class="info-box">
<strong>Next Steps:</strong><br>
1. Create your super admin account<br>
2. Configure your organization settings<br>
3. Add monitoring targets<br>
4. Activate your license (demo available)
</div>

<form method="POST" class="mt-3">
<button type="submit" name="finalize" class="btn btn-success btn-block">Complete Installation & Register →</button>
</form>

<p class="text-muted text-center mt-3">The installation wizard will be locked after completion.</p>
<?php endif; ?>
</div>
</div>

<div class="text-center text-muted">
<p>© <?php echo date('Y'); ?> ScolemaxAI-Kenya. All rights reserved.</p>
</div>
</div>
</body>
</html>