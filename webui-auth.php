<?php
/**
 * SMV Security - WAF WebUI Authentication
 * Simple login/registration for customer dashboard
 * NO API credentials stored here - only for webui access
 */

// Start session FIRST
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Load config if it exists
if (file_exists(__DIR__ . '/config.php')) {
    require_once __DIR__ . '/config.php';
} else {
    // Fallback for standalone webui
    define('DB_HOST', 'localhost');
    define('DB_USER', 'root');
    define('DB_PASS', '');
    define('DB_NAME', 'smv_waf_local');
    define('ENVIRONMENT', 'production');
}

// Start output buffering
ob_start();

// Initialize variables
$page = isset($_GET['page']) && in_array($_GET['page'], ['login', 'register']) ? $_GET['page'] : 'login';
$message = '';
$errors = [];

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: webui-auth.php?page=login&message=Logged out successfully');
    exit;
}

// Database connection helper
function getWAFDB() {
    static $conn = null;
    if ($conn === null) {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            die('Database connection failed: ' . $conn->connect_error);
        }
        $conn->set_charset('utf8mb4');
    }
    return $conn;
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);
    
    // Validate input
    if (empty($email) || empty($password)) {
        $errors[] = 'Email and password are required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Invalid email address';
    } else {
        try {
            $db = getWAFDB();
            
            // Check if customers table exists and has password_hash field
            $result = $db->query("DESCRIBE customers");
            if ($result) {
                $columns = [];
                while ($row = $result->fetch_assoc()) {
                    $columns[] = $row['Field'];
                }
                
                if (in_array('password_hash', $columns)) {
                    // Use password verification
                    $stmt = $db->prepare(
                        "SELECT id, company_name, password_hash FROM customers WHERE contact_email = ? AND is_active = 1 LIMIT 1"
                    );
                    
                    $stmt->bind_param("s", $email);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $customer = $result->fetch_assoc();
                    
                    if (!$customer) {
                        $errors[] = 'Invalid email or customer not found';
                    } elseif ($customer['password_hash'] && password_verify($password, $customer['password_hash'])) {
                        // Login successful
                        $_SESSION['webui_customer_id'] = $customer['id'];
                        $_SESSION['webui_email'] = $email;
                        $_SESSION['webui_company'] = $customer['company_name'];
                        $_SESSION['webui_login_time'] = time();
                        
                        // Update last login
                        $update = $db->prepare("UPDATE customers SET last_login = NOW(), login_attempts = 0 WHERE id = ?");
                        $update->bind_param("i", $customer['id']);
                        $update->execute();
                        
                        // Remember me cookie
                        if ($remember) {
                            setcookie(
                                'webui_remember',
                                bin2hex(random_bytes(32)),
                                time() + (30 * 24 * 60 * 60),
                                '/',
                                '',
                                false,
                                true
                            );
                        }
                        
                        header('Location: webui.php');
                        exit;
                    } else {
                        $errors[] = 'Invalid email or password';
                        // Track failed attempts
                        $upd = $db->prepare("UPDATE customers SET login_attempts = login_attempts + 1 WHERE id = ?");
                        $upd->bind_param("i", $customer['id']);
                        $upd->execute();
                    }
                } else {
                    // No password_hash field, use simple email verification
                    $stmt = $db->prepare(
                        "SELECT id, company_name FROM customers WHERE contact_email = ? AND is_active = 1 LIMIT 1"
                    );
                    
                    $stmt->bind_param("s", $email);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $customer = $result->fetch_assoc();
                    
                    if (!$customer) {
                        $errors[] = 'Customer account not found';
                    } else {
                        // Simple verification - just check if account exists
                        // In production, implement proper email verification
                        $_SESSION['webui_customer_id'] = $customer['id'];
                        $_SESSION['webui_email'] = $email;
                        $_SESSION['webui_company'] = $customer['company_name'];
                        $_SESSION['webui_login_time'] = time();
                        
                        $update = $db->prepare("UPDATE customers SET last_login = NOW() WHERE id = ?");
                        $update->bind_param("i", $customer['id']);
                        $update->execute();
                        
                        if ($remember) {
                            setcookie(
                                'webui_remember',
                                bin2hex(random_bytes(32)),
                                time() + (30 * 24 * 60 * 60),
                                '/',
                                '',
                                false,
                                true
                            );
                        }
                        
                        header('Location: webui.php');
                        exit;
                    }
                }
            }
        } catch (Exception $e) {
            $errors[] = 'An error occurred during login. Please try again.';
            error_log("WebUI login error: " . $e->getMessage());
        }
    }
}

// Handle registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'register') {
    $company_name = trim($_POST['company_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';
    
    // Validate input
    if (empty($company_name) || empty($email) || empty($password)) {
        $errors[] = 'Company name, email, and password are required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Invalid email address';
    } elseif (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters';
    } elseif ($password !== $password_confirm) {
        $errors[] = 'Passwords do not match';
    } else {
        try {
            $db = getWAFDB();
            
            // Check if email exists
            $check = $db->prepare("SELECT id FROM customers WHERE contact_email = ? LIMIT 1");
            $check->bind_param("s", $email);
            $check->execute();
            $check_result = $check->get_result();
            
            if ($check_result->num_rows > 0) {
                $errors[] = 'Email address already registered';
            } else {
                // Check if password_hash column exists
                $result = $db->query("DESCRIBE customers");
                $columns = [];
                while ($row = $result->fetch_assoc()) {
                    $columns[] = $row['Field'];
                }
                
                if (in_array('password_hash', $columns)) {
                    // Register with password
                    $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                    
                    $stmt = $db->prepare(
                        "INSERT INTO customers (company_name, contact_email, contact_phone, is_active) 
                        VALUES (?, ?, ?, 1)"
                    );
                    
                    $stmt->bind_param("sss", $company_name, $email, $phone);
                    
                    if ($stmt->execute()) {
                        $customer_id = $db->insert_id;
                        
                        // Update password
                        $upd = $db->prepare("UPDATE customers SET password_hash = ? WHERE id = ?");
                        $upd->bind_param("si", $password_hash, $customer_id);
                        $upd->execute();
                        
                        $message = 'Account created successfully! Please log in.';
                        $page = 'login';
                    } else {
                        $errors[] = 'Failed to create account: ' . $db->error;
                    }
                } else {
                    // Simple registration without password
                    $stmt = $db->prepare(
                        "INSERT INTO customers (company_name, contact_email, contact_phone, is_active) 
                        VALUES (?, ?, ?, 1)"
                    );
                    
                    $stmt->bind_param("sss", $company_name, $email, $phone);
                    
                    if ($stmt->execute()) {
                        $message = 'Account created successfully! Please log in.';
                        $page = 'login';
                    } else {
                        $errors[] = 'Failed to create account: ' . $db->error;
                    }
                }
            }
        } catch (Exception $e) {
            $errors[] = 'An error occurred during registration. Please try again.';
            error_log("WebUI registration error: " . $e->getMessage());
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMV Security WAF - Customer Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0e1a;color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;font-size:14px;background-image:radial-gradient(circle at 20% 50%,rgba(37,99,235,.1) 0%,transparent 50%),radial-gradient(circle at 80% 80%,rgba(59,130,246,.1) 0%,transparent 50%)}
.container{width:100%;max-width:450px;padding:20px}
.auth-card{background:#111827;border-radius:16px;padding:40px 35px;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 0 1px rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.1)}
.logo{text-align:center;margin-bottom:30px}
.logo h1{font-size:28px;font-weight:700;background:linear-gradient(135deg,#3b82f6 0%,#60a5fa 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:8px;letter-spacing:-0.5px}
.logo p{font-size:13px;color:#9ca3af;font-weight:500;letter-spacing:0.5px}
.tabs{display:flex;gap:8px;margin-bottom:28px;background:#0a0e1a;border-radius:10px;padding:5px;border:1px solid rgba(59,130,246,.1)}
.tab{flex:1;padding:11px;text-align:center;background:transparent;border:none;color:#9ca3af;font-size:13px;font-weight:600;cursor:pointer;border-radius:7px;transition:all .3s;position:relative}
.tab.active{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;box-shadow:0 4px 12px rgba(59,130,246,.3)}
.tab:hover:not(.active){color:#fff;background:rgba(59,130,246,.1)}
.form-container{display:none;animation:fadeIn .3s ease-in}
.form-container.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.form-group{margin-bottom:20px}
.form-group label{display:block;margin-bottom:8px;font-size:13px;font-weight:600;color:#e5e7eb;letter-spacing:0.3px}
.form-group input{width:100%;padding:12px 16px;background:#0a0e1a;border:1px solid rgba(59,130,246,.2);border-radius:8px;color:#e5e7eb;font-size:14px;transition:all .3s;font-family:'Inter',sans-serif}
.form-group input:focus{outline:none;border-color:#3b82f6;background:#111827;box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.form-group input::placeholder{color:#6b7280}
.alert{padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:13px;font-weight:500;animation:slideDown .3s ease}
@keyframes slideDown{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.alert-error{background:rgba(239,68,68,.1);color:#fca5a5;border:1px solid rgba(239,68,68,.2)}
.alert-success{background:rgba(34,197,94,.1);color:#86efac;border:1px solid rgba(34,197,94,.2)}
.btn{width:100%;padding:13px;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:all .3s;box-shadow:0 4px 12px rgba(59,130,246,.3);font-family:'Inter',sans-serif;letter-spacing:0.3px}
.btn:hover{background:linear-gradient(135deg,#2563eb 0%,#1d4ed8 100%);transform:translateY(-2px);box-shadow:0 6px 20px rgba(59,130,246,.4)}
.btn:active{transform:translateY(0);box-shadow:0 2px 8px rgba(59,130,246,.3)}
.link-text{text-align:center;margin-top:20px;font-size:13px;color:#9ca3af}
.link-text a{color:#3b82f6;text-decoration:none;font-weight:600;transition:color .3s}
.link-text a:hover{color:#60a5fa;text-decoration:underline}
.footer{text-align:center;margin-top:25px;font-size:12px;color:#6b7280;letter-spacing:0.3px}
.input-group{position:relative}
.toggle-password{position:absolute;right:14px;top:50%;transform:translateY(-50%);background:none;border:none;color:#6b7280;cursor:pointer;font-size:16px;padding:0;transition:color .3s}
.toggle-password:hover{color:#3b82f6}
.checkbox-group{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.checkbox-group input[type="checkbox"]{width:18px;height:18px;margin:0;cursor:pointer;accent-color:#3b82f6}
.checkbox-group label{margin:0;font-size:13px;color:#9ca3af;font-weight:400;cursor:pointer}
.security-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(59,130,246,.1);color:#60a5fa;padding:6px 12px;border-radius:6px;font-size:11px;font-weight:600;margin-top:20px;border:1px solid rgba(59,130,246,.2)}
.security-badge svg{width:14px;height:14px}
.optional{color:#6b7280;font-weight:400}
    </style>
</head>
<body>
    <div class="container">
        <div class="auth-card">
            <div class="logo">
                <h1>🛡️ SMV Security WAF</h1>
                <p>CUSTOMER DASHBOARD LOGIN</p>
            </div>

            <?php if (!empty($message)): ?>
                <div class="alert alert-success">✓ <?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-error">
                    <?php foreach ($errors as $error): ?>
                        ⚠ <?php echo htmlspecialchars($error); ?><br>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <div class="tabs">
                <button class="tab <?php echo $page === 'login' ? 'active' : ''; ?>" onclick="switchTab('login')">Login</button>
                <button class="tab <?php echo $page === 'register' ? 'active' : ''; ?>" onclick="switchTab('register')">Register</button>
            </div>

            <!-- Login Form -->
            <div id="login-form" class="form-container <?php echo $page === 'login' ? 'active' : ''; ?>">
                <form method="POST" action="webui-auth.php">
                    <input type="hidden" name="action" value="login">
                    
                    <div class="form-group">
                        <label>Email Address</label>
                        <input type="email" name="email" placeholder="company@example.com" required autocomplete="email">
                    </div>
                    
                    <div class="form-group">
                        <label>Password</label>
                        <div class="input-group">
                            <input type="password" id="login-password" name="password" placeholder="Enter your password" required autocomplete="current-password">
                            <button type="button" class="toggle-password" onclick="togglePassword('login-password')" title="Show/Hide Password">👁️</button>
                        </div>
                    </div>

                    <div class="checkbox-group">
                        <input type="checkbox" id="remember" name="remember">
                        <label for="remember">Keep me logged in for 30 days</label>
                    </div>
                    
                    <button type="submit" class="btn">Login to Dashboard</button>
                    
                    <div style="text-align:center;margin-top:15px">
                        <span class="security-badge">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                            Secured Connection
                        </span>
                    </div>
                </form>
                
                <div class="link-text">
                    Don't have an account? <a href="webui-auth.php?page=register">Register here</a>
                </div>
            </div>

            <!-- Registration Form -->
            <div id="register-form" class="form-container <?php echo $page === 'register' ? 'active' : ''; ?>">
                <form method="POST" action="webui-auth.php">
                    <input type="hidden" name="action" value="register">
                    
                    <div class="form-group">
                        <label>Company Name</label>
                        <input type="text" name="company_name" placeholder="Your Company Name" required autocomplete="organization">
                    </div>
                    
                    <div class="form-group">
                        <label>Email Address</label>
                        <input type="email" name="email" placeholder="company@example.com" required autocomplete="email">
                    </div>
                    
                    <div class="form-group">
                        <label>Phone Number <span class="optional">(Optional)</span></label>
                        <input type="tel" name="phone" placeholder="+254 7XX XXX XXX" autocomplete="tel">
                    </div>
                    
                    <div class="form-group">
                        <label>Password</label>
                        <div class="input-group">
                            <input type="password" id="reg-password" name="password" placeholder="Minimum 8 characters" required minlength="8" autocomplete="new-password">
                            <button type="button" class="toggle-password" onclick="togglePassword('reg-password')" title="Show/Hide Password">👁️</button>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Confirm Password</label>
                        <div class="input-group">
                            <input type="password" id="reg-confirm-password" name="password_confirm" placeholder="Re-enter your password" required minlength="8" autocomplete="new-password">
                            <button type="button" class="toggle-password" onclick="togglePassword('reg-confirm-password')" title="Show/Hide Password">👁️</button>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn">Create Account</button>
                    
                    <div style="text-align:center;margin-top:15px">
                        <span class="security-badge">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                            Safe Registration
                        </span>
                    </div>
                </form>
                
                <div class="link-text">
                    Already have an account? <a href="webui-auth.php?page=login">Sign in here</a>
                </div>
            </div>

            <div class="footer">
                &copy; <?php echo date('Y'); ?> SMV Security. Kenya Cybersecurity System.
            </div>
        </div>
    </div>

    <script>
        function switchTab(tab){
            window.location.href='webui-auth.php?page='+tab;
        }
        function togglePassword(id){
            const input=document.getElementById(id);
            const button=input.nextElementSibling;
            if(input.type==='password'){
                input.type='text';
                button.textContent='🔒';
            }else{
                input.type='password';
                button.textContent='👁️';
            }
        }
    </script>
</body>
</html>
<?php ob_end_flush(); ?>
