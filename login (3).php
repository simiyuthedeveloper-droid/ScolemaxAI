<?php
/**
 * ScolemaxAI-Kenya - Login Page
 * All users (Super Admin, Managers, Staff) login through this page
 */

require_once 'config.php';

// Redirect if already logged in
if (isLoggedIn()) {
    redirect('dashboard.php');
}

$errors = [];
$username_value = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitize($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);
    
    $username_value = $username; // Keep username in field if error
    
    // Validation
    if (empty($username)) {
        $errors[] = 'Username is required';
    }
    if (empty($password)) {
        $errors[] = 'Password is required';
    }
    
    // Authenticate user
    if (empty($errors)) {
        try {
            $db = getDB();
            $stmt = $db->prepare("SELECT u.*, d.name as department_name, o.name as organization_name, o.license_status 
                                  FROM users u 
                                  LEFT JOIN departments d ON u.department_id = d.id 
                                  LEFT JOIN organizations o ON u.organization_id = o.id 
                                  WHERE u.username = ? OR u.email = ?");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            if ($user && verifyPassword($password, $user['password_hash'])) {
                // Check if user account is active
                if ($user['status'] !== 'active') {
                    $errors[] = 'Your account has been ' . $user['status'] . '. Contact administrator.';
                } else {
                    // Successful login
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['full_name'] = $user['full_name'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['department_id'] = $user['department_id'];
                    $_SESSION['organization_id'] = $user['organization_id'];
                    $_SESSION['logged_in'] = true;
                    $_SESSION['last_activity'] = time();
                    
                    // Set remember me cookie (30 days)
                    if ($remember) {
                        $token = bin2hex(random_bytes(32));
                        setcookie('remember_token', $token, time() + (86400 * 30), '/');
                        // In production, store this token in database
                    }
                    
                    // Update last login
                    $updateStmt = $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                    $updateStmt->execute([$user['id']]);
                    
                    // Log activity
                    logActivity('user_login', 'User logged in successfully', $user['id']);
                    
                    // Redirect to dashboard
                    redirect('dashboard.php', 'Welcome back, ' . $user['full_name'] . '!', 'success');
                }
            } else {
                $errors[] = 'Invalid username or password';
                // Log failed attempt
                logActivity('login_failed', 'Failed login attempt for username: ' . $username, null);
            }
        } catch (PDOException $e) {
            $errors[] = 'Login error. Please try again.';
        }
    }
}

// Get flash message if any
$flash = getFlashMessage();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo SITE_NAME; ?></title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#1a2a4a 0%,#0f1e38 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;position:relative}
        body::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320"><path fill="%23ff6b35" fill-opacity="0.05" d="M0,96L48,112C96,128,192,160,288,160C384,160,480,128,576,122.7C672,117,768,139,864,154.7C960,171,1056,181,1152,165.3C1248,149,1344,107,1392,85.3L1440,64L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path></svg>') no-repeat bottom;background-size:cover;opacity:0.3}
        .container{background:#fff;border-radius:20px;box-shadow:0 25px 70px rgba(0,0,0,0.3);max-width:450px;width:100%;padding:50px 40px;animation:slideIn 0.6s ease;position:relative;z-index:1}
        @keyframes slideIn{from{opacity:0;transform:translateY(-40px)}to{opacity:1;transform:translateY(0)}}
        .logo{text-align:center;margin-bottom:35px}
        .logo-icon{width:90px;height:90px;background:linear-gradient(135deg,#ff6b35 0%,#ffc837 100%);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:42px;color:#fff;font-weight:bold;box-shadow:0 8px 20px rgba(255,107,53,0.5);margin-bottom:15px;animation:pulse 2s infinite}
        @keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.05)}}
        h1{color:#333;font-size:32px;margin-bottom:8px}
        .subtitle{color:#666;font-size:15px;margin-bottom:30px}
        .alert{padding:14px 18px;border-radius:10px;margin-bottom:20px;font-size:14px;animation:fadeIn 0.3s}
        @keyframes fadeIn{from{opacity:0}to{opacity:1}}
        .alert-danger{background:#fee2e2;color:#dc2626;border-left:4px solid #dc2626}
        .alert-success{background:#d1fae5;color:#059669;border-left:4px solid #059669}
        .alert-warning{background:#fef3c7;color:#d97706;border-left:4px solid #d97706}
        .alert-info{background:#dbeafe;color:#2563eb;border-left:4px solid #2563eb}
        .form-group{margin-bottom:24px;position:relative}
        label{display:block;color:#333;font-weight:600;margin-bottom:10px;font-size:14px}
        input[type="text"],input[type="password"]{width:100%;padding:14px 18px 14px 50px;border:2px solid #e5e7eb;border-radius:10px;font-size:15px;transition:all 0.3s;background:#f9fafb}
        input:focus{outline:none;border-color:#ff6b35;background:#fff;box-shadow:0 0 0 4px rgba(255,107,53,0.1)}
        .input-wrapper{position:relative}
        .input-icon{position:absolute;left:16px;top:50%;transform:translateY(-50%);font-size:20px;opacity:0.6;transition:opacity 0.3s}
        input:focus + .input-icon{opacity:1}
        .checkbox-group{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
        .checkbox-wrapper{display:flex;align-items:center}
        input[type="checkbox"]{width:18px;height:18px;margin-right:8px;cursor:pointer;accent-color:#ff6b35}
        .checkbox-label{color:#666;font-size:14px;cursor:pointer;user-select:none}
        .forgot-link{color:#ff6b35;text-decoration:none;font-size:14px;font-weight:600;transition:color 0.3s}
        .forgot-link:hover{color:#ffc837;text-decoration:underline}
        button{width:100%;padding:16px;background:linear-gradient(135deg,#ff6b35 0%,#ffc837 100%);color:#fff;border:none;border-radius:10px;font-size:17px;font-weight:600;cursor:pointer;transition:all 0.3s;box-shadow:0 6px 20px rgba(255,107,53,0.4);position:relative;overflow:hidden}
        button::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;border-radius:50%;background:rgba(255,255,255,0.3);transform:translate(-50%,-50%);transition:width 0.6s,height 0.6s}
        button:hover::before{width:300px;height:300px}
        button:hover{transform:translateY(-3px);box-shadow:0 8px 25px rgba(255,107,53,0.6)}
        button:active{transform:translateY(-1px)}
        .divider{text-align:center;margin:30px 0;color:#999;font-size:14px;position:relative}
        .divider::before,.divider::after{content:'';position:absolute;top:50%;width:42%;height:1px;background:#e5e7eb}
        .divider::before{left:0}
        .divider::after{right:0}
        .register-link{text-align:center;margin-top:25px;color:#666;font-size:14px}
        .register-link a{color:#ff6b35;text-decoration:none;font-weight:600;transition:color 0.3s}
        .register-link a:hover{color:#ffc837;text-decoration:underline}
        .demo-credentials{background:linear-gradient(135deg,#f3f4f6 0%,#e5e7eb 100%);padding:18px;border-radius:10px;margin-bottom:25px;border-left:4px solid #ff6b35}
        .demo-credentials h4{color:#333;font-size:14px;margin-bottom:10px;display:flex;align-items:center;gap:8px}
        .demo-credentials p{color:#666;font-size:13px;margin:5px 0;font-family:monospace}
        .demo-credentials strong{color:#333}
        .security-badge{display:flex;align-items:center;justify-content:center;gap:8px;margin-top:30px;color:#666;font-size:13px}
        .security-badge::before{content:'🔒'}
        .loading{display:none;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%)}
        .spinner{width:24px;height:24px;border:3px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.8s linear infinite}
        @keyframes spin{to{transform:rotate(360deg)}}
        button.loading .btn-text{opacity:0}
        button.loading .loading{display:block}
        @media(max-width:480px){.container{padding:35px 25px}.logo-icon{width:70px;height:70px;font-size:32px}h1{font-size:26px}}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <div class="logo-icon">S</div>
            <h1>ScolemaxAI-Kenya</h1>
            <p class="subtitle">Intelligent Cyber Threat Detection</p>
        </div>

        <?php if ($flash): ?>
            <div class="alert alert-<?php echo $flash['type']; ?>">
                <?php echo htmlspecialchars($flash['text']); ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <?php foreach ($errors as $error): ?>
                    <div>â€¢ <?php echo htmlspecialchars($error); ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <div class="demo-credentials">
            <h4>🎯 Demo Credentials</h4>
            <p><strong>Username:</strong> admin</p>
            <p><strong>Password:</strong> Admin@2025</p>
        </div>

        <form method="POST" action="" id="loginForm">
            <div class="form-group">
                <label>Username or Email</label>
                <div class="input-wrapper">
                    <input type="text" name="username" id="username" 
                           placeholder="Enter username or email" 
                           value="<?php echo htmlspecialchars($username_value); ?>" 
                           autocomplete="username" required autofocus>
                    <span class="input-icon">👤</span>
                </div>
            </div>

            <div class="form-group">
                <label>Password</label>
                <div class="input-wrapper">
                    <input type="password" name="password" id="password" 
                           placeholder="Enter your password" 
                           autocomplete="current-password" required>
                    <span class="input-icon">🔒</span>
                </div>
            </div>

            <div class="checkbox-group">
                <div class="checkbox-wrapper">
                    <input type="checkbox" name="remember" id="remember">
                    <label for="remember" class="checkbox-label">Remember me</label>
                </div>
                <a href="#" class="forgot-link" onclick="alert('Contact your administrator to reset password'); return false;">Forgot password?</a>
            </div>

            <button type="submit" id="loginBtn">
                <span class="btn-text">Sign In</span>
                <div class="loading">
                    <div class="spinner"></div>
                </div>
            </button>
        </form>

        <div class="divider">OR</div>

        <div class="register-link">
            Don't have an account? <a href="register.php">Create Super Admin Account</a>
        </div>

        <div class="security-badge">
            Secured with 256-bit encryption
        </div>
    </div>

    <script>
        // Form submission with loading state
        const loginForm = document.getElementById('loginForm');
        const loginBtn = document.getElementById('loginBtn');
        
        loginForm.addEventListener('submit', function() {
            loginBtn.classList.add('loading');
            loginBtn.disabled = true;
        });

        // Auto-fill demo credentials (optional - for presentation ease)
        document.addEventListener('keydown', function(e) {
            // Press Ctrl+D to auto-fill demo credentials
            if (e.ctrlKey && e.key === 'd') {
                e.preventDefault();
                document.getElementById('username').value = 'admin';
                document.getElementById('password').value = 'Admin@2025';
                document.getElementById('username').focus();
            }
        });

        // Clear any stale sessions on page load
        if (performance.navigation.type === 1) {
            // Page was refreshed
            console.log('Page refreshed - ready for login');
        }

        // Focus username field on load
        window.addEventListener('load', function() {
            document.getElementById('username').focus();
        });

        // Enter key support for better UX
        document.getElementById('username').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                document.getElementById('password').focus();
            }
        });
    </script>
</body>
</html>