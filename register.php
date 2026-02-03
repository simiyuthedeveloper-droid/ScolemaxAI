<?php
/**
 * ScolemaxAI-Kenya - Super Admin Registration
 * This page is ONLY for creating the first Super Admin account
 * Regular users are added by Super Admin through the dashboard
 */

require_once 'config.php';

// Check if registration is locked by super admin
$db = getDB();

// Check system setting for registration lock
$stmt = $db->query("SELECT setting_value FROM settings WHERE setting_key = 'lock_super_admin_registration' LIMIT 1");
$lockSetting = $stmt->fetch();

if ($lockSetting && $lockSetting['setting_value'] === '1') {
    redirect('login.php', 'Super Admin registration has been locked. Contact existing administrator.', 'warning');
}

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get form data
    $organization_name = sanitize($_POST['organization_name'] ?? '');
    $full_name = sanitize($_POST['full_name'] ?? '');
    $email = sanitize($_POST['email'] ?? '');
    $username = sanitize($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // Validation
    if (empty($organization_name)) {
        $errors[] = 'Organization name is required';
    }
    if (empty($full_name)) {
        $errors[] = 'Full name is required';
    }
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Valid email is required';
    }
    if (empty($username) || strlen($username) < 4) {
        $errors[] = 'Username must be at least 4 characters';
    }
    if (empty($password) || strlen($password) < PASSWORD_MIN_LENGTH) {
        $errors[] = 'Password must be at least ' . PASSWORD_MIN_LENGTH . ' characters';
    }
    if ($password !== $confirm_password) {
        $errors[] = 'Passwords do not match';
    }
    
    // Check if email or username already exists
    if (empty($errors)) {
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM users WHERE email = ? OR username = ?");
        $stmt->execute([$email, $username]);
        $exists = $stmt->fetch();
        
        if ($exists['count'] > 0) {
            $errors[] = 'Email or username already exists';
        }
    }
    
    // Create organization and super admin
    if (empty($errors)) {
        try {
            $db->beginTransaction();
            
            // Create organization
            $stmt = $db->prepare("INSERT INTO organizations (name, email, license_status, created_at) 
                                  VALUES (?, ?, 'inactive', NOW())");
            $stmt->execute([$organization_name, $email]);
            $org_id = $db->lastInsertId();
            
            // Create default departments
            $departments = [
                ['IT Department', 'Information Technology and Systems'],
                ['Security Department', 'Cybersecurity and Threat Management'],
                ['Compliance Department', 'Regulatory Compliance and Auditing']
            ];
            
            $dept_stmt = $db->prepare("INSERT INTO departments (organization_id, name, description) VALUES (?, ?, ?)");
            foreach ($departments as $dept) {
                $dept_stmt->execute([$org_id, $dept[0], $dept[1]]);
            }
            
            // Get IT department ID
            $stmt = $db->prepare("SELECT id FROM departments WHERE organization_id = ? AND name = 'IT Department' LIMIT 1");
            $stmt->execute([$org_id]);
            $it_dept = $stmt->fetch();
            $dept_id = $it_dept['id'];
            
            // Create super admin user
            $password_hash = hashPassword($password);
            $stmt = $db->prepare("INSERT INTO users (organization_id, department_id, username, email, password_hash, full_name, role, status, created_at) 
                                  VALUES (?, ?, ?, ?, ?, ?, 'super_admin', 'active', NOW())");
            $stmt->execute([$org_id, $dept_id, $username, $email, $password_hash, $full_name]);
            
            // Create default settings
            $default_settings = [
                ['email_alerts', '1', 'boolean'],
                ['sms_alerts', '0', 'boolean'],
                ['whatsapp_alerts', '0', 'boolean'],
                ['auto_block_threats', '1', 'boolean'],
                ['auto_quarantine', '1', 'boolean'],
                ['alert_recipients', '["' . $email . '"]', 'json'],
                ['detection_sensitivity', 'medium', 'string'],
                ['log_retention_days', '90', 'integer'],
                ['lock_super_admin_registration', '0', 'boolean']
            ];
            
            $settings_stmt = $db->prepare("INSERT INTO settings (organization_id, setting_key, setting_value, setting_type) VALUES (?, ?, ?, ?)");
            foreach ($default_settings as $setting) {
                $settings_stmt->execute([$org_id, $setting[0], $setting[1], $setting[2]]);
            }
            
            $db->commit();
            
            redirect('login.php', 'Registration successful! Please login.', 'success');
            
        } catch (PDOException $e) {
            $db->rollBack();
            $errors[] = 'Registration failed: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin Registration - <?php echo SITE_NAME; ?></title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#1a2a4a 0%,#0f1e38 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
        .container{background:#fff;border-radius:15px;box-shadow:0 20px 60px rgba(0,0,0,0.3);max-width:500px;width:100%;padding:40px;animation:slideIn 0.5s ease}
        @keyframes slideIn{from{opacity:0;transform:translateY(-30px)}to{opacity:1;transform:translateY(0)}}
        .logo{text-align:center;margin-bottom:30px}
        .logo-icon{width:80px;height:80px;background:linear-gradient(135deg,#ff6b35 0%,#ffc837 100%);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:36px;color:#fff;font-weight:bold;box-shadow:0 5px 15px rgba(255,107,53,0.4)}
        h1{color:#333;font-size:28px;margin:20px 0 10px;text-align:center}
        .subtitle{color:#666;text-align:center;font-size:14px;margin-bottom:30px}
        .alert{padding:12px 15px;border-radius:8px;margin-bottom:20px;font-size:14px}
        .alert-danger{background:#fee;color:#c33;border-left:4px solid #c33}
        .alert-success{background:#efe;color:#3c3;border-left:4px solid #3c3}
        .form-group{margin-bottom:20px}
        label{display:block;color:#333;font-weight:600;margin-bottom:8px;font-size:14px}
        .required{color:#e74c3c}
        input[type="text"],input[type="email"],input[type="password"]{width:100%;padding:12px 15px;border:2px solid #e0e0e0;border-radius:8px;font-size:14px;transition:all 0.3s;background:#fafafa}
        input:focus{outline:none;border-color:#ff6b35;background:#fff;box-shadow:0 0 0 3px rgba(255,107,53,0.1)}
        .input-icon{position:relative}
        .input-icon input{padding-left:40px}
        .input-icon::before{content:'👤';position:absolute;left:12px;top:50%;transform:translateY(-50%);font-size:18px}
        .input-icon.email::before{content:'✉️'}
        .input-icon.lock::before{content:'🔒'}
        .input-icon.org::before{content:'🏢'}
        button{width:100%;padding:14px;background:linear-gradient(135deg,#ff6b35 0%,#ffc837 100%);color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:all 0.3s;box-shadow:0 4px 15px rgba(255,107,53,0.4)}
        button:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(255,107,53,0.6)}
        button:active{transform:translateY(0)}
        .login-link{text-align:center;margin-top:25px;color:#666;font-size:14px}
        .login-link a{color:#ff6b35;text-decoration:none;font-weight:600}
        .login-link a:hover{text-decoration:underline}
        .password-strength{height:4px;background:#e0e0e0;border-radius:2px;margin-top:8px;overflow:hidden}
        .password-strength-bar{height:100%;width:0;transition:all 0.3s;background:#e74c3c}
        .strength-weak{width:33%;background:#e74c3c}
        .strength-medium{width:66%;background:#f39c12}
        .strength-strong{width:100%;background:#27ae60}
        .divider{text-align:center;margin:25px 0;color:#999;font-size:14px;position:relative}
        .divider::before,.divider::after{content:'';position:absolute;top:50%;width:40%;height:1px;background:#e0e0e0}
        .divider::before{left:0}
        .divider::after{right:0}
        .feature-list{background:#f8f9fa;padding:20px;border-radius:8px;margin:20px 0}
        .feature-list h3{font-size:14px;color:#333;margin-bottom:12px;font-weight:600}
        .feature-list ul{list-style:none}
        .feature-list li{padding:6px 0;color:#666;font-size:13px;position:relative;padding-left:25px}
        .feature-list li::before{content:'✓';position:absolute;left:0;color:#27ae60;font-weight:bold;font-size:16px}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <div class="logo-icon">S</div>
            <h1>ScolemaxAI-Kenya</h1>
            <p class="subtitle">Create Super Admin Account</p>
        </div>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <?php foreach ($errors as $error): ?>
                    <div>• <?php echo htmlspecialchars($error); ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <div class="feature-list">
            <h3>🚀 What You Get:</h3>
            <ul>
                <li>AI-Powered Threat Detection</li>
                <li>Real-Time Security Monitoring</li>
                <li>Automated Incident Response</li>
                <li>Department & User Management</li>
                <li>Compliance Reporting Tools</li>
            </ul>
        </div>

        <form method="POST" action="" id="registerForm">
            <div class="form-group">
                <label>Organization Name <span class="required">*</span></label>
                <div class="input-icon org">
                    <input type="text" name="organization_name" placeholder="e.g., Safaricom Ltd" 
                           value="<?php echo htmlspecialchars($_POST['organization_name'] ?? ''); ?>" required>
                </div>
            </div>

            <div class="form-group">
                <label>Full Name <span class="required">*</span></label>
                <div class="input-icon">
                    <input type="text" name="full_name" placeholder="John Doe" 
                           value="<?php echo htmlspecialchars($_POST['full_name'] ?? ''); ?>" required>
                </div>
            </div>

            <div class="form-group">
                <label>Email Address <span class="required">*</span></label>
                <div class="input-icon email">
                    <input type="email" name="email" placeholder="admin@company.co.ke" 
                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
                </div>
            </div>

            <div class="form-group">
                <label>Username <span class="required">*</span></label>
                <div class="input-icon">
                    <input type="text" name="username" placeholder="admin" 
                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" 
                           minlength="4" required>
                </div>
            </div>

            <div class="form-group">
                <label>Password <span class="required">*</span></label>
                <div class="input-icon lock">
                    <input type="password" name="password" id="password" 
                           placeholder="Min. <?php echo PASSWORD_MIN_LENGTH; ?> characters" 
                           minlength="<?php echo PASSWORD_MIN_LENGTH; ?>" required>
                </div>
                <div class="password-strength">
                    <div class="password-strength-bar" id="strengthBar"></div>
                </div>
            </div>

            <div class="form-group">
                <label>Confirm Password <span class="required">*</span></label>
                <div class="input-icon lock">
                    <input type="password" name="confirm_password" id="confirm_password" 
                           placeholder="Re-enter password" 
                           minlength="<?php echo PASSWORD_MIN_LENGTH; ?>" required>
                </div>
            </div>

            <button type="submit">Create Super Admin Account</button>
        </form>

        <div class="divider">OR</div>

        <div class="login-link">
            Already have an account? <a href="login.php">Login here</a>
        </div>
    </div>

    <script>
        // Password strength checker
        const password = document.getElementById('password');
        const strengthBar = document.getElementById('strengthBar');
        
        password.addEventListener('input', function() {
            const val = this.value;
            const length = val.length;
            
            strengthBar.className = 'password-strength-bar';
            
            if (length === 0) {
                strengthBar.style.width = '0';
            } else if (length < 6) {
                strengthBar.classList.add('strength-weak');
            } else if (length < 10) {
                strengthBar.classList.add('strength-medium');
            } else {
                strengthBar.classList.add('strength-strong');
            }
        });

        // Password match validation
        const confirmPassword = document.getElementById('confirm_password');
        const form = document.getElementById('registerForm');
        
        form.addEventListener('submit', function(e) {
            if (password.value !== confirmPassword.value) {
                e.preventDefault();
                alert('Passwords do not match!');
                confirmPassword.focus();
            }
        });

        // Real-time password match indicator
        confirmPassword.addEventListener('input', function() {
            if (this.value && password.value !== this.value) {
                this.style.borderColor = '#e74c3c';
            } else if (this.value && password.value === this.value) {
                this.style.borderColor = '#27ae60';
            } else {
                this.style.borderColor = '#e0e0e0';
            }
        });
    </script>
</body>
</html>