# 🛡️ SMV Security WAF - Installation & Usage Guide

## Overview

SMV Security WAF is a **free, open-source Web Application Firewall** designed for **Kenyan organizations**. It provides automated threat detection, AI-powered analysis, and network-wide threat intelligence sharing.

**Key Features:**
- ✅ Automatic threat detection from server logs
- ✅ AI-powered analysis via LLAMA (local or cloud)
- ✅ Network-wide threat intelligence sharing
- ✅ Automatic IP blocking and rate limiting
- ✅ One-command installation
- ✅ 100% free and open-source
- ✅ No licensing fees or vendor lock-in

---

## System Requirements

### Minimum Requirements
- **PHP** 7.4 or higher
- **MySQL/MariaDB** 5.7 or higher
- **Linux/Unix** server (Apache, Nginx, cPanel, or Plesk)
- **5 MB** disk space (logs grow over time)
- **cron** access for daemon scheduling

### Required PHP Extensions
```bash
php-mysqli      # MySQL database
php-curl        # API communication
php-json        # JSON parsing
php-posix       # Process handling
php-pcntl       # Process control (optional)
```

### Supported Web Servers
- Apache with mod_rewrite
- Nginx with conf.d support
- cPanel/WHM
- Plesk
- LiteSpeed
- OpenLiteSpeed

---

## Installation

### Step 1: Download WAF

Download the WAF system from the Control Center:

1. Go to: `https://threatresponder.scolemax.co.ke/`
2. Fill in your organization details:
   - Company Name
   - Email Address
   - Organization Type (Hosting, Bank, Hospital, etc.)
   - Server Type (Direct Linux, cPanel, Plesk, etc.)
3. Click **"Download WAF & Get API Key"**
4. Check your email for download link and API credentials

### Step 2: Extract Files

```bash
# Extract the zip file
unzip smv-security-waf-v1.0.0.zip

# Navigate to directory
cd smv-security-waf

# Make install script executable
chmod +x install.php
```

### Step 3: Run Installer

```bash
# Run the automated installer
php install.php
```

**Installer will:**
✓ Check system requirements
✓ Create required directories
✓ Connect to MySQL
✓ Create database and tables
✓ Generate API credentials
✓ Create configuration file
✓ Setup firewall rules

### Step 4: Configure Cron Job

Enable threat detection (runs every 5 minutes):

```bash
# Edit crontab
crontab -e

# Add this line:
*/5 * * * * php /path/to/smv-security-waf/daemon.php >> /path/to/smv-security-waf/logs/daemon.log 2>&1
```

### Step 5: Verify Installation

```bash
# Check daemon execution
tail -f logs/daemon.log

# Check threats detected
tail -f logs/threats.log

# Verify database
mysql smv_waf_local -e "SHOW TABLES;"
```

---

## Configuration

### API Credentials Setup

After installation, your API credentials are in `.api-credentials.json`:

```json
{
  "api_key": "smv_waf_xxxxxxxxxxxxxxxxxxxxxxxx",
  "api_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "generated_at": "2026-02-09 12:00:00"
}
```

These are automatically configured in `config.php`.

### Basic Configuration

Edit `config.php` to customize:

```php
// Enable/disable WAF
define('WAF_ENABLED', true);

// Threat detection
define('THREAT_DETECTION_ENABLED', true);
define('AUTO_BLOCK_ENABLED', true);

// Daemon interval (minutes)
define('DAEMON_INTERVAL', 5);

// Control Center URL
define('CONTROL_CENTER_URL', 'https://threatresponder.scolemax.co.ke');

// Log retention (days)
define('THREAT_RETENTION_DAYS', 30);

// Block retention (days)
define('BLOCK_RETENTION_DAYS', 7);
```

### Firewall Rule Blocking Methods

By default, `.htaccess` blocking is enabled. Edit `config.php`:

```php
define('BLOCKING_METHODS', [
    'htaccess' => true,      // Apache .htaccess rules
    'nginx_rules' => false,  // Nginx configuration
    'iptables' => false,     // Linux kernel-level (requires root)
]);
```

---

## Monitoring

### Check WAF Status

```bash
# View recent threats
tail -50 logs/threats.log

# Check daemon execution
tail -20 logs/daemon.log

# View all logs
tail -100 logs/waf.log
```

### Database Queries

```bash
# Total threats detected (24 hours)
mysql smv_waf_local -e "SELECT COUNT(*) FROM local_threats WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 1 DAY);"

# Blocked IPs
mysql smv_waf_local -e "SELECT ip_address, reason, blocked_at FROM blocked_ips;"

# Threats by type
mysql smv_waf_local -e "SELECT threat_type, COUNT(*) as count FROM local_threats GROUP BY threat_type;"

# Top attacking IPs
mysql smv_waf_local -e "SELECT source_ip, COUNT(*) as count FROM local_threats GROUP BY source_ip ORDER BY count DESC LIMIT 10;"
```

### Access Control Center Dashboard

1. Login to Control Center: `https://threatresponder.scolemax.co.ke/`
2. View threats from all customers
3. See network-wide threat intelligence
4. Download threat feeds
5. Manage firewall rules

---

## Threat Detection

### What Gets Detected?

The WAF automatically detects:

| Threat Type | Detection Method | Severity |
|---|---|---|
| SQL Injection | Pattern matching & LLAMA | Critical |
| Command Injection | Pattern matching & LLAMA | Critical |
| Cross-Site Scripting (XSS) | Pattern matching | High |
| Path Traversal | Pattern matching | High |
| Brute Force Attacks | Rate analysis | High |
| DDoS Attacks | Request rate analysis | Critical |
| File Upload Attacks | Extension & content analysis | High |
| XXE Attacks | XML pattern analysis | High |
| CSRF Attacks | Token validation | Medium |

### How It Works

**Every 5 Minutes:**
1. Daemon reads server logs (Apache/Nginx access logs)
2. Scans for threat patterns
3. Analyzes matches with LLAMA AI
4. Scores severity (0-10)
5. Blocks critical threats automatically
6. Reports to Control Center
7. Receives updated threat feed

### Auto-Blocking Rules

**Critical Threats** → Automatic IP block
**High Severity + Repeat Offender** → Automatic IP block  
**High Severity** → Rate limiting (100 req/min)
**Medium Severity** → Logged and monitored
**Low Severity** → Logged only

---

## Firewall Rules

### View Active Rules

```bash
# Query database
mysql smv_waf_local -e "SELECT * FROM firewall_rules WHERE is_active = 1;"
```

### Add Custom Rule

Edit `.htaccess.smv` or use Control Center API:

```bash
# Add to .htaccess.smv
echo "Deny from 192.168.1.100 # Manual block" >> .htaccess.smv
```

### Remove Rule

```bash
# Edit file to remove line
nano .htaccess.smv
```

### Reload Rules (Nginx)

```bash
sudo systemctl reload nginx
```

---

## API Integration

### Report Threat to Control Center

```php
$api = new ControlCenterAPI();

$threats = [
    [
        'threat_type' => 'sql_injection',
        'severity' => 'critical',
        'source_ip' => '192.168.1.100',
        'target_path' => '/admin?id=1 OR 1=1'
    ]
];

$result = $api->reportThreats($threats);
```

### Get Threat Feed

```php
$api = new ControlCenterAPI();
$feed = $api->getThreatFeed(limit: 100);

// Feed contains:
// - IP hashes from other servers
// - Threat types
// - Report counts
// - Should_block recommendations
```

### Test Connection

```bash
# PHP CLI
php -r "require 'config.php'; require 'includes/ControlCenterAPI.php'; \$api = new ControlCenterAPI(); print_r(\$api->testConnection());"
```

---

## Troubleshooting

### Daemon Not Running

**Check cron job:**
```bash
crontab -l
```

**Check if PHP is in cron PATH:**
```bash
which php
# Update crontab with full path
crontab -e
*/5 * * * * /usr/bin/php /path/to/daemon.php
```

**Check log for errors:**
```bash
tail -f logs/daemon.log
```

### Database Connection Failed

```bash
# Test MySQL connection
mysql -h localhost -u root -p smv_waf_local

# Check config.php credentials
cat config.php | grep "DB_"
```

### Control Center Not Reachable

```bash
# Test connectivity
curl -v https://threatresponder.scolemax.co.ke

# Check API credentials
cat .api-credentials.json

# Check firewall rules
sudo iptables -L
```

### High Log File Sizes

Logs are automatically rotated when they exceed 10 MB. To manually clean:

```bash
# Delete old logs
find logs -name "*.log.*" -mtime +7 -delete

# Clear threat database (older than 30 days)
mysql smv_waf_local -e "DELETE FROM local_threats WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);"
```

### Low Disk Space

```bash
# Check disk usage
df -h

# Reduce log retention period in config.php
define('THREAT_RETENTION_DAYS', 7);

# Or manually delete old data
rm -f logs/*.gz
```

---

## Uninstalling WAF

To completely remove the WAF:

```bash
# Run uninstall script
chmod +x uninstall.sh
./uninstall.sh
```

**This will:**
- Remove cron job
- Delete .htaccess rules
- Drop database
- Delete configuration files
- Remove all files

**Backup Important Data First!**

---

## Support & Documentation

### Resources

- **Control Center**: https://threatresponder.scolemax.co.ke/
- **Documentation**: https://threatresponder.scolemax.co.ke/docs/
- **Email Support**: support@scolemax.co.ke
- **Admin Email**: admin@scolemax.co.ke

### Reporting Security Issues

Found a vulnerability? Please email: security@scolemax.co.ke

**Do not** disclose publicly without responsible disclosure timeline.

---

## License & Terms

SMV Security WAF is **100% free** for:
- ✅ Organizations in Kenya
- ✅ Personal use
- ✅ Commercial use
- ✅ Educational use
- ✅ Modification and redistribution

**License**: Open Source (MIT License)

---

## FAQ

### Q: Is my data sent to Control Center?

**A:** Only threat data is shared:
- IP addresses (hashed for privacy)
- Threat types detected
- Report counts
- Geographic information

Your actual server logs and detailed payloads stay local.

### Q: Can I use without Control Center?

**A:** Yes! Disable in config.php:
```php
define('CONTROL_CENTER_URL', '');
```

Local threat detection and blocking still works.

### Q: What if Control Center is down?

**A:** WAF continues operating locally:
- Threat detection works
- IP blocking works
- Rules are applied
- Just can't share or receive feeds

### Q: Does it work with CDN/WAF services?

**A:** Yes! Place it on your origin server, after any existing WAF.

### Q: How much CPU does it use?

**A:** Daemon typically uses <1% CPU for 5 minutes every execution.

### Q: Can I run it on Windows?

**A:** Limited support. Some features require Linux:
- iptables blocking (Linux only)
- Full cron support (use Task Scheduler instead)
- Recommended: Linux/Unix servers

---

## Version History

### v1.0.0 (February 2026)
- Initial release
- Core threat detection
- LLAMA integration
- Network intelligence sharing
- Automatic blocking
- API integration

---

## Credits

**SMV Security** - Protecting Kenya's Digital Infrastructure

Built for Kenyan organizations by cybersecurity professionals.

---

**Last Updated:** February 9, 2026

For the latest information, visit: https://threatresponder.scolemax.co.ke/
