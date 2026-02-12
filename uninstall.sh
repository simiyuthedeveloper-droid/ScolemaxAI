#!/bin/bash

# ============================================================
# SMV Security WAF - Uninstall Script
# Safely removes all WAF components from the system
# 
# Usage: chmod +x uninstall.sh && ./uninstall.sh
# ============================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get base directory
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Log file
LOG_FILE="$BASE_DIR/uninstall.log"

# ============================================================
# Helper Functions
# ============================================================

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                        ║${NC}"
    echo -e "${BLUE}║   🛡️  SMV Security WAF - Uninstall Script             ║${NC}"
    echo -e "${BLUE}║                                                        ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
    echo "[SUCCESS] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    echo "[ERROR] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    echo "[WARNING] $1" >> "$LOG_FILE"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
    echo "[INFO] $1" >> "$LOG_FILE"
}

# ============================================================
# Safety Checks
# ============================================================

check_root() {
    # Warn if not root (some operations may fail)
    if [ "$EUID" -ne 0 ]; then
        print_warning "Not running as root - some uninstall steps may fail"
        print_info "To run as root: sudo ./uninstall.sh"
    fi
}

confirm_uninstall() {
    echo ""
    echo -e "${RED}⚠️  WARNING: This will remove all WAF components!${NC}"
    echo ""
    echo "This script will:"
    echo "  • Remove cron job"
    echo "  • Delete .htaccess rules"
    echo "  • Drop database (smv_waf_local)"
    echo "  • Delete configuration files"
    echo "  • Remove all WAF files"
    echo ""
    
    # Backup reminder
    echo -e "${YELLOW}IMPORTANT: Create backups first!${NC}"
    echo ""
    
    read -p "Are you absolutely sure? Type 'yes' to continue: " -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_info "Uninstall cancelled"
        exit 0
    fi
    
    read -p "Type the path to confirm ($BASE_DIR): " -r
    echo
    if [[ ! $REPLY == "$BASE_DIR" ]]; then
        print_error "Path mismatch - uninstall cancelled"
        exit 1
    fi
    
    print_success "Confirmed - proceeding with uninstall"
}

# ============================================================
# Backup Functions
# ============================================================

backup_files() {
    print_section "Creating Backup"
    
    local backup_dir="/tmp/smv-waf-backup-$(date +%Y%m%d-%H%M%S)"
    
    if mkdir -p "$backup_dir"; then
        # Backup important files
        if [ -f "$BASE_DIR/.api-credentials.json" ]; then
            cp "$BASE_DIR/.api-credentials.json" "$backup_dir/" 2>/dev/null
            print_success "Backed up API credentials"
        fi
        
        if [ -f "$BASE_DIR/config.php" ]; then
            cp "$BASE_DIR/config.php" "$backup_dir/" 2>/dev/null
            print_success "Backed up configuration"
        fi
        
        if [ -d "$BASE_DIR/logs" ]; then
            cp -r "$BASE_DIR/logs" "$backup_dir/" 2>/dev/null
            print_success "Backed up logs"
        fi
        
        print_info "Backup location: $backup_dir"
        return 0
    else
        print_warning "Could not create backup directory"
        return 1
    fi
}

# ============================================================
# Removal Functions
# ============================================================

remove_cron_job() {
    print_section "Removing Cron Job"
    
    # Check if cron entry exists
    if crontab -l 2>/dev/null | grep -q "daemon.php"; then
        # Remove the cron entry
        (crontab -l 2>/dev/null | grep -v "daemon.php") | crontab -
        print_success "Removed cron job"
    else
        print_info "Cron job not found (may have been removed already)"
    fi
}

remove_firewall_rules() {
    print_section "Removing Firewall Rules"
    
    # Remove .htaccess rules
    if [ -f "$BASE_DIR/.htaccess.smv" ]; then
        rm -f "$BASE_DIR/.htaccess.smv"
        print_success "Removed .htaccess.smv"
    else
        print_info ".htaccess.smv not found"
    fi
    
    # Remove nginx rules
    if [ -f "$BASE_DIR/nginx-blocked-ips.conf" ]; then
        rm -f "$BASE_DIR/nginx-blocked-ips.conf"
        print_success "Removed nginx-blocked-ips.conf"
    else
        print_info "nginx-blocked-ips.conf not found"
    fi
}

remove_database() {
    print_section "Removing Database"
    
    # Get MySQL credentials from config
    local db_host="localhost"
    local db_user="root"
    local db_pass=""
    
    if [ -f "$BASE_DIR/config.php" ]; then
        db_host=$(grep -oP "define\('DB_HOST',\s*'\K[^']*" "$BASE_DIR/config.php")
        db_user=$(grep -oP "define\('DB_USER',\s*'\K[^']*" "$BASE_DIR/config.php")
        db_pass=$(grep -oP "define\('DB_PASS',\s*'\K[^']*" "$BASE_DIR/config.php")
    fi
    
    # Try to drop database
    if mysql -h "$db_host" -u "$db_user" -p"$db_pass" -e "DROP DATABASE IF EXISTS smv_waf_local;" 2>/dev/null; then
        print_success "Dropped database: smv_waf_local"
    else
        print_warning "Could not drop database (incorrect credentials or MySQL not accessible)"
        print_info "To manually drop: mysql -u root -p -e 'DROP DATABASE smv_waf_local;'"
    fi
}

remove_files() {
    print_section "Removing Files"
    
    # List of directories/files to remove
    local dirs_to_remove=(
        "logs"
        "cache"
        "rules"
        "backups"
        "includes"
        "webui"
    )
    
    local files_to_remove=(
        "config.php"
        ".api-credentials.json"
        "daemon.php"
        "install.php"
        "install.log"
        "waf_config.php"
        "waf_database.sql"
        ".htaccess.smv"
        "nginx-blocked-ips.conf"
    )
    
    # Remove directories
    for dir in "${dirs_to_remove[@]}"; do
        if [ -d "$BASE_DIR/$dir" ]; then
            rm -rf "$BASE_DIR/$dir"
            print_success "Removed directory: $dir/"
        fi
    done
    
    # Remove files
    for file in "${files_to_remove[@]}"; do
        if [ -f "$BASE_DIR/$file" ]; then
            rm -f "$BASE_DIR/$file"
            print_success "Removed file: $file"
        fi
    done
}

cleanup_system() {
    print_section "System Cleanup"
    
    # Remove lock file if exists
    if [ -f "$BASE_DIR/logs/.daemon.lock" ]; then
        rm -f "$BASE_DIR/logs/.daemon.lock"
        print_success "Removed daemon lock file"
    fi
    
    # Clear any remaining empty directories
    find "$BASE_DIR" -type d -empty -delete 2>/dev/null
    print_success "Cleaned up empty directories"
}

# ============================================================
# Final Report
# ============================================================

print_summary() {
    print_section "Uninstall Summary"
    
    echo -e "${GREEN}✓ Uninstall completed successfully!${NC}"
    echo ""
    echo "Removed:"
    echo "  ✓ Cron job (daemon scheduling)"
    echo "  ✓ Firewall rules (.htaccess, nginx)"
    echo "  ✓ Database (smv_waf_local)"
    echo "  ✓ Configuration files"
    echo "  ✓ All WAF files and directories"
    echo ""
    
    echo -e "${YELLOW}Important Notes:${NC}"
    echo "  • Check $LOG_FILE for details"
    echo "  • Backup files are in /tmp/smv-waf-backup-*"
    echo "  • You may want to revert .htaccess modifications manually"
    echo "  • Contact support if you need recovery assistance"
    echo ""
    
    # Check if directory is empty
    if [ -z "$(ls -A "$BASE_DIR")" ]; then
        print_success "Directory is now empty"
        echo ""
        read -p "Remove installation directory? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            cd /
            rm -rf "$BASE_DIR"
            print_success "Removed: $BASE_DIR"
        fi
    fi
}

# ============================================================
# Main Execution
# ============================================================

main() {
    # Initialize log
    echo "[$(date)] Starting WAF Uninstall" > "$LOG_FILE"
    
    # Print header
    print_header
    
    # Check root
    check_root
    
    # Confirm uninstall
    confirm_uninstall
    
    # Backup important files
    backup_files
    
    # Remove components
    remove_cron_job
    remove_firewall_rules
    remove_database
    remove_files
    cleanup_system
    
    # Print summary
    print_summary
    
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo "Uninstall log: $LOG_FILE"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
}

# Run main function
main

exit 0
