#!/bin/bash
#
# This script combines deep system enumeration with an anonymous FTP upload test.
#
# 1. It performs a comprehensive, distro-agnostic enumeration of the system.
# 2. It saves the report to /tmp/<hostname>-deep-enumeration.txt.
# 3. It then attempts to anonymously upload that report to 172.20.240.104.
#
# MUST BE RUN AS ROOT OR WITH SUDO for complete information.

# Exit on error, unset variable, or pipe failure
set -euo pipefail

# --- Configuration ---
HOST_NAME=$(hostname)
OUTPUT_FILE="/tmp/${HOST_NAME}-deep-enumeration.txt" # File to create
LOCAL_FILE="$OUTPUT_FILE"                            # File to upload

FTP_SERVER="172.20.240.104"
FTP_USER="anonymous"
FTP_PASS="guest@example.com"
REMOTE_FILE_NAME="${HOST_NAME}-upload-test.txt"

# --- Helper Functions ---

# Function to check if a command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Function to write a section header to the report
report_header() {
  local title="$1"
  echo "" | tee -a "$OUTPUT_FILE"
  echo "====================================================================" | tee -a "$OUTPUT_FILE"
  echo "=== $title" | tee -a "$OUTPUT_FILE"
  echo "====================================================================" | tee -a "$OUTPUT_FILE"
}

# Function to run a command and append its output to the report
report_cmd() {
  local cmd_string="$1"
  echo "" | tee -a "$OUTPUT_FILE"
  echo "---[ Executing: $cmd_string ]---" | tee -a "$OUTPUT_FILE"
  echo "" | tee -a "$OUTPUT_FILE"
  
  # Execute the command and append both stdout and stderr to the file
  # We add '|| true' to prevent 'set -e' from exiting on non-zero exit codes,
  # as many enumeration commands fail gracefully (e.g., file not found).
  eval "$cmd_string" >> "$OUTPUT_FILE" 2>&1 || true
  
  # Add a small note to the console that the command ran
  echo "  ... finished $cmd_string"
}

# --- Main Functions ---

run_enumeration() {
  # Initialize the report file
  echo "System Enumeration Report for $HOST_NAME" > "$OUTPUT_FILE"
  echo "Generated: $(date)" >> "$OUTPUT_FILE"
  
  echo "Starting deep enumeration. Report will be saved to $OUTPUT_FILE"

  # --- System Basics ---
  report_header "SYSTEM BASICS"
  report_cmd "hostname -f"
  if command_exists hostnamectl; then report_cmd "hostnamectl"; fi
  report_cmd "uname -a"
  if command_exists lsb_release; then report_cmd "lsb_release -a"; fi
  report_cmd "cat /etc/os-release"
  report_cmd "uptime"
  report_cmd "w"
  report_cmd "env"

  # --- Hardware Information ---
  report_header "HARDWARE INFORMATION"
  if command_exists lscpu; then report_cmd "lscpu"; fi
  if command_exists free; then report_cmd "free -h"; fi
  if command_exists df; then report_cmd "df -h"; fi
  if command_exists lsblk; then report_cmd "lsblk -a -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"; fi
  if command_exists lspci; then report_cmd "lspci -vnn"; fi
  if command_exists lsusb; then report_cmd "lsusb -v"; fi
  if command_exists dmidecode; then report_cmd "dmidecode"; fi

  # --- Networking Configuration ---
  report_header "NETWORKING CONFIGURATION"
  if command_exists ip; then
    report_cmd "ip addr show"
    report_cmd "ip route show"
    report_cmd "ip neigh show"
  elif command_exists ifconfig; then
    report_cmd "ifconfig -a"
  fi
  if command_exists arp; then report_cmd "arp -a"; fi
  if command_exists ss; then
    report_cmd "ss -ltunp"
  elif command_exists netstat; then
    report_cmd "netstat -ltunp"
  fi
  report_cmd "cat /etc/hosts"
  report_cmd "cat /etc/resolv.conf"

  # --- Firewall ---
  report_header "FIREWALL RULES"
  if command_exists ufw; then
    report_cmd "ufw status verbose"
  elif command_exists firewall-cmd; then
    report_cmd "firewall-cmd --list-all"
  elif command_exists iptables; then
    report_cmd "iptables -L -n -v"
    report_cmd "iptables -t nat -L -n -v"
  fi

  # --- Users and Groups ---
  report_header "USERS AND GROUPS"
  report_cmd "cat /etc/passwd"
  report_cmd "cat /etc/group"
  report_cmd "awk -F: '{print \$1 \" has password? \" (\$2 != \"\" && \$2 != \"!\" && \$2 != \"*\" ? \"Yes\" : \"No\")}' /etc/shadow"
  report_cmd "getent passwd"
  report_cmd "getent group"
  report_cmd "grep -vE '^#|^$' /etc/sudoers /etc/sudoers.d/*"
  if command_exists sudo; then report_cmd "sudo -l"; fi
  if command_exists lastlog; then report_cmd "lastlog"; fi

  # --- Processes and Services ---
  report_header "PROCESSES AND SERVICES"
  report_cmd "ps aux"
  report_cmd "ps -e -o pid,ppid,user,%mem,%cpu,cmd --forest"
  if command_exists lsmod; then report_cmd "lsmod"; fi
  if command_exists systemctl; then
    report_cmd "systemctl list-units --type=service --all"
    report_cmd "systemctl list-timers --all"
  elif command_exists service; then
    report_cmd "service --status-all"
  fi

  # --- Log Files ---
  report_header "LOG FILES (Recent)"
  if command_exists journalctl; then
    report_cmd "journalctl -n 50 --no-pager"
  fi
  report_cmd "tail -n 50 /var/log/auth.log 2>/dev/null || tail -n 50 /var/log/secure 2>/dev/null"
  report_cmd "tail -n 50 /var/log/syslog 2>/dev/null || tail -n 50 /var/log/messages 2>/dev/null"

  # --- File System & Persistence ---
  report_header "FILE SYSTEM & PERSISTENCE"
  report_cmd "find /bin /usr/bin /usr/local/bin /sbin /usr/sbin /etc -perm -4000 -type f"
  report_cmd "find /home -type f -name '.*'"
  report_cmd "du -sh /var /home /etc 2>/dev/null"
  report_cmd "cat /etc/crontab"
  report_cmd "ls -l /etc/cron.d/"
  report_cmd "ls -l /var/spool/cron/"
  report_cmd "crontab -l 2>/dev/null || echo 'No user crontab found for root'"

  # --- Installed Software ---
  report_header "INSTALLED SOFTWARE"
  if command_exists apt; then
    report_cmd "apt list --installed"
  elif command_exists dnf; then
    report_cmd "dnf list installed"
  elif command_exists yum; then
    report_cmd "yum list installed"
  elif command_exists dpkg; then
    report_cmd "dpkg -l"
  elif command_exists rpm; then
    report_cmd "rpm -qa"
  fi
  if command_exists snap; then report_cmd "snap list"; fi
  if command_exists flatpak; then report_cmd "flatpak list"; fi
  
  # --- Common Configurations ---
  report_header "COMMON CONFIGURATIONS"
  report_cmd "cat /etc/fstab"
  report_cmd "grep -vE '^#|^$' /etc/ssh/sshd_config"

  # --- Security Tools ---
  report_header "SECURITY TOOL CHECKS"
  if command_exists chkrootkit; then
    report_cmd "chkrootkit"
  else
    report_cmd "echo 'chkrootkit not found'"
  fi
  if command_exists rkhunter; then
    report_cmd "rkhunter --check --skip-keypress"
  else
    report_cmd "echo 'rkhunter not found'"
  fi

  echo ""
  echo "---[ Enumeration Complete ]---"
  echo "Report saved to $OUTPUT_FILE"
}

run_ftp_upload() {
  echo ""
  echo "===================================================================="
  echo "=== ATTEMPTING ANONYMOUS FTP UPLOAD"
  echo "===================================================================="
  echo "Attempting anonymous FTP upload to $FTP_SERVER..."
  echo "  - User: $FTP_USER"
  echo "  - File: $LOCAL_FILE"
  echo ""

  # We use 'curl' as it's a powerful, non-interactive tool for this.
  # -v : Verbose, so you can see the server's response
  # -T : Upload the specified local file
  # --user : The username and password
  # We add '|| true' at the end so that 'set -e' doesn't exit if the
  # upload fails (which is the desired, secure outcome).
  curl -v -T "$LOCAL_FILE" "ftp://${FTP_SERVER}/${REMOTE_FILE_NAME}" --user "${FTP_USER}:${FTP_PASS}" || true

  echo ""
  echo "---[ FTP Test Complete ]---"
  echo "Review the output above:"
  echo "- If you see '226 Transfer complete', the upload SUCCEEDED. (This is BAD)"
  echo "- If you see '530 Login incorrect' or '550 Permission denied', the upload FAILED. (This is GOOD)"
}

# --- Main Execution ---
main() {
  # Check for root privileges
  if [ "$EUID" -ne 0 ]; then
    echo "Warning: Running as non-root. Some information may be incomplete."
    echo "It is highly recommended to run this script with sudo or as root."
    sleep 2
  fi
  
  run_enumeration
  run_ftp_upload
  
  echo ""
  echo "===================================================================="
  echo "=== SCRIPT FINISHED ==="
  echo "===================================================================="
}

# Run the main function
main
