#!/bin/bash
#===============================================================================
#
#  Splunkbase Add-on Installer
#  Installs Splunk add-ons directly from Splunkbase using Splunk's REST API
#
#  Usage:
#    ./download_addons.sh -u splunkbase@email.com -p sbpass -a admin -s adminpass
#    ./download_addons.sh -u splunkbase@email.com  # prompts for passwords
#
#  Requirements:
#    - curl
#    - A running Splunk Enterprise instance
#    - A valid Splunk.com account (free to create)
#
#  This script uses Splunk's built-in ability to install apps from Splunkbase,
#  which handles the SAML authentication automatically.
#
#  Samuel Brucker 2024-2026
#
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_URI="https://localhost:8089"

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC=''
fi

# Splunkbase app definitions: "APP_ID|APP_NAME|DESCRIPTION"
# APP_NAME is the technical name used by Splunk
ADDONS=(
    # Network/Firewall
    "2757|Splunk_TA_paloalto|Splunk Add-on for Palo Alto Networks"
    "4388|Splunk_TA_cisco_secure_firewall|Cisco Secure Firewall (FTD)"
    "5466|TA-zeek|Splunk Add-on for Zeek"
    "2760|TA-suricata|Splunk Add-on for Suricata"

    # Windows
    "742|Splunk_TA_windows|Splunk Add-on for Windows"
    "5709|Splunk_TA_microsoft_sysmon|Splunk Add-on for Sysmon"
    "3208|Splunk_TA_microsoft-dns|Splunk Add-on for Microsoft Windows DNS"

    # Linux/Unix
    "833|Splunk_TA_nix|Splunk Add-on for Unix and Linux"

    # Security Tools
    "4494|SplunkAppForWazuh|Wazuh App for Splunk"

    # Web/Infrastructure
    "3186|Splunk_TA_apache|Splunk Add-on for Apache Web Server"
    "3258|Splunk_TA_nginx|Splunk Add-on for NGINX"
    "2891|TA-haproxy|Splunk Add-on for HAProxy"
    "5765|Splunk_TA_docker|Splunk Add-on for Docker"
    "1917|splunk_app_for_tomcat|Splunk Add-on for Tomcat"
    "4679|Splunk_TA_postgresql|Splunk Add-on for PostgreSQL"
    "2818|Splunk_TA_mysql|Splunk Add-on for MySQL"

    # Foundation
    "1621|Splunk_SA_CIM|Splunk Common Information Model (CIM)"
)

cleanup() {
    stty echo 2>/dev/null || true
}
trap cleanup EXIT INT TERM

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Installs Splunk add-ons from Splunkbase using Splunk's REST API.
All credentials will be prompted if not provided via options.

OPTIONS:
  -u    Splunkbase username (email) - your Splunk.com account
  -p    Splunkbase password
  -a    Splunk admin username (default: admin)
  -s    Splunk admin password
  -H    Splunk host URI (default: https://localhost:8089)
  -l    List add-ons that will be installed
  -h    Show this help

EXAMPLES:
  $0                                    # prompts for all credentials
  $0 -u myemail@example.com             # prompts for passwords only
  $0 -u myemail@example.com -p mypass -s adminpass
  $0 -l                                 # list add-ons without installing

EOF
    exit 1
}

list_addons() {
    echo -e "${CYAN}Add-ons to be installed:${NC}"
    echo ""
    printf "%-8s %-30s %s\n" "APP_ID" "APP_NAME" "DESCRIPTION"
    echo "--------------------------------------------------------------------------------"
    for addon in "${ADDONS[@]}"; do
        IFS='|' read -r app_id app_name description <<< "$addon"
        printf "%-8s %-30s %s\n" "$app_id" "$app_name" "$description"
    done
    echo ""
    echo "Total: ${#ADDONS[@]} add-ons"
    exit 0
}

# Parse arguments
SB_USERNAME=""
SB_PASSWORD=""
SPLUNK_ADMIN="admin"
SPLUNK_PASSWORD=""

while getopts "u:p:a:s:H:lh" opt; do
    case $opt in
        u) SB_USERNAME="$OPTARG" ;;
        p) SB_PASSWORD="$OPTARG" ;;
        a) SPLUNK_ADMIN="$OPTARG" ;;
        s) SPLUNK_PASSWORD="$OPTARG" ;;
        H) SPLUNK_URI="$OPTARG" ;;
        l) list_addons ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Prompt for any missing credentials
if [[ -z "$SB_USERNAME" ]]; then
    echo -n "Enter Splunkbase username (email): "
    read -r SB_USERNAME
    if [[ -z "$SB_USERNAME" ]]; then
        echo -e "${RED}Error: Splunkbase username is required${NC}"
        exit 1
    fi
fi

if [[ -z "$SB_PASSWORD" ]]; then
    echo -n "Enter Splunkbase password for $SB_USERNAME: "
    stty -echo
    read -r SB_PASSWORD
    stty echo
    echo ""
fi

if [[ -z "$SPLUNK_PASSWORD" ]]; then
    echo -n "Enter Splunk admin password for $SPLUNK_ADMIN: "
    stty -echo
    read -r SPLUNK_PASSWORD
    stty echo
    echo ""
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Splunkbase Add-on Installer${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Splunkbase User:${NC}  $SB_USERNAME"
echo -e "${BLUE}Splunk URI:${NC}       $SPLUNK_URI"
echo -e "${BLUE}Splunk Admin:${NC}     $SPLUNK_ADMIN"
echo -e "${BLUE}Add-ons:${NC}          ${#ADDONS[@]}"
echo ""

# Verify Splunk is accessible
echo -e "${YELLOW}[1/2] Verifying Splunk connection...${NC}"

VERIFY=$(curl -s -k -u "${SPLUNK_ADMIN}:${SPLUNK_PASSWORD}" \
    "${SPLUNK_URI}/services/server/info?output_mode=json" 2>/dev/null)

if ! echo "$VERIFY" | grep -q '"version"'; then
    echo -e "${RED}Cannot connect to Splunk at $SPLUNK_URI${NC}"
    echo "Make sure Splunk is running and credentials are correct."
    exit 1
fi

SPLUNK_VERSION=$(echo "$VERIFY" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1)
echo -e "${GREEN}[✓] Connected to Splunk $SPLUNK_VERSION${NC}"
echo ""

# Step 2: Install add-ons
echo -e "${YELLOW}[2/2] Installing add-ons from Splunkbase...${NC}"
echo ""

SUCCESS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_ADDONS=()

for addon in "${ADDONS[@]}"; do
    IFS='|' read -r app_id app_name description <<< "$addon"

    printf "  %-50s " "$description..."

    # Check if already installed
    CHECK=$(curl -s -k -u "${SPLUNK_ADMIN}:${SPLUNK_PASSWORD}" \
        "${SPLUNK_URI}/services/apps/local/${app_name}?output_mode=json" 2>/dev/null)

    if echo "$CHECK" | grep -q '"name"'; then
        echo -e "${BLUE}SKIP${NC} (already installed)"
        ((SKIP_COUNT++))
        continue
    fi

    # Install from Splunkbase using the REST API
    # The 'auth' parameter takes splunkbase_user:splunkbase_password
    INSTALL_RESPONSE=$(curl -s -k -w "\n%{http_code}" \
        -u "${SPLUNK_ADMIN}:${SPLUNK_PASSWORD}" \
        -X POST \
        -d "name=${app_name}" \
        -d "auth=${SB_USERNAME}:${SB_PASSWORD}" \
        -d "update=true" \
        "${SPLUNK_URI}/services/apps/local" 2>/dev/null)

    HTTP_CODE=$(echo "$INSTALL_RESPONSE" | tail -1)
    RESPONSE_BODY=$(echo "$INSTALL_RESPONSE" | sed '$d')

    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "201" ]]; then
        echo -e "${GREEN}OK${NC}"
        ((SUCCESS_COUNT++))
    elif echo "$RESPONSE_BODY" | grep -qi "already exists"; then
        echo -e "${BLUE}SKIP${NC} (already installed)"
        ((SKIP_COUNT++))
    else
        # Extract error message if possible
        ERROR_MSG=$(echo "$RESPONSE_BODY" | grep -oP '"message"\s*:\s*"\K[^"]+' | head -1)
        if [[ -z "$ERROR_MSG" ]]; then
            ERROR_MSG="HTTP $HTTP_CODE"
        fi
        echo -e "${RED}FAILED${NC} ($ERROR_MSG)"
        FAILED_ADDONS+=("$app_id|$description")
        ((FAIL_COUNT++))
    fi

    # Small delay to avoid overwhelming the API
    sleep 1
done

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Installed:${NC} $SUCCESS_COUNT"
echo -e "${BLUE}Skipped:${NC}   $SKIP_COUNT (already installed)"
echo -e "${RED}Failed:${NC}    $FAIL_COUNT"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

if [[ ${#FAILED_ADDONS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Failed add-ons (install manually from Splunkbase):${NC}"
    for failed in "${FAILED_ADDONS[@]}"; do
        IFS='|' read -r app_id description <<< "$failed"
        echo "  - $description: https://splunkbase.splunk.com/app/$app_id"
    done
fi

if [[ $SUCCESS_COUNT -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Restart Splunk to load new add-ons:${NC}"
    echo "  sudo $SPLUNK_HOME/bin/splunk restart"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
