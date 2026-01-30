#!/bin/bash
# Dry-run test harness for Wazuh scripts
# Validates syntax and structure without requiring Wazuh installation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$SCRIPT_DIR/.."

PASS=0
FAIL=0
TESTS=0

assert() {
    local desc="$1" cond="$2"
    TESTS=$((TESTS + 1))
    if eval "$cond"; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=========================================="
echo "Wazuh Scripts - Dry Run Tests"
echo "=========================================="
echo ""

# --- Test 1: Syntax validation for all Wazuh bash scripts ---
echo "Test 1: Bash syntax validation"

WAZUH_SCRIPTS=(
    "linux/securityInfrastructure/Wazuh/Server/OL9-wazuhInstall.sh"
    "linux/securityInfrastructure/Wazuh/Configs/setGroupConfigs.sh"
    "linux/securityInfrastructure/Wazuh/fortressInstall.sh"
    "agentInstallations/wazuh/linuxWazuhAgentSetup.sh"
)

for script in "${WAZUH_SCRIPTS[@]}"; do
    full_path="$REPO_DIR/$script"
    name=$(basename "$script")
    if [[ -f "$full_path" ]]; then
        assert "$name parses without syntax errors" \
            "bash -n '$full_path' 2>/dev/null"
    else
        echo "  SKIP: $name (not found)"
    fi
done

# --- Test 2: Shellcheck ---
echo ""
echo "Test 2: Shellcheck analysis"
if command -v shellcheck &>/dev/null; then
    for script in "${WAZUH_SCRIPTS[@]}"; do
        full_path="$REPO_DIR/$script"
        name=$(basename "$script")
        if [[ -f "$full_path" ]]; then
            errors=$(shellcheck -s bash -S error "$full_path" 2>&1 || true)
            assert "$name has no shellcheck errors (severity: error)" \
                '[[ -z "$errors" ]]'
        fi
    done
else
    echo "  SKIP: shellcheck not installed"
fi

# --- Test 3: Required structure checks ---
echo ""
echo "Test 3: Script structure validation"

for script in "${WAZUH_SCRIPTS[@]}"; do
    full_path="$REPO_DIR/$script"
    name=$(basename "$script")
    [[ ! -f "$full_path" ]] && continue

    assert "$name has bash shebang" \
        'head -1 "$full_path" | grep -q "^#!/bin/bash"'

    assert "$name is executable" \
        '[[ -x "$full_path" ]]'
done

# --- Test 4: fortressInstall.sh specific checks ---
echo ""
echo "Test 4: fortressInstall.sh structure"

FORTRESS="$REPO_DIR/linux/securityInfrastructure/Wazuh/fortressInstall.sh"
if [[ -f "$FORTRESS" ]]; then
    assert "References SOCFortress rules repo" \
        'grep -q "socfortress" "$FORTRESS" || grep -q "SOCFortress" "$FORTRESS"'

    assert "Defines Wazuh directories" \
        'grep -q "WAZUH_RULES_DIR\|rules_dir\|RULES_DIR" "$FORTRESS"'

    assert "Copies rules files" \
        'grep -q "\.xml" "$FORTRESS"'

    assert "Sets file permissions" \
        'grep -q "chmod" "$FORTRESS"'

    assert "No local keyword outside functions" \
        '! grep -n "^[[:space:]]*local " "$FORTRESS" | grep -v "^[0-9]*:[[:space:]]*#" | while read -r line; do echo "$line"; done | head -1 | grep -q "."'
else
    echo "  SKIP: fortressInstall.sh not found"
fi

# --- Test 5: OL9-wazuhInstall.sh specific checks ---
echo ""
echo "Test 5: OL9-wazuhInstall.sh structure"

OL9="$REPO_DIR/linux/securityInfrastructure/Wazuh/Server/OL9-wazuhInstall.sh"
if [[ -f "$OL9" ]]; then
    assert "References Wazuh package/repo" \
        'grep -qi "wazuh" "$OL9"'

    assert "Handles indexer or dashboard component" \
        'grep -qi "indexer\|dashboard\|manager" "$OL9"'

    assert "Configures systemd or service" \
        'grep -qi "systemctl\|service" "$OL9"'
else
    echo "  SKIP: OL9-wazuhInstall.sh not found"
fi

# --- Test 6: setGroupConfigs.sh specific checks ---
echo ""
echo "Test 6: setGroupConfigs.sh structure"

SETGROUP="$REPO_DIR/linux/securityInfrastructure/Wazuh/Configs/setGroupConfigs.sh"
if [[ -f "$SETGROUP" ]]; then
    assert "References agent group config" \
        'grep -qi "group\|agent\|shared" "$SETGROUP"'

    assert "Copies or writes config files" \
        'grep -q "cp \|cat \|tee \|>" "$SETGROUP"'
else
    echo "  SKIP: setGroupConfigs.sh not found"
fi

# --- Test 7: Agent setup script checks ---
echo ""
echo "Test 7: linuxWazuhAgentSetup.sh structure"

AGENT="$REPO_DIR/agentInstallations/wazuh/linuxWazuhAgentSetup.sh"
if [[ -f "$AGENT" ]]; then
    assert "Installs wazuh-agent package" \
        'grep -qi "wazuh-agent\|WAZUH_AGENT" "$AGENT"'

    assert "Configures manager address" \
        'grep -qi "WAZUH_MANAGER\|manager_ip\|MANAGER_IP" "$AGENT"'

    assert "Handles multiple distros" \
        'grep -qi "apt\|yum\|dnf\|zypper" "$AGENT"'
else
    echo "  SKIP: linuxWazuhAgentSetup.sh not found"
fi

# --- Test 8: SaltyBoxes copies match originals ---
echo ""
echo "Test 8: SaltyBoxes/Windows copies consistency"

assert "SaltyBoxes linuxWazuhAgentSetup.sh matches original" \
    'diff -q "$REPO_DIR/agentInstallations/wazuh/linuxWazuhAgentSetup.sh" "$REPO_DIR/SaltyBoxes/CustomScripts/SecurityInfrastructure/linuxWazuhAgentSetup.sh" &>/dev/null'

assert "SaltyBoxes windowsWazuhAgentSetup.ps1 matches original" \
    'diff -q "$REPO_DIR/agentInstallations/wazuh/windowsWazuhAgentSetup.ps1" "$REPO_DIR/SaltyBoxes/CustomScripts/Windows/windowsWazuhAgentSetup.ps1" &>/dev/null'

assert "Windows/ windowsWazuhAgentSetup.ps1 matches original" \
    'diff -q "$REPO_DIR/agentInstallations/wazuh/windowsWazuhAgentSetup.ps1" "$REPO_DIR/Windows/windowsWazuhAgentSetup.ps1" &>/dev/null'

# --- Test 9: PowerShell script structure ---
echo ""
echo "Test 9: windowsWazuhAgentSetup.ps1 structure"

PS_SCRIPT="$REPO_DIR/agentInstallations/wazuh/windowsWazuhAgentSetup.ps1"
if [[ -f "$PS_SCRIPT" ]]; then
    assert "Has CmdletBinding attribute" \
        'grep -q "\[CmdletBinding()\]" "$PS_SCRIPT"'

    assert "Defines ManagerIP parameter" \
        'grep -q "ManagerIP" "$PS_SCRIPT"'

    assert "Defines AgentGroup parameter" \
        'grep -q "AgentGroup" "$PS_SCRIPT"'

    assert "Downloads Wazuh MSI" \
        'grep -q "Invoke-WebRequest.*wazuh" "$PS_SCRIPT" || grep -q "WazuhMsiUrl" "$PS_SCRIPT"'

    assert "Installs via msiexec" \
        'grep -q "msiexec" "$PS_SCRIPT"'

    assert "Configures firewall rules" \
        'grep -q "New-NetFirewallRule" "$PS_SCRIPT"'

    assert "Starts WazuhSvc service" \
        'grep -q "WazuhSvc" "$PS_SCRIPT"'

    assert "Has error handling (try/catch)" \
        'grep -q "try" "$PS_SCRIPT" && grep -q "catch" "$PS_SCRIPT"'

    assert "Uses Wazuh version 4.14.2" \
        'grep -q "4\.14\.2" "$PS_SCRIPT"'

    assert "Requires admin (#Requires -RunAsAdministrator)" \
        'grep -q "#Requires -RunAsAdministrator" "$PS_SCRIPT"'

    assert "No paired braces mismatch" \
        '[[ $(grep -o "{" "$PS_SCRIPT" | wc -l) -eq $(grep -o "}" "$PS_SCRIPT" | wc -l) ]]'

    assert "No paired parens mismatch" \
        '[[ $(grep -o "(" "$PS_SCRIPT" | wc -l) -eq $(grep -o ")" "$PS_SCRIPT" | wc -l) ]]'
else
    echo "  SKIP: windowsWazuhAgentSetup.ps1 not found"
fi

# --- Test 10: Wazuh XML config validation ---
echo ""
echo "Test 10: Wazuh config file validation"

CONFIGS_DIR="$REPO_DIR/linux/securityInfrastructure/Wazuh/Configs"

if command -v xmllint &>/dev/null; then
    assert "ossec.conf is valid XML" \
        'xmllint --noout "$CONFIGS_DIR/ossec.conf" 2>/dev/null'

    assert "local_rules.xml is valid XML" \
        'xmllint --noout "$CONFIGS_DIR/local_rules.xml" 2>/dev/null'

    # Wazuh decoder files have multiple root elements (no single root wrapper).
    # Validate by wrapping in a temporary root element.
    assert "local_decoder.xml is valid Wazuh XML (multi-root)" \
        '{ echo "<root>"; cat "$CONFIGS_DIR/local_decoder.xml"; echo "</root>"; } | xmllint --noout - 2>/dev/null'

    assert "linux-default.conf is valid XML" \
        'xmllint --noout "$CONFIGS_DIR/linux-default.conf" 2>/dev/null'

    assert "windows-default.conf is valid XML" \
        'xmllint --noout "$CONFIGS_DIR/windows-default.conf" 2>/dev/null'
else
    echo "  SKIP: xmllint not installed"
fi

# --- Test 11: Wazuh JSON template validation ---
echo ""
echo "Test 11: Wazuh template JSON validation"

TEMPLATE="$REPO_DIR/linux/securityInfrastructure/Wazuh/Server/wazuh-template.json"
if command -v jq &>/dev/null && [[ -f "$TEMPLATE" ]]; then
    assert "wazuh-template.json is valid JSON" \
        'jq empty "$TEMPLATE" 2>/dev/null'

    assert "Template has index_patterns or template field" \
        'jq -e ".index_patterns // .template" "$TEMPLATE" &>/dev/null'
else
    echo "  SKIP: jq not installed or template not found"
fi

# --- Test 12: Config content validation ---
echo ""
echo "Test 12: Wazuh config content checks"

OSSEC="$CONFIGS_DIR/ossec.conf"
if [[ -f "$OSSEC" ]]; then
    assert "ossec.conf has <ossec_config> root" \
        'grep -q "<ossec_config>" "$OSSEC"'

    assert "ossec.conf defines syscheck (FIM)" \
        'grep -q "<syscheck>" "$OSSEC"'

    assert "ossec.conf defines log analysis" \
        'grep -q "<localfile>" "$OSSEC"'
fi

LINUX_DEFAULT="$CONFIGS_DIR/linux-default.conf"
if [[ -f "$LINUX_DEFAULT" ]]; then
    assert "linux-default.conf has agent config" \
        'grep -q "<agent_config>" "$LINUX_DEFAULT" || grep -q "<syscheck>" "$LINUX_DEFAULT"'
fi

WINDOWS_DEFAULT="$CONFIGS_DIR/windows-default.conf"
if [[ -f "$WINDOWS_DEFAULT" ]]; then
    assert "windows-default.conf has agent config" \
        'grep -q "<agent_config>" "$WINDOWS_DEFAULT" || grep -q "<syscheck>" "$WINDOWS_DEFAULT"'
fi

# --- Summary ---
echo ""
echo "=========================================="
echo "Results: $PASS/$TESTS passed, $FAIL failed"
echo "=========================================="
exit $FAIL
