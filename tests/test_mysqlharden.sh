#!/bin/bash
# Dry-run test harness for mysqlharden.sh
# Mocks mysql command and config files to verify script logic
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

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
echo "MySQL Hardening Script - Dry Run Tests"
echo "=========================================="
echo ""

# --- Setup mock mysql binary ---
MOCK_BIN="$WORK_DIR/bin"
mkdir -p "$MOCK_BIN"

# Track all queries executed
QUERY_LOG="$WORK_DIR/queries.log"
touch "$QUERY_LOG"

cat > "$MOCK_BIN/mysql" << 'MOCKEOF'
#!/bin/bash
# Mock mysql that logs queries and returns sensible defaults
QUERY_LOG="${MOCK_QUERY_LOG:-/dev/null}"

for arg in "$@"; do
    if [[ "$arg" == "-e" ]]; then
        shift_next=true
        continue
    fi
    if [[ "${shift_next:-}" == "true" ]]; then
        echo "$arg" >> "$QUERY_LOG"
        shift_next=false

        # Return values based on query
        case "$arg" in
            "SELECT 1")
                echo "1"
                ;;
            *"COUNT(*) FROM mysql.user WHERE User=''"*)
                echo "2"
                ;;
            *"COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test'"*)
                echo "1"
                ;;
            *"COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN"*)
                echo "1"
                ;;
            *"CONCAT(User"*"File_priv='Y'"*)
                echo "testuser@%"
                ;;
            *)
                ;;
        esac
    fi
done
MOCKEOF
chmod +x "$MOCK_BIN/mysql"

# --- Setup mock config file ---
MOCK_CONF="$WORK_DIR/my.cnf"
cat > "$MOCK_CONF" << 'EOF'
[mysqld]
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
EOF

MOCK_MY_CNF="$WORK_DIR/.my.cnf"
cat > "$MOCK_MY_CNF" << 'EOF'
[client]
user=root
password=testpass
EOF

# --- Test 1: Script syntax check ---
echo "Test 1: Bash syntax validation"
assert "mysqlharden.sh parses without errors" \
    "bash -n '$SCRIPT_DIR/../linux/postHardenTools/misc/MySQL/mysqlharden.sh'"

# --- Test 2: Help flag ---
echo ""
echo "Test 2: Help output"
help_output=$(bash "$SCRIPT_DIR/../linux/postHardenTools/misc/MySQL/mysqlharden.sh" -h 2>&1 || true)
assert "Help shows usage info" '[[ "$help_output" == *"Usage"* ]]'
assert "Help shows options" '[[ "$help_output" == *"Options"* ]]'

# --- Test 3: Run with mocked mysql and faked root ---
echo ""
echo "Test 3: Mock execution (simulated root)"

# We can't easily fake EUID, so we'll source parts of the script logic manually.
# Instead, let's test that the mock mysql captures the right queries.
export PATH="$MOCK_BIN:$PATH"
export MOCK_QUERY_LOG="$QUERY_LOG"
export HOME="$WORK_DIR"

# Create a modified version that skips root check and config file ops
MODIFIED_SCRIPT="$WORK_DIR/mysqlharden_test.sh"
sed 's/if \[\[ \$EUID -ne 0 \]\]/if false/' \
    "$SCRIPT_DIR/../linux/postHardenTools/misc/MySQL/mysqlharden.sh" > "$MODIFIED_SCRIPT"

# Replace config file search with our mock
sed -i "s|for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf|for conf in $MOCK_CONF|" "$MODIFIED_SCRIPT"
# Skip chown (not root)
sed -i 's/chown .*/true/' "$MODIFIED_SCRIPT"

chmod +x "$MODIFIED_SCRIPT"
bash "$MODIFIED_SCRIPT" -u root -p testpass > "$WORK_DIR/output.log" 2>&1 || true

# Verify queries were issued
assert "Anonymous user removal query issued" \
    'grep -q "DELETE FROM mysql.user WHERE User=" "$QUERY_LOG"'

assert "Test database drop query issued" \
    'grep -q "DROP DATABASE IF EXISTS test" "$QUERY_LOG"'

assert "Remote root removal query issued" \
    'grep -q "DELETE FROM mysql.user WHERE User=.root" "$QUERY_LOG"'

assert "local_infile disabled" \
    'grep -q "SET GLOBAL local_infile = 0" "$QUERY_LOG"'

assert "FLUSH PRIVILEGES issued" \
    'grep -q "FLUSH PRIVILEGES" "$QUERY_LOG"'

assert "General log enabled" \
    'grep -q "SET GLOBAL general_log" "$QUERY_LOG"'

# --- Test 4: Config file modifications ---
echo ""
echo "Test 4: Config file hardening"
assert "symbolic-links added to config" \
    'grep -q "symbolic-links=0" "$MOCK_CONF"'

assert "local-infile added to config" \
    'grep -q "local-infile=0" "$MOCK_CONF"'

assert "bind-address added to config" \
    'grep -q "bind-address=127.0.0.1" "$MOCK_CONF"'

assert "Config backup created" \
    'ls "$MOCK_CONF".bak.* &>/dev/null'

assert "Config permissions set to 640" \
    '[[ "$(stat -c %a "$MOCK_CONF")" == "640" ]]'

# --- Test 5: --allow-remote flag ---
echo ""
echo "Test 5: --allow-remote flag"
MOCK_CONF2="$WORK_DIR/my2.cnf"
cat > "$MOCK_CONF2" << 'EOF'
[mysqld]
datadir=/var/lib/mysql
EOF

MODIFIED_SCRIPT2="$WORK_DIR/mysqlharden_test2.sh"
sed 's/if \[\[ \$EUID -ne 0 \]\]/if false/' \
    "$SCRIPT_DIR/../linux/postHardenTools/misc/MySQL/mysqlharden.sh" > "$MODIFIED_SCRIPT2"
sed -i "s|for conf in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf /etc/my.cnf|for conf in $MOCK_CONF2|" "$MODIFIED_SCRIPT2"
sed -i 's/chown .*/true/' "$MODIFIED_SCRIPT2"
chmod +x "$MODIFIED_SCRIPT2"

bash "$MODIFIED_SCRIPT2" -u root -p testpass -r > /dev/null 2>&1 || true
assert "bind-address NOT set with --allow-remote" \
    '! grep -q "bind-address" "$MOCK_CONF2"'

# --- Summary ---
echo ""
echo "=========================================="
echo "Results: $PASS/$TESTS passed, $FAIL failed"
echo "=========================================="
exit $FAIL
