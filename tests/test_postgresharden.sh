#!/bin/bash
# Dry-run test harness for postgresharden.sh
# Mocks psql command and config files to verify script logic
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
echo "PostgreSQL Hardening Script - Dry Run Tests"
echo "=========================================="
echo ""

# --- Setup mock pg data directory and configs ---
PG_DATA="$WORK_DIR/pgdata"
mkdir -p "$PG_DATA"

PG_HBA="$PG_DATA/pg_hba.conf"
cat > "$PG_HBA" << 'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
host    all             all             127.0.0.1/32            ident
host    all             all             ::1/128                 trust
# host  replication     all             127.0.0.1/32            trust
EOF

PG_CONF="$PG_DATA/postgresql.conf"
cat > "$PG_CONF" << 'EOF'
#listen_addresses = '*'
#ssl = off
#log_connections = off
#log_disconnections = off
#log_statement = 'none'
#password_encryption = md5
max_connections = 100
EOF

# --- Setup mock psql binary ---
MOCK_BIN="$WORK_DIR/bin"
mkdir -p "$MOCK_BIN"

QUERY_LOG="$WORK_DIR/queries.log"
touch "$QUERY_LOG"

cat > "$MOCK_BIN/psql" << MOCKEOF
#!/bin/bash
QUERY_LOG="$QUERY_LOG"
PG_DATA="$PG_DATA"
PG_HBA="$PG_HBA"
PG_CONF="$PG_CONF"

# Parse args to find -c query
query=""
i=0
args=("\$@")
for ((i=0; i<\${#args[@]}; i++)); do
    if [[ "\${args[i]}" == "-c" ]]; then
        query="\${args[i+1]}"
        break
    fi
done

if [[ -n "\$query" ]]; then
    echo "\$query" >> "\$QUERY_LOG"

    case "\$query" in
        "SELECT 1")
            echo " ?column? "
            echo "----------"
            echo "        1"
            ;;
        *"data_directory"*)
            echo " \$PG_DATA "
            ;;
        *"hba_file"*)
            echo " \$PG_HBA "
            ;;
        *"config_file"*)
            echo " \$PG_CONF "
            ;;
        *"rolsuper = true AND rolname"*)
            echo ""
            ;;
        *"pg_reload_conf"*)
            echo " pg_reload_conf "
            echo "----------------"
            echo " t"
            ;;
        *"REVOKE"*)
            echo "REVOKE"
            ;;
    esac
fi
MOCKEOF
chmod +x "$MOCK_BIN/psql"

export PATH="$MOCK_BIN:$PATH"

# --- Test 1: Syntax check ---
echo "Test 1: Bash syntax validation"
assert "postgresharden.sh parses without errors" \
    "bash -n '$SCRIPT_DIR/../linux/postHardenTools/misc/PostgreSQL/postgresharden.sh'"

# --- Test 2: Help ---
echo ""
echo "Test 2: Help output"
help_output=$(bash "$SCRIPT_DIR/../linux/postHardenTools/misc/PostgreSQL/postgresharden.sh" -h 2>&1 || true)
assert "Help shows usage info" '[[ "$help_output" == *"Usage"* ]]'

# --- Test 3: Mock execution ---
echo ""
echo "Test 3: Mock execution (simulated root)"

MODIFIED_SCRIPT="$WORK_DIR/postgresharden_test.sh"
sed 's/if \[\[ \$EUID -ne 0 \]\]/if false/' \
    "$SCRIPT_DIR/../linux/postHardenTools/misc/PostgreSQL/postgresharden.sh" > "$MODIFIED_SCRIPT"
chmod +x "$MODIFIED_SCRIPT"

bash "$MODIFIED_SCRIPT" -U postgres -W testpass > "$WORK_DIR/output.log" 2>&1 || true

# --- Test 4: pg_hba.conf hardening ---
echo ""
echo "Test 4: pg_hba.conf hardening"
assert "trust replaced with scram-sha-256" \
    '! grep -v "^#" "$PG_HBA" | grep -q "\btrust\b"'

assert "ident replaced with scram-sha-256" \
    '! grep -v "^#" "$PG_HBA" | grep -q "\bident\b"'

assert "scram-sha-256 present in pg_hba.conf" \
    'grep -q "scram-sha-256" "$PG_HBA"'

assert "Commented lines preserved" \
    'grep -q "^# host.*replication.*trust" "$PG_HBA"'

assert "pg_hba.conf backup created" \
    'ls "$PG_HBA".bak.* &>/dev/null'

# --- Test 5: postgresql.conf hardening ---
echo ""
echo "Test 5: postgresql.conf hardening"
assert "listen_addresses set to localhost" \
    'grep -q "^listen_addresses = .localhost." "$PG_CONF"'

assert "log_connections enabled" \
    'grep -q "^log_connections = on" "$PG_CONF"'

assert "log_disconnections enabled" \
    'grep -q "^log_disconnections = on" "$PG_CONF"'

assert "log_statement set to ddl" \
    'grep -q "^log_statement = .ddl." "$PG_CONF"'

assert "password_encryption set to scram-sha-256" \
    'grep -q "^password_encryption = .scram-sha-256." "$PG_CONF"'

assert "postgresql.conf backup created" \
    'ls "$PG_CONF".bak.* &>/dev/null'

# --- Test 6: SQL commands issued ---
echo ""
echo "Test 6: SQL commands"
assert "REVOKE on template1 issued" \
    'grep -q "REVOKE ALL ON DATABASE template1" "$QUERY_LOG"'

assert "REVOKE on template0 issued" \
    'grep -q "REVOKE ALL ON DATABASE template0" "$QUERY_LOG"'

assert "REVOKE on postgres issued" \
    'grep -q "REVOKE ALL ON DATABASE postgres" "$QUERY_LOG"'

assert "Config reload issued" \
    'grep -q "pg_reload_conf" "$QUERY_LOG"'

# --- Test 7: --allow-remote flag ---
echo ""
echo "Test 7: --allow-remote flag"
PG_CONF2="$WORK_DIR/pg2.conf"
cat > "$PG_CONF2" << 'EOF'
#listen_addresses = '*'
max_connections = 100
EOF

# Point mock to new conf
MOCK_BIN2="$WORK_DIR/bin2"
mkdir -p "$MOCK_BIN2"
sed "s|PG_CONF=.*|PG_CONF=\"$PG_CONF2\"|" "$MOCK_BIN/psql" > "$MOCK_BIN2/psql"
chmod +x "$MOCK_BIN2/psql"

MODIFIED_SCRIPT2="$WORK_DIR/postgresharden_test2.sh"
sed 's/if \[\[ \$EUID -ne 0 \]\]/if false/' \
    "$SCRIPT_DIR/../linux/postHardenTools/misc/PostgreSQL/postgresharden.sh" > "$MODIFIED_SCRIPT2"
chmod +x "$MODIFIED_SCRIPT2"

PATH="$MOCK_BIN2:$PATH" bash "$MODIFIED_SCRIPT2" -U postgres -W testpass -r > /dev/null 2>&1 || true
assert "listen_addresses NOT changed with --allow-remote" \
    'grep -q "^#listen_addresses" "$PG_CONF2"'

# --- Summary ---
echo ""
echo "=========================================="
echo "Results: $PASS/$TESTS passed, $FAIL failed"
echo "=========================================="
exit $FAIL
