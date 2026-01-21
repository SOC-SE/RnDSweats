#!/bin/bash

# ====================================================================================
# Custom port Entry Tool for /etc/hosts
#
# Description: Adds a new exposed port for proxy streams in NPM
#
# Usage: sudo ./streamAdd.sh <PORT_NUMBER> <COMMENT>
# ====================================================================================

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 1. Argument Validation
if [ "$#" -ne 2 ]; then
    echo -e "Correct format: $0 {port-number} {comment}"
    echo -e "${CYAN}Example:${NC} $0 777 custom-ssh"
    exit 1
fi

PORT=$1
COMMENT=$2
COMPOSE_PATH="/opt/nginx-proxy-manager/"
COMPOSE_FILE="${COMPOSE_PATH}/docker-compose.yaml"


# 1. Add the new entry
echo -e "Adding port: ${CYAN}$PORT${NC}"
sed -i "s/- 81\:81 \# Admin Web Port/- 81:81 \# Admin Web Port \n      - ${PORT}\:${PORT} \# ${COMMENT}/" $COMPOSE_FILE
echo -e "${GREEN}SUCCESS: The port has been added to $COMPOSE_FILE${NC}"

# 2. Restart NPM
echo -e "${CYAN}Restarting Docker containers...${NC}"
cd $COMPOSE_PATH
docker compose up -d --force-recreate
echo -e "${GREEN}SUCCESS: Docker containers have restarted successfully${NC}"
