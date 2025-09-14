#!/bin/bash

# ====================================================================================
# FireJail Profile Builder Script
#
# This script semi-automates the creation of a baseline FireJail profile for a
# given application. It uses FireJail's `--build` feature to trace the
# application's activity and generate a starting profile.
#
# USAGE: sudo ./firejailProfileBuilder.sh
# ====================================================================================

# --- Script Configuration ---
# Exit immediately if a command exits with a non-zero status.
set -e

# --- Color Codes for Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Function to Print Messages ---
log_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}--- $1 ---${NC}"
}

# --- Root User Check ---
if [ "$(id -u)" -ne 0 ]; then
  log_warning "This script must be run as root to build and install profiles. Please use sudo."
  exit 1
fi

# --- Step 1: Get Application Path ---
log_step "Step 1: Select Application to Profile"
read -p "Enter the full path to the application executable (e.g., /usr/sbin/nginx): " APP_PATH

if [ -z "$APP_PATH" ]; then
    log_warning "Application path cannot be empty. Aborting."
    exit 1
fi

if [ ! -x "$APP_PATH" ]; then
    log_warning "The file at '$APP_PATH' does not exist or is not executable. Aborting."
    exit 1
fi

# --- Step 2: Prepare for Build ---
log_step "Step 2: Prepare Profile Build"
APP_NAME=$(basename "$APP_PATH")
PROFILE_NAME="${APP_NAME}.profile"
TEMP_PROFILE_PATH="./${PROFILE_NAME}"

log_message "Application: $APP_PATH"
log_message "A new profile will be generated at: $TEMP_PROFILE_PATH"

if [ -f "$TEMP_PROFILE_PATH" ]; then
    log_warning "A temporary profile file '$TEMP_PROFILE_PATH' already exists."
    read -p "Do you want to overwrite it? (y/n): " confirm
    if [[ "$confirm" != [yY] ]]; then
        log_message "Aborting."
        exit 0
    fi
    rm -f "$TEMP_PROFILE_PATH"
fi

# --- Step 3: Run the Build Process ---
log_step "Step 3: Interactive Profile Generation"
echo -e "${YELLOW}The application '$APP_NAME' will now start in a tracing environment.${NC}"
echo -e "1. ${CYAN}Interact with the application${NC} in another terminal. Perform all the actions you want to allow (e.g., access a webpage, connect to a database, etc.)."
echo -e "2. FireJail will record these actions to build the profile."
echo -e "3. When you are finished interacting with the application, ${CYAN}press [Enter] in THIS window${NC} to stop the trace and finalize the profile."
echo ""
read -p "Press [Enter] to begin the trace..."

# Run firejail --build in the background
firejail --build="$TEMP_PROFILE_PATH" "$APP_PATH" &
FJ_PID=$!

# Wait for the user to finish their interaction
read -p "Tracing is active. Press [Enter] when you are done interacting with the application..."

# Stop the tracing process
log_message "Stopping the trace and killing the application process (PID: $FJ_PID)..."
kill -SIGINT "$FJ_PID"
sleep 2 # Wait a moment to ensure the process is terminated and the file is written

if [ ! -f "$TEMP_PROFILE_PATH" ]; then
    log_warning "❌ Profile generation failed. The file '$TEMP_PROFILE_PATH' was not created."
    log_warning "This can happen if the application exits immediately or crashes. Try running it manually first."
    exit 1
fi

log_message "✅ Baseline profile has been generated."

# --- Step 4: Review and Install Profile ---
log_step "Step 4: Review and Install Profile"
echo "-------------------- Generated Profile: $PROFILE_NAME --------------------"
cat "$TEMP_PROFILE_PATH"
echo "--------------------------------------------------------------------------"
echo ""

log_warning "The profile above is a baseline. It may be too permissive."
log_warning "It is STRONGLY recommended to review it and remove unnecessary 'read' or 'write' permissions."

read -p "Do you want to install this profile to /etc/firejail/? (y/n): " install_confirm
if [[ "$install_confirm" != [yY] ]]; then
    log_message "Profile not installed. You can find it at '$TEMP_PROFILE_PATH'."
    exit 0
fi

DEST_PROFILE_PATH="/etc/firejail/${PROFILE_NAME}"
log_message "Installing profile to '$DEST_PROFILE_PATH'..."
mv "$TEMP_PROFILE_PATH" "$DEST_PROFILE_PATH"
chown root:root "$DEST_PROFILE_PATH"
chmod 644 "$DEST_PROFILE_PATH"

log_message "✅ Profile installed successfully."

# --- Step 5: Final Instructions ---
log_step "Step 5: Next Steps"
echo "You can now test your new profile with:"
echo -e "  ${YELLOW}sudo firejail --profile=$DEST_PROFILE_PATH $APP_PATH${NC}"
echo ""
echo "Once you are satisfied, you can integrate it with systemd to make it permanent."
echo "For example, for nginx:"
echo "  1. Run: ${YELLOW}sudo systemctl edit nginx.service${NC}"
echo "  2. Add the following lines:"
echo -e "     ${CYAN}[Service]${NC}"
echo -e "     ${CYAN}ExecStart=${NC}"
echo -e "     ${CYAN}ExecStart=/usr/bin/firejail --profile=$DEST_PROFILE_PATH /usr/sbin/nginx -g 'daemon on; master_process on;'${NC}"
echo "  3. Run: ${YELLOW}sudo systemctl daemon-reload && sudo systemctl restart nginx.service${NC}"

exit 0