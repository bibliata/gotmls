#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0;37m' # Normal plain text color

# Base client path
BASE_PATH="/var/www/clients/client0"

# Find all directories inside the client folder matching 'web*'
mapfile -t DIRS < <(find "$BASE_PATH" -maxdepth 1 -type d -name "web*" | sort -V)
TOTAL_DIRS=${#DIRS[@]}

if [ "$TOTAL_DIRS" -eq 0 ]; then
    echo -e "${RED}Error: No web directories found in $BASE_PATH${NC}"
    exit 1
fi

echo -e "\n========================================================"
echo -e "Starting WordPress Integrity Audit for $TOTAL_DIRS Directories"
echo -e "========================================================\n"

# Loop through each directory
for i in "${!DIRS[@]}"; do
    DIR="${DIRS[$i]}"
    WEB_ROOT="$DIR/web"
    DIR_NAME=$(basename "$DIR")
    
    # Calculate progress bar details
    CURRENT=$((i + 1))
    PERCENT=$(( CURRENT * 100 / TOTAL_DIRS ))
    BAR_WIDTH=20
    FILLED=$(( PERCENT * BAR_WIDTH / 100 ))
    UNFILLED=$(( BAR_WIDTH - FILLED ))
    
    # Build the text-based DOS status bar string
    BAR_STR="["
    for ((j=0; j<FILLED; j++)); do BAR_STR="${BAR_STR}#"; done
    for ((j=0; j<UNFILLED; j++)); do BAR_STR="${BAR_STR}."; done
    BAR_STR="${BAR_STR}] (${PERCENT}%)"

    # Step 1: Check if the folder contains a valid WordPress installation
    if [ ! -f "$WEB_ROOT/wp-config.php" ] || [ ! -f "$WEB_ROOT/wp-includes/version.php" ]; then
        # If it's not WordPress, display status and skip to next directory
        printf "%-28s %-30s\n" "${BAR_STR}" "DIR: ${DIR_NAME} -> Skipping (Not WordPress)"
        continue
    fi

    # Step 2: Run Core Checksum Verification
    CORE_CHECK=$(wp core verify-checksums --path="$WEB_ROOT" --allow-root 2>&1)
    CORE_STATUS=$?

    # Step 3: Run Plugin Checksum Verification
    PLUGIN_CHECK=$(wp plugin verify-checksums --all --path="$WEB_ROOT" --allow-root 2>&1)
    PLUGIN_STATUS=$?

    # Step 4: Parse outputs and display single-line results
    if [ $CORE_STATUS -eq 0 ] && [ $PLUGIN_STATUS -eq 0 ]; then
        # Everything passed successfully
        printf "%-28s %-15s ${GREEN}[OK] Core & Plugins Clear${NC}\n" "${BAR_STR}" "DIR: ${DIR_NAME}"
    else
        # Something failed, aggregate error notifications
        ERR_MSG=""
        if [ $CORE_STATUS -ne 0 ]; then
            ERR_MSG="Core Corrupted"
        fi
        if [ $PLUGIN_STATUS -ne 0 ]; then
            if [ -n "$ERR_MSG" ]; then ERR_MSG="${ERR_MSG} & "; fi
            ERR_MSG="${ERR_MSG}Plugin Malfunction/403 Block"
        fi
        printf "%-28s %-15s ${RED}[NOT OK] ${ERR_MSG}${NC}\n" "${BAR_STR}" "DIR: ${DIR_NAME}"
    fi

done

echo -e "\n========================================================"
echo -e "Audit Complete! Clear your history using: history -c"
echo -e "========================================================\n"
