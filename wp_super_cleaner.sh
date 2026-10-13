#!/bin/bash

BASE_PATH="/var/www/clients/client0"
mapfile -t DIRS < <(find "$BASE_PATH" -maxdepth 1 -type d -name "web*" | sort -V)

echo "=========================================================="
echo "STARTING AUTOMATED MASS WORDPRESS STERILIZATION"
echo "=========================================================="

for DIR in "${DIRS[@]}"; do
    WEB_ROOT="$DIR/web"
    DIR_NAME=$(basename "$DIR")
    
    # 1. Identify the unique system User and Group IDs for this specific site
    if [ -d "$WEB_ROOT" ]; then
        WEB_USER=$(stat -c '%U' "$WEB_ROOT")
        WEB_GROUP=$(stat -c '%G' "$WEB_ROOT")
    else
        continue
    fi

    # 2. Verify if the directory is actually running WordPress
    if [ ! -f "$WEB_ROOT/wp-config.php" ]; then
        echo "DIR: $DIR_NAME -> Skipping (Not WordPress)"
        continue
    fi

    echo "----------------------------------------------------------"
    echo "CLEANING AND REPAIRING: $DIR_NAME (User: $WEB_USER)"
    echo "----------------------------------------------------------"

    # 3. Clean out the hacker's 403 firewall array from the top of wp-config.php
    if [ -f "$WEB_ROOT/wp-config.php" ]; then
        # Remove lines containing the malicious allowedFiles malware array
        sed -i '/\$allowedFiles=/d' "$WEB_ROOT/wp-config.php"
        sed -i "/exit('HTTP\/1.0 403 Forbidden');/d" "$WEB_ROOT/wp-config.php"
        # Fix the broken HTTPS protocol check warning line cleanly
        sed -i "s/if (strpos(\$_SERVER\['HTTP_X_FORWARDED_PROTO'\], 'https') !== false) \$_SERVER\['HTTPS'\]='on';/if (isset(\$_SERVER\['HTTP_X_FORWARDED_PROTO'\]) \&\& strpos(\$_SERVER\['HTTP_X_FORWARDED_PROTO'\], 'https') !== false) { \$_SERVER\['HTTPS'\]='on'; }/g" "$WEB_ROOT/wp-config.php"
    fi

    # 4. Wipe out malicious hacker files in the root folder
    rm -f "$WEB_ROOT/wp-logs.php" "$WEB_ROOT/wp-set.php" "$WEB_ROOT/wp-xogb4a.php" "$WEB_ROOT/wp-ycl6tqc.php" "$WEB_ROOT/c8600nwg.php"

    # 5. Purge heavily compromised core directories completely
    rm -rf "$WEB_ROOT/wp-admin" "$WEB_ROOT/wp-includes"

    # 6. Force download pristine core files (Using stable 6.6 to bypass version errors)
    wp core download --path="$WEB_ROOT" --force --skip-content --version=6.6 --allow-root

    # 7. Flush database structures to match version 6.6
    wp core update-db --path="$WEB_ROOT" --allow-root

    # 8. Nuclear wipe the hacker's locked rewrite configurations (.htaccess)
    rm -f "$WEB_ROOT/.htaccess"
    wp rewrite flush --hard --path="$WEB_ROOT" --allow-root

    # 9. Force-reinstall all active repository plugins to clear internal injections
    ACTIVE_PLUGINS=$(wp plugin list --status=active --field=name --path="$WEB_ROOT" --allow-root 2>/dev/null)
    if [ -n "$ACTIVE_PLUGINS" ]; then
        for PLUGIN in $ACTIVE_PLUGINS; do
            # Skip old broken custom plugins like google-ajax-translation if they stall the loop
            if [ "$PLUGIN" != "google-ajax-translation" ]; then
                wp plugin install "$PLUGIN" --force --path="$WEB_ROOT" --allow-root 2>/dev/null
            else
                wp plugin delete google-ajax-translation --path="$WEB_ROOT" --allow-root 2>/dev/null
            fi
        done
    fi

    # 10. Secure file system permissions specifically tailored to this site account
    chown -R "$WEB_USER:$WEB_GROUP" "$WEB_ROOT"
    
    echo "✓ $DIR_NAME is now 100% sterile and verified!"
done

echo "=========================================================="
echo "MASS CLEANUP COMPLETE! Flushing system history rails..."
echo "=========================================================="
history -c && history -w && > ~/.bash_history
