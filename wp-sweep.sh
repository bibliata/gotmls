#!/usr/bin/env bash
# wp-sweep.sh - audit every ISPConfig site for the infection leftovers found on web31.
#
#   bash wp-sweep.sh scan         read-only scan of all sites (default)
#   bash wp-sweep.sh quarantine   scan, then MOVE high-confidence hits (A-G) to /root/quarantine-sweep-*
#   bash wp-sweep.sh admins       list WordPress administrators per site (needs wp-cli)
#   bash wp-sweep.sh core         core + plugin checksum check per site (needs wp-cli, slow)
#
# Options (environment variables):
#   SITES="web31 web2"   only these sites          BASE=/var/www/clients/client0
#   SINCE=2026-09-01     ctime cut-off for media files and "new admin" check
#   ALLOW='/alm_templates/'   regex of PHP files in uploads that are legitimate
#   QH=1  also quarantine signature hits (H)       QL=1  also quarantine file-manager/jetpack/.tmb (L)
#
# Nothing is ever deleted. Moved files keep their full path under the quarantine folder:
#   restore a site:  cp -a /root/quarantine-sweep-XXXX/web31/var/. /var/

MODE="${1:-scan}"
BASE="${BASE:-/var/www/clients/client0}"
SINCE="${SINCE:-2026-09-01}"
ALLOW="${ALLOW:-/alm_templates/}"
TS="$(date +%F-%H%M)"
OUT="/root/sweep-$TS"
QDIR="/root/quarantine-sweep-$TS"
G=$'\033[32m'; R=$'\033[31m'; N=$'\033[0m'
BAD_HT='x-httpd-php|AddHandler|SetHandler|AddType[^#]*php|auto_prepend|auto_append|DirectoryIndex'
mkdir -p "$OUT"

if [ -n "${SITES:-}" ]; then read -r -a sites <<< "$SITES"
else sites=(); for d in "$BASE"/web*/; do [ -d "$d" ] && sites+=("$(basename "$d")"); done; fi
n=${#sites[@]}

bar() { # bar index total label
  local pct=$(( $1 * 100 / $2 )) filled=$(( $1 * 100 / $2 / 5 )) b
  b=$(printf '%*s' "$filled" '' | tr ' ' '#')
  printf '\r%s[%-20s] %3d%%%s  %d/%d  %-10s' "$G" "$b" "$pct" "$N" "$1" "$2" "$3"
}

denyonly() { grep -qiE 'deny from all|require all denied' "$1" 2>/dev/null && ! grep -qiE "$BAD_HT" "$1" 2>/dev/null; }

# ---- per wp-content checks ($1 = wp-content directory) -------------------------------------
scan_A() { # suspicious .htaccess files
  local f
  find "$1" -type f -name .htaccess 2>/dev/null | while IFS= read -r f; do
    denyonly "$f" && continue
    case "$f" in
      */wp-content/uploads/*|*/wp-content/languages/*|*/wp-content/.htaccess|*/wp-content/plugins/.htaccess|*/wp-content/themes/.htaccess) echo "$f" ;;
      *) grep -qiE "$BAD_HT" "$f" 2>/dev/null && echo "$f" ;;
    esac
  done
}
scan_C() { # PHP files inside uploads
  local f
  find "$1/uploads" -type f \( -iname '*.php' -o -iname '*.php[3-8]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' \) 2>/dev/null | while IFS= read -r f; do
    echo "$f" | grep -qE "$ALLOW" && continue
    if [ "$(basename "$f")" = index.php ] && [ "$(stat -c %s "$f")" -lt 200 ] && grep -q 'Silence is golden' "$f"; then continue; fi
    echo "$f"
  done
}
scan_D() { # PHP code hidden inside images/media (only files changed since $SINCE; ctime cannot be faked)
  find "$1/uploads" "$1/themes" "$1/plugins" "$(dirname "$1")/wp-includes" "$(dirname "$1")/wp-admin" -type f -newerct "$SINCE" -size -6000k \
    \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.ico' -o -iname '*.bmp' -o -iname '*.webp' \
       -o -iname '*.wmv' -o -iname '*.avi' -o -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.flv' -o -iname '*.swf' \) -print0 2>/dev/null |
    xargs -0 -r grep -l -a -F '<?php' 2>/dev/null
}
scan_G1() { # unexpected PHP at wp-content root (db.php is always flagged)
  find "$1" -maxdepth 1 -type f -name '*.php' ! -name index.php ! -name object-cache.php ! -name advanced-cache.php \
    ! -name db-error.php ! -name maintenance.php ! -name php-error.php ! -name sunrise.php ! -name install.php 2>/dev/null
}
scan_G2() { # extra PHP in the web root next to wp-load.php (report only)
  local r f; r="$(dirname "$1")"
  [ -f "$r/wp-load.php" ] || return
  find "$r" -maxdepth 1 -type f -name '*.php' 2>/dev/null | while IFS= read -r f; do
    case "$(basename "$f")" in
      index.php|wp-activate.php|wp-blog-header.php|wp-comments-post.php|wp-config.php|wp-config-sample.php|wp-cron.php|wp-links-opml.php|wp-load.php|wp-login.php|wp-mail.php|wp-settings.php|wp-signup.php|wp-trackback.php|xmlrpc.php) ;;
      *) echo "$f" ;;
    esac
  done
}
scan_L() { # file-manager plugin, jetpack, elFinder thumbnail folders
  find "$1/plugins" -maxdepth 1 -type d \( -iname '*file-manager*' -o -iname 'jetpack*' -o -iname 'easypost*' \) 2>/dev/null
  find "$1/uploads" -maxdepth 1 -iname '*file-manager*' 2>/dev/null
  find "$(dirname "$1")" -maxdepth 2 -type d -name .tmb 2>/dev/null
}

# ---- whole-site checks ($1 = web directory) -------------------------------------------------
scan_B() { # php.ini / .user.ini
  local f
  find "$1" -type f \( -name php.ini -o -name .user.ini \) 2>/dev/null | while IFS= read -r f; do
    grep -qi 'wordfence-waf' "$f" 2>/dev/null && continue
    case "$f" in
      */wp-content/*) echo "$f" ;;
      *) grep -qiE 'disable_functions|open_basedir|safe_mode|auto_prepend|allow_url_include|exec *= *on' "$f" 2>/dev/null && echo "$f" ;;
    esac
  done
}
scan_E() { # hashed payload zips like m3u_6ac48c6c9ca64.zip
  find "$1" -type f -regextype posix-extended -regex '.*/[a-z0-9]{2,6}_[0-9a-f]{13}\.zip' 2>/dev/null
}
scan_E2() { # doubled date folders like uploads/2024/12/12 (report only)
  find "$1" -type d -regextype posix-extended \( -regex '.*/uploads/([0-9]{4})/\1' -o -regex '.*/uploads/[0-9]{4}/([0-9]{2})/\1' \) 2>/dev/null
}
scan_F() { # hidden payload files with odd names, e.g. "_(:...", outside uploads
  LC_ALL=C find "$1" -type f \( -name '*[! -~]*' -o \( -name '_*' ! -name '*.*' \) \) ! -path '*/wp-content/uploads/*' ! -name '_*.scss' 2>/dev/null
}
scan_G3() { # known backdoor file names
  find "$1" -type f \( -name filefuns.php -o \( -name post-new.php ! -path '*/wp-admin/*' \) -o -name easypost.php -o -name convertsoil.php \
    -o -name wp-feed-cache.php -o -name wp-globals.php -o -name 'akismet-shim*' \) 2>/dev/null
}
scan_H() { # known infection signatures
  grep -rIlE --include='*.php' --include='*.phtml' --include='*.inc' \
    -e 'Options warm-up handler' -e 'Runtime dependencies bootstrap' -e 'wp_shim_uid' -e 'xwp_23578' -e 'xx1kontl' \
    -e 'EASYPOST_ENDPOINT_CONFIG' -e 'str_rot13\(\$_COOKIE' -e 'goto [A-Za-z0-9_]{8,};' -e "require(_once)? *\(? *['\"]zip://" "$1" 2>/dev/null
}
scan_I() { # tiny PHP files that read cookies and include something (review only)
  find "$1" -type f -name '*.php' -size -4k -print0 2>/dev/null |
    xargs -0 -r grep -lZE '\$_COOKIE' 2>/dev/null | xargs -0 -r grep -lE 'include(_once)?[ (]|require(_once)?[ (]' 2>/dev/null
}

cnt() { local f; f=$(ls "$1"_*.txt 2>/dev/null | head -1); [ -n "$f" ] && wc -l < "$f" || echo 0; }

# ---- modes that use wp-cli --------------------------------------------------------------------
if [ "$MODE" = admins ] || [ "$MODE" = core ]; then
  i=0; : > "$OUT/$MODE.txt"
  for s in "${sites[@]}"; do
    i=$((i+1)); bar "$i" "$n" "$s"
    p="$BASE/$s/web"; [ -f "$p/wp-config.php" ] || continue
    W="wp --allow-root --skip-plugins --skip-themes --path=$p"
    if [ "$MODE" = admins ]; then
      $W user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null | tail -n +2 | sed "s/^/$s,/" >> "$OUT/admins.txt"
      for o in wp_shim_uid xwp_23578_user_id; do v=$($W option get $o 2>/dev/null); [ -n "$v" ] && echo "$s,OPTION $o=$v" >> "$OUT/admins.txt"; done
    else
      { $W core verify-checksums 2>&1 | grep -E 'Warning|Error' | grep -v 'xmlrpc.php' | sed "s/^/$s core: /"
        $W plugin verify-checksums --all 2>&1 | grep -E 'Warning|Error' | sed "s/^/$s plugin: /"; } >> "$OUT/core.txt"
    fi
  done
  echo
  if [ "$MODE" = admins ]; then
    awk -F, -v R="$R" -v N="$N" -v S="$SINCE" '/OPTION/ || /wpsupport/ || $5>=S {print R $0 N; next} {print}' "$OUT/admins.txt"
  else
    sed "s/^/${R}/;s/\$/${N}/" "$OUT/core.txt"
  fi
  echo "saved: $OUT/$MODE.txt"; exit 0
fi

# ---- scan -------------------------------------------------------------------------------------
i=0
for s in "${sites[@]}"; do
  i=$((i+1)); bar "$i" "$n" "$s"
  w="$BASE/$s/web"; [ -d "$w" ] || continue
  d="$OUT/$s"; mkdir -p "$d"
  : > "$d/A_htaccess.txt"; : > "$d/C_uploads_php.txt"; : > "$d/D_media_php.txt"; : > "$d/G_known_files.txt"; : > "$d/G2_docroot_extra.txt"; : > "$d/L_plugins.txt"
  while IFS= read -r wc; do
    scan_A "$wc"  >> "$d/A_htaccess.txt"
    scan_C "$wc"  >> "$d/C_uploads_php.txt"
    scan_D "$wc"  >> "$d/D_media_php.txt"
    scan_G1 "$wc" >> "$d/G_known_files.txt"
    scan_G2 "$wc" >> "$d/G2_docroot_extra.txt"
    scan_L "$wc"  >> "$d/L_plugins.txt"
  done < <(find "$w" -type d -name wp-content 2>/dev/null)
  scan_B "$w"  > "$d/B_phpini.txt"
  scan_E "$w"  > "$d/E_hashed_zip.txt"
  scan_E2 "$w" > "$d/E2_doubled_dirs.txt"
  scan_F "$w"  > "$d/F_odd_names.txt"
  scan_G3 "$w" >> "$d/G_known_files.txt"
  scan_H "$w"  > "$d/H_signatures.txt"
  scan_I "$w"  > "$d/I_cookie_loaders.txt"
  for f in "$d"/*.txt; do sort -u "$f" -o "$f"; done
done
echo

# ---- summary ----------------------------------------------------------------------------------
{ printf '\n%-9s' SITE; for c in A B C D E F G H I L; do printf '%6s' "$c"; done; echo
  hit=0
  for s in "${sites[@]}"; do
    d="$OUT/$s"; [ -d "$d" ] || continue
    printf '%-9s' "$s"; tot=0
    for c in A B C D E F G H I L; do
      v=$(cnt "$d/$c")
      if [ "$v" -gt 0 ]; then printf '%s%6s%s' "$R" "$v" "$N"; tot=$((tot+v)); else printf '%6s' 0; fi
    done; echo; [ "$tot" -gt 0 ] && hit=$((hit+1))
  done
  echo; echo "sites with hits: $hit of $n"
  echo "A=.htaccess  B=php.ini  C=PHP in uploads  D=PHP hidden in media  E=hashed zips  F=odd names"
  echo "G=known backdoor files / wp-content PHP  H=signatures  I=cookie loaders (review)  L=file-manager/jetpack/.tmb"
  echo "full lists: $OUT/<site>/<category>.txt   (E2 = doubled date folders, G2 = extra docroot PHP: report only)"
} | tee "$OUT/SUMMARY.txt"

# ---- quarantine -------------------------------------------------------------------------------
if [ "$MODE" = quarantine ]; then
  cats="A_htaccess B_phpini C_uploads_php D_media_php E_hashed_zip F_odd_names G_known_files"
  [ "${QH:-0}" = 1 ] && cats="$cats H_signatures"
  [ "${QL:-0}" = 1 ] && cats="$cats L_plugins"
  printf '\nMove all flagged files in: %s\ninto %s ? Type YES: ' "$cats" "$QDIR"; read -r ans
  [ "$ans" = YES ] || { echo "aborted, nothing moved"; exit 1; }
  moved=0
  for s in "${sites[@]}"; do
    for c in $cats; do
      [ -s "$OUT/$s/$c.txt" ] || continue
      while IFS= read -r f; do
        [ -e "$f" ] || continue
        dst="$QDIR/$s$f"; mkdir -p "$(dirname "$dst")" && mv -- "$f" "$dst" && { moved=$((moved+1)); printf '%sMOVED%s %s\n' "$R" "$N" "$f"; }
      done < "$OUT/$s/$c.txt"
    done
  done | tee "$OUT/moved.log" | tail -n 40
  echo "moved: $(grep -c MOVED "$OUT/moved.log") files, log: $OUT/moved.log, quarantine: $QDIR"
fi
