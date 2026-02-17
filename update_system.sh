#!/bin/bash
# Simple Arcades Updater - Gen4 (self-host + mirrors + auth + hash-aware reapply)
# Build: 2026-01-16-gen4-v1

set -u

# ----------------------------
# Config
# ----------------------------

# Primary + mirrors (blank entries are ignored).
# Must point to a folder containing:
#   - update_version_list.txt
#   - update_system.sh (+ update_system.sh.sha256 if enabled)
#   - <version>.tar.gz (+ <version>.tar.gz.sha256)
UPDATE_BASE_URLS=(
  "https://vintage-vault.ddns.net/simple-arcade-updates/updates_gen_4-main"
  ""
  ""
)

AUTH_FILE="/home/pi/simplearcades/scripts/utilities/.sa_updater_auth"

# Self-update (relative to base URLs)
SELF_UPDATE_ENABLED=1
SELF_UPDATE_REL_PATH="update_system.sh"

# Verification
CHECKSUM_VERIFY_ENABLED=1

# Timeouts / retries (applies to curl/wget)
NET_TIMEOUT=20
NET_TRIES=3

# Local paths
CUSTOM_SCRIPTS_DIR="/home/pi/simplearcades/scripts"
LOG_FILE="$CUSTOM_SCRIPTS_DIR/logs/update_system.log"
VERSION_LOG="$CUSTOM_SCRIPTS_DIR/logs/update_version.log"
LOCAL_VERSION_FILE="$CUSTOM_SCRIPTS_DIR/logs/current_update_version.txt"
HASH_LOG="$CUSTOM_SCRIPTS_DIR/logs/applied_update_hashes.log"

# Extract temp dir
TEMP_UPDATE_DIR="/tmp/simple_arcades_update"

# Update pack meta folder name
META_DIR_NAME=".sa_meta"

# UI
DIALOG_TITLE="Simple Arcades Updates"
IN_GAUGE=0

# ----------------------------
# Permissions baselines (keep as-is; add auth file override)
# ----------------------------

declare -A DIR_PERMISSIONS=(
  ["/home/pi/simplearcades"]="pi:pi 755"
  ["/home/pi/RetroPie"]="pi:pi 755"
  ["/opt/retropie/configs"]="pi:pi 755"
  ["/opt/retropie/supplementary"]="root:root 755"
  ["/opt/retropie/libretrocores"]="root:root 755"
  ["/etc/emulationstation"]="root:root 755"
  ["/boot"]="root:root 755"
)

declare -A FILE_PERMISSIONS=(
)

# ----------------------------
# Helpers
# ----------------------------

log_update() {
  local msg="$1"
  mkdir -p "$(dirname "$LOG_FILE")" >/dev/null 2>&1
  if touch "$LOG_FILE" >/dev/null 2>&1; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $msg" >> "$LOG_FILE"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $msg" >> /tmp/update_system.log
  fi
}

show_message() {
  local message="$1"
  if [ "$IN_GAUGE" -eq 1 ]; then
    # Never open dialog boxes inside the gauge; just log.
    log_update "UI suppressed (in gauge): $(echo "$message" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    return 0
  fi
  if command -v dialog >/dev/null 2>&1; then
    dialog --title "$DIALOG_TITLE" --ok-button "OK" --msgbox "$message" 14 72
  else
    echo "$message"
  fi
}

ensure_file_exists() {
  local file_path="$1"
  local default_value="$2"
  if [ ! -f "$file_path" ]; then
    mkdir -p "$(dirname "$file_path")" >/dev/null 2>&1
    echo "$default_value" > "$file_path"
    log_update "Initialized $file_path with value: $default_value"
  fi
}

clean_version_name() {
  local v="$1"
  v="${v##*/}"
  v="${v%.tar.gz}"
  echo "$v"
}

apply_dir_baselines() {
  local dir owner_group perm owner group
  for dir in "${!DIR_PERMISSIONS[@]}"; do
    [ -d "$dir" ] || continue
    IFS=' ' read -r owner_group perm <<< "${DIR_PERMISSIONS[$dir]}"
    IFS=':' read -r owner group <<< "$owner_group"
    chown "$owner":"$group" "$dir" >/dev/null 2>&1
    chmod "$perm" "$dir" >/dev/null 2>&1
  done
}

apply_file_permission_overrides() {
  local f owner_group perm owner group
  for f in "${!FILE_PERMISSIONS[@]}"; do
    if [ -e "$f" ]; then
      IFS=' ' read -r owner_group perm <<< "${FILE_PERMISSIONS[$f]}"
      IFS=':' read -r owner group <<< "$owner_group"
      chown "$owner":"$group" "$f" >/dev/null 2>&1
      chmod "$perm" "$f" >/dev/null 2>&1
    fi
  done
}

human_bytes() {
  local b="${1:-0}"
  if [ "$b" -ge 1073741824 ] 2>/dev/null; then
    awk -v x="$b" 'BEGIN{printf "%.1f GB", x/1073741824}'
  elif [ "$b" -ge 1048576 ] 2>/dev/null; then
    awk -v x="$b" 'BEGIN{printf "%.1f MB", x/1048576}'
  elif [ "$b" -ge 1024 ] 2>/dev/null; then
    awk -v x="$b" 'BEGIN{printf "%.1f KB", x/1024}'
  else
    echo "${b} B"
  fi
}

is_valid_update_filename() {
  local f="$1"
  [[ "$f" =~ ^[A-Za-z0-9._-]+\.tar\.gz$ ]]
}

validate_tarball_safe() {
  local archive="$1"
  local listing rc entry
  listing="$(tar -tzf "$archive" 2>&1)"
  rc=$?
  if [ $rc -ne 0 ]; then
    local one_line
    one_line="$(echo "$listing" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    log_update "Tar list failed (rc=$rc) for $(basename "$archive"): $one_line"
    return 1
  fi

  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    entry="${entry%$'\r'}"
    [[ "$entry" == /* ]] && { log_update "Unsafe tar entry (absolute path): $entry"; return 1; }
    [[ "$entry" =~ (^|/)\.\.($|/) ]] && { log_update "Unsafe tar entry (path traversal): $entry"; return 1; }
    [[ "$entry" == *\\* ]] && { log_update "Unsafe tar entry (backslash): $entry"; return 1; }
  done <<< "$listing"

  return 0
}

# ----------------------------
# Auth (safe parse; no "source")
# ----------------------------

SA_USER=""
SA_PASS=""

strip_quotes() {
  local s="$1"
  s="${s%$'\r'}"
  s="${s%\"}"
  s="${s#\"}"
  echo "$s"
}

load_auth() {
  [ -f "$AUTH_FILE" ] || return 1

  local u p
  u="$(grep -m1 '^SA_USER=' "$AUTH_FILE" 2>/dev/null | sed 's/^SA_USER=//')"
  p="$(grep -m1 '^SA_PASS=' "$AUTH_FILE" 2>/dev/null | sed 's/^SA_PASS=//')"

  u="$(strip_quotes "$u")"
  p="$(strip_quotes "$p")"

  if [ -z "$u" ] || [ -z "$p" ]; then
    return 1
  fi

  SA_USER="$u"
  SA_PASS="$p"
  return 0
}

# ----------------------------
# URL helpers + downloads (primary + mirrors)
# ----------------------------

join_url() {
  local base="$1"
  local path="$2"
  base="${base%/}"
  path="${path#/}"
  echo "${base}/${path}"
}

curl_auth_args() {
  # Only add auth if loaded
  if [ -n "${SA_USER:-}" ] && [ -n "${SA_PASS:-}" ]; then
    echo "--user" "${SA_USER}:${SA_PASS}"
  fi
}

wget_auth_args() {
  if [ -n "${SA_USER:-}" ] && [ -n "${SA_PASS:-}" ]; then
    echo "--user=${SA_USER}" "--password=${SA_PASS}"
  fi
}

head_content_length() {
  local url="$1"
  local len=""
  if command -v curl >/dev/null 2>&1; then
    # shellcheck disable=SC2046
    len="$(curl -fsI $(curl_auth_args) --connect-timeout "$NET_TIMEOUT" "$url" 2>/dev/null \
      | tr -d '\r' \
      | awk -F': ' 'tolower($1)=="content-length"{print $2; exit}')"
  fi
  if [[ "$len" =~ ^[0-9]+$ ]]; then
    echo "$len"
    return 0
  fi
  echo "0"
  return 0
}

download_url_to_file() {
  local url="$1"
  local out="$2"

  rm -f "$out" >/dev/null 2>&1

  if command -v curl >/dev/null 2>&1; then
    local tries=0
    while [ $tries -lt "$NET_TRIES" ]; do
      tries=$((tries+1))
      # shellcheck disable=SC2046
      curl -fL $(curl_auth_args) --connect-timeout "$NET_TIMEOUT" --max-time "$((NET_TIMEOUT*NET_TRIES))" \
        -o "$out" "$url" >/dev/null 2>&1 && [ -s "$out" ] && return 0
      rm -f "$out" >/dev/null 2>&1
    done
    return 1
  fi

  if command -v wget >/dev/null 2>&1; then
    local tries=0
    while [ $tries -lt "$NET_TRIES" ]; do
      tries=$((tries+1))
      # shellcheck disable=SC2046
      wget -q $(wget_auth_args) \
        --timeout="$NET_TIMEOUT" \
        --tries=1 \
        --dns-timeout="$NET_TIMEOUT" \
        --connect-timeout="$NET_TIMEOUT" \
        --read-timeout="$NET_TIMEOUT" \
        -O "$out" "$url" >/dev/null 2>&1
      [ $? -eq 0 ] && [ -s "$out" ] && return 0
      rm -f "$out" >/dev/null 2>&1
    done
  fi

  return 1
}

download_from_bases() {
  local rel="$1"
  local out="$2"
  local base url

  for base in "${UPDATE_BASE_URLS[@]}"; do
    [ -n "$base" ] || continue
    url="$(join_url "$base" "$rel")"
    if download_url_to_file "$url" "$out"; then
      log_update "Downloaded $(basename "$out") from $base"
      return 0
    fi
    log_update "Download failed from $base for $rel"
  done

  return 1
}

download_from_bases_with_progress() {
  # Emits gauge updates while downloading
  # args: rel out update_filename i total
  local rel="$1"
  local out="$2"
  local label="$3"
  local i="$4"
  local total="$5"

  local base url size cur subpct overall pid tick=0

  rm -f "$out" >/dev/null 2>&1

  for base in "${UPDATE_BASE_URLS[@]}"; do
    [ -n "$base" ] || continue
    url="$(join_url "$base" "$rel")"
    size="$(head_content_length "$url")"

    log_update "Downloading $label from $base (size_bytes=$size)"

    # Start download in background
    if command -v curl >/dev/null 2>&1; then
      # shellcheck disable=SC2046
      ( curl -fL $(curl_auth_args) --connect-timeout "$NET_TIMEOUT" --max-time "$((NET_TIMEOUT*NET_TRIES))" \
          -o "$out" "$url" >/dev/null 2>&1 ) &
      pid=$!
    else
      # shellcheck disable=SC2046
      ( wget -q $(wget_auth_args) \
          --timeout="$NET_TIMEOUT" --tries="$NET_TRIES" \
          --dns-timeout="$NET_TIMEOUT" --connect-timeout="$NET_TIMEOUT" --read-timeout="$NET_TIMEOUT" \
          -O "$out" "$url" >/dev/null 2>&1 ) &
      pid=$!
    fi

    # Progress loop
    while kill -0 "$pid" >/dev/null 2>&1; do
      sleep 1
      cur=0
      [ -f "$out" ] && cur="$(stat -c%s "$out" 2>/dev/null || echo 0)"

      if [ "$size" -gt 0 ] 2>/dev/null; then
        subpct=$(( cur * 100 / size ))
        [ "$subpct" -gt 99 ] && subpct=99
        overall=$(( (( (i-1) * 100 ) + subpct ) / total ))
        echo "$overall"
        echo "XXX"
        echo "Downloading $label ($i/$total)"
        echo "Received: $(human_bytes "$cur") / $(human_bytes "$size")"
        echo "XXX"
      else
        # Unknown size: show activity without lying about percent
        tick=$(( (tick + 7) % 90 ))
        overall=$(( (( (i-1) * 100 ) + tick ) / total ))
        echo "$overall"
        echo "XXX"
        echo "Downloading $label ($i/$total)"
        echo "Working... (size unknown)"
        echo "XXX"
      fi
    done

    wait "$pid"
    if [ $? -eq 0 ] && [ -s "$out" ]; then
      return 0
    fi

    rm -f "$out" >/dev/null 2>&1
    log_update "Download failed from $base for $rel (will try next mirror)"
  done

  return 1
}

# ----------------------------
# SHA256 helpers (CRLF-safe; no sha256sum -c filename dependency)
# ----------------------------

parse_sha256_file_first_hash() {
  local sha_file="$1"
  [ -f "$sha_file" ] || return 1
  awk 'NF>=1 {gsub(/\r/,""); print $1; exit}' "$sha_file" 2>/dev/null
}

get_saved_hash() {
  local fn="$1"
  [ -f "$HASH_LOG" ] || return 1
  awk -v f="$fn" '$1==f {print $2; exit}' "$HASH_LOG" 2>/dev/null
}

set_saved_hash() {
  local fn="$1"
  local h="$2"
  [ -z "$fn" ] && return 1
  [ -z "$h" ] && return 1

  mkdir -p "$(dirname "$HASH_LOG")" >/dev/null 2>&1
  touch "$HASH_LOG" >/dev/null 2>&1

  local tmp="/tmp/update_hashes_$$.tmp"
  awk -v f="$fn" '$1!=f' "$HASH_LOG" 2>/dev/null > "$tmp"
  printf "%s %s\n" "$fn" "$h" >> "$tmp"
  mv -f "$tmp" "$HASH_LOG" >/dev/null 2>&1

  chown pi:pi "$HASH_LOG" >/dev/null 2>&1
  chmod 644 "$HASH_LOG" >/dev/null 2>&1
}

verify_checksum_for_download() {
  # NOTE: no dialog popups here (safe inside gauge)
  local filename="$1"
  local tmpdir="$2"

  [ "$CHECKSUM_VERIFY_ENABLED" -ne 1 ] && return 0

  local checksum_path="$tmpdir/$filename.sha256"
  rm -f "$checksum_path" >/dev/null 2>&1

  if ! download_from_bases "$filename.sha256" "$checksum_path"; then
    log_update "Checksum download failed for $filename"
    return 1
  fi

  local expected actual
  expected="$(parse_sha256_file_first_hash "$checksum_path")"
  if ! [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    log_update "Checksum file invalid for $filename (expected hash not found)"
    return 1
  fi

  actual="$(sha256sum "$tmpdir/$filename" 2>/dev/null | awk '{print $1}')"
  if [ -z "$actual" ]; then
    log_update "Could not compute sha256 for $filename"
    return 1
  fi

  if [ "${actual,,}" != "${expected,,}" ]; then
    log_update "Checksum verification FAILED for $filename (expected=${expected,,} actual=${actual,,})"
    return 1
  fi

  log_update "Checksum verification PASSED for $filename"
  return 0
}

get_remote_hash() {
  local filename="$1"
  local sha_path="/tmp/$filename.sha256"
  rm -f "$sha_path" >/dev/null 2>&1
  if ! download_from_bases "$filename.sha256" "$sha_path"; then
    return 1
  fi
  parse_sha256_file_first_hash "$sha_path"
}

# ----------------------------
# Control files inside update pack
# ----------------------------

control_file_path() {
  local root="$1"
  local name="$2"
  local meta="$root/$META_DIR_NAME/$name"
  local legacy="$root/$name"
  if [ -f "$meta" ]; then echo "$meta"; return 0; fi
  if [ -f "$legacy" ]; then echo "$legacy"; return 0; fi
  return 1
}

is_safe_delete_path() {
  local p="$1"
  [[ "$p" == /* ]] || return 1
  [[ "$p" != "/" ]] || return 1
  [[ "$p" =~ (^|/)\.\.($|/) ]] && return 1
  return 0
}

process_delete_list() {
  local root="$1"
  local del_file line
  del_file="$(control_file_path "$root" "delete_list.txt")" || return 0

  log_update "Found delete list ($del_file). Processing deletes."
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    if ! is_safe_delete_path "$line"; then
      log_update "Rejected unsafe delete path: $line"
      return 1
    fi

    if [ -e "$line" ]; then
      log_update "Deleting: $line"
      rm -rf -- "$line" >/dev/null 2>&1 || return 1
    else
      log_update "Delete path not present (ok): $line"
    fi
  done < "$del_file"

  return 0
}

install_update_dependencies() {
  local root="$1"
  local dep_file line
  dep_file="$(control_file_path "$root" "dependencies.txt")" || return 0

  log_update "Found dependencies file ($dep_file). Installing dependencies."

  if ! command -v apt-get >/dev/null 2>&1; then
    log_update "apt-get not found; cannot install dependencies."
    return 1
  fi

  apt-get update >/dev/null 2>&1 || true

  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    log_update "Installing dependency: $line"
    apt-get install -y "$line" >/dev/null 2>&1 || return 1
  done < "$dep_file"

  return 0
}

# ----------------------------
# Version list + sequencing
# ----------------------------

fetch_updates() {
  log_update "Fetching update list (update_version_list.txt) from base URLs"
  if ! download_from_bases "update_version_list.txt" /tmp/update_version_list.txt; then
    log_update "Failed to fetch update list."
    show_message "Failed to fetch the update list.\n\nCheck WiFi/internet and update server availability."
    return 1
  fi
  return 0
}

get_available_updates() {
  grep -E '^[A-Za-z0-9._-]+\.tar\.gz$' /tmp/update_version_list.txt 2>/dev/null | tr -d '\r'
}

get_missing_updates() {
  local current="$1"; shift
  local all=("$@")
  local found=0
  local missing=()

  for u in "${all[@]}"; do
    if [ "$found" -eq 1 ]; then
      missing+=("$u")
    fi
    if [ "$u" = "$current" ]; then
      found=1
    fi
  done

  if [ "$found" -eq 0 ]; then
    missing=("${all[@]}")
  fi

  printf '%s\n' "${missing[@]}"
}

# ----------------------------
# Apply updates (no popups during gauge)
# ----------------------------

apply_updates() {
  local updates=("$@")
  [ ${#updates[@]} -eq 0 ] && return 1

  apply_dir_baselines

  (
    IN_GAUGE=1
    local i=0
    local total=${#updates[@]}

    for update in "${updates[@]}"; do
      i=$((i+1))

      echo $(( ( (i-1) * 100 ) / total ))
      echo "XXX"
      echo "Preparing update: $update ($i/$total)"
      echo "XXX"

      log_update "Processing update: $update"

      if ! is_valid_update_filename "$update"; then
        log_update "Invalid update filename rejected: $update"
        echo "100"; echo "XXX"; echo "Invalid update filename: $update"; echo "XXX"
        exit 1
      fi

      local tmp_update="/tmp/$update"
      rm -f "$tmp_update" "/tmp/$update.sha256" >/dev/null 2>&1

      # Download package WITH progress
      if ! download_from_bases_with_progress "$update" "$tmp_update" "$update" "$i" "$total"; then
        log_update "Failed to download $update"
        echo "100"; echo "XXX"; echo "Failed to download $update"; echo "XXX"
        exit 1
      fi

      # Verify checksum (no popups)
      if ! verify_checksum_for_download "$update" "/tmp"; then
        echo "100"; echo "XXX"; echo "Checksum failed for $update"; echo "XXX"
        exit 1
      fi

      local expected_hash
      expected_hash="$(parse_sha256_file_first_hash "/tmp/$update.sha256" 2>/dev/null || true)"

      if ! validate_tarball_safe "$tmp_update"; then
        log_update "Tarball safety validation failed for $update"
        echo "100"; echo "XXX"; echo "Invalid update package: $update"; echo "XXX"
        exit 1
      fi

      rm -rf "$TEMP_UPDATE_DIR" >/dev/null 2>&1
      mkdir -p "$TEMP_UPDATE_DIR" >/dev/null 2>&1

      echo $(( (( (i-1) * 100 ) + 99 ) / total ))
      echo "XXX"
      echo "Extracting $update ($i/$total)"
      echo "XXX"

      log_update "Extracting $update"
      tar -xzf "$tmp_update" -C "$TEMP_UPDATE_DIR" >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        log_update "Failed to extract $update"
        echo "100"; echo "XXX"; echo "Failed to extract $update"; echo "XXX"
        exit 1
      fi

      if ! install_update_dependencies "$TEMP_UPDATE_DIR"; then
        log_update "Dependency install failed for $update"
        echo "100"; echo "XXX"; echo "Dependencies failed for $update"; echo "XXX"
        exit 1
      fi

      log_update "Applying files to / (copy first)"
      rsync -rl \
        --exclude="${META_DIR_NAME}/" \
        --exclude="delete_list.txt" \
        --exclude="dependencies.txt" \
        "$TEMP_UPDATE_DIR/" / >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        log_update "rsync failed for $update"
        echo "100"; echo "XXX"; echo "Failed to apply $update"; echo "XXX"
        exit 1
      fi

      if ! process_delete_list "$TEMP_UPDATE_DIR"; then
        log_update "Delete list failed for $update"
        echo "100"; echo "XXX"; echo "Delete list failed for $update"; echo "XXX"
        exit 1
      fi

      apply_dir_baselines
      apply_file_permission_overrides

      # Ensure updater remains runnable
      if [ -f "$CUSTOM_SCRIPTS_DIR/update_system.sh" ]; then
        chown pi:pi "$CUSTOM_SCRIPTS_DIR/update_system.sh" >/dev/null 2>&1
        chmod 755 "$CUSTOM_SCRIPTS_DIR/update_system.sh" >/dev/null 2>&1
      fi

      # Record version + hash
      echo "$update" > "$LOCAL_VERSION_FILE"
      if [ -n "$expected_hash" ]; then
        set_saved_hash "$update" "$expected_hash"
      fi

      log_update "Update applied successfully: $update"
    done

    rm -rf "$TEMP_UPDATE_DIR" >/dev/null 2>&1
    echo "100"
    echo "XXX"
    echo "Updates complete"
    echo "XXX"
    exit 0
  ) | dialog --title "$DIALOG_TITLE" --gauge "Applying updates..." 12 72 0

  local rc=$?
  IN_GAUGE=0
  return $rc
}

# ----------------------------
# Self-update
# ----------------------------

self_update_if_needed() {
  [ "$SELF_UPDATE_ENABLED" -ne 1 ] && return 0

  local self_path
  self_path="$(readlink -f "$0" 2>/dev/null || true)"
  [ -z "$self_path" ] && return 0
  [ ! -f "$self_path" ] && return 0

  local tmp_script="/tmp/update_system.sh"
  rm -f "$tmp_script" "/tmp/update_system.sh.sha256" >/dev/null 2>&1

  if ! download_from_bases "$SELF_UPDATE_REL_PATH" "$tmp_script"; then
    rm -f "$tmp_script" >/dev/null 2>&1
    return 0
  fi

  if [ "$CHECKSUM_VERIFY_ENABLED" -eq 1 ]; then
    # Put the downloaded file where verify_checksum expects it
    cp -f "$tmp_script" "/tmp/update_system.sh" >/dev/null 2>&1
    if ! verify_checksum_for_download "update_system.sh" "/tmp"; then
      log_update "Updater checksum missing/failed. Skipping self-update."
      rm -f "$tmp_script" "/tmp/update_system.sh" "/tmp/update_system.sh.sha256" >/dev/null 2>&1
      return 0
    fi
  fi

  if ! cmp -s "$self_path" "$tmp_script" 2>/dev/null; then
    log_update "New updater detected. Installing and restarting updater."
    cp -f "$tmp_script" "$self_path" >/dev/null 2>&1
    chmod 755 "$self_path" >/dev/null 2>&1
    chown pi:pi "$self_path" >/dev/null 2>&1
    rm -f "$tmp_script" >/dev/null 2>&1
    exec bash "$self_path" "$@"
  fi

  rm -f "$tmp_script" >/dev/null 2>&1
  return 0
}

# ----------------------------
# Main menu (hash-aware reapply)
# ----------------------------

system_updates_menu() {
  ensure_file_exists "$LOCAL_VERSION_FILE" "11.0.0.tar.gz"
  ensure_file_exists "$HASH_LOG" ""
  apply_dir_baselines
  apply_file_permission_overrides

  if ! load_auth; then
    show_message "Missing or invalid auth file:\n\n$AUTH_FILE\n\nGen4 requires this to download updates."
    return 1
  fi

  self_update_if_needed

  while true; do
    local choice
    choice=$(dialog --title "$DIALOG_TITLE" --menu "Choose an option:" 14 72 6 \
      1 "Check for Updates" \
      2 "View Update Log" \
      3 "Exit" \
      3>&1 1>&2 2>&3)

    [ $? -ne 0 ] && break

    case "$choice" in
      1)
        log_update "User selected Check for Updates"

        if ! fetch_updates; then
          continue
        fi

        mapfile -t all_updates < <(get_available_updates)
        if [ ${#all_updates[@]} -eq 0 ]; then
          show_message "No updates found in update_version_list.txt"
          continue
        fi

        local current_version
        current_version="$(cat "$LOCAL_VERSION_FILE" 2>/dev/null | tr -d '\r')"
        [ -z "$current_version" ] && current_version="11.0.0.tar.gz"

        local latest="${all_updates[-1]}"

        # Standard missing updates
        mapfile -t missing < <(get_missing_updates "$current_version" "${all_updates[@]}")

        # Hash-aware: if current version exists but remote hash differs, prepend a "REVISED" reapply
        local reapply_current=0
        local saved_hash remote_hash
        saved_hash="$(get_saved_hash "$current_version" 2>/dev/null || true)"
        remote_hash="$(get_remote_hash "$current_version" 2>/dev/null || true)"

        if [ -n "$saved_hash" ] && [ -n "$remote_hash" ] && [ "${saved_hash,,}" != "${remote_hash,,}" ]; then
          reapply_current=1
        fi

        # If you are already on latest, but it was revised, offer reapply
        if [ "$current_version" = "$latest" ] && [ "$reapply_current" -eq 1 ]; then
          local msg="You are already on the latest version:\n\n$(clean_version_name "$latest")\n\nBut the update package was revised on the server.\n\nRecommended: Re-apply this update to receive the corrections."
          if dialog --title "$DIALOG_TITLE" --yesno "$msg" 16 72; then
            if apply_updates "$latest"; then
              show_message "Re-apply complete.\n\nNow on: $(clean_version_name "$latest")"
            else
              show_message "Failed to re-apply.\n\nPlease check the update log:\n$LOG_FILE"
            fi
          fi
          continue
        fi

        # Build checklist options
        local options=()
        local u desc status sz
        local list_to_offer=()

        # If current needs reapply and you're moving forward, apply it first
        if [ "$reapply_current" -eq 1 ] && [ "$current_version" != "$latest" ]; then
          list_to_offer+=("$current_version")
        fi

        # Then missing versions (normal path)
        if [ ${#missing[@]} -gt 0 ]; then
          for u in "${missing[@]}"; do
            list_to_offer+=("$u")
          done
        fi

        if [ ${#list_to_offer[@]} -eq 0 ]; then
          show_message "You are up to date.\n\nCurrent: $(clean_version_name "$current_version")"
          continue
        fi

        for u in "${list_to_offer[@]}"; do
          desc="$(clean_version_name "$u")"

          # Size (best effort)
          # try first base that returns a size
          sz="0"
          for base in "${UPDATE_BASE_URLS[@]}"; do
            [ -n "$base" ] || continue
            sz="$(head_content_length "$(join_url "$base" "$u")")"
            [ "$sz" != "0" ] && break
          done
          if [ "$sz" != "0" ]; then
            desc="$desc ($(human_bytes "$sz"))"
          fi

          status="on"
          if [ "$u" = "$current_version" ] && [ "$reapply_current" -eq 1 ]; then
            desc="$desc - REVISED (re-apply recommended)"
            status="on"
          fi

          options+=("$u" "$desc" "$status")
        done

        local selected
        selected=$(dialog --title "$DIALOG_TITLE" \
          --checklist "Select updates to apply:" 18 78 10 \
          "${options[@]}" \
          3>&1 1>&2 2>&3)

        [ $? -ne 0 ] && continue
        selected="$(echo "$selected" | tr -d '"')"
        [ -z "$selected" ] && continue

        local selected_updates=()
        for u in $selected; do
          selected_updates+=("$u")
        done

        if apply_updates "${selected_updates[@]}"; then
          show_message "Updates complete.\n\nNow on: $(clean_version_name "${selected_updates[-1]}")"
        else
          show_message "Failed to apply updates.\n\nPlease check the update log:\n$LOG_FILE"
        fi
        ;;
      2)
        if [ -f "$LOG_FILE" ]; then
          dialog --title "$DIALOG_TITLE" --textbox "$LOG_FILE" 22 80
        else
          show_message "Log not found:\n$LOG_FILE"
        fi
        ;;
      3)
        break
        ;;
    esac
  done
}

# ----------------------------
# Entrypoint
# ----------------------------

system_updates_menu
exit 0