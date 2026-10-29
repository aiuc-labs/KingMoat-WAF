#!/usr/bin/env bash
# KingMoat WAF — naming migration for CE installs (pre-v0.9.6 "kingmoat" → "kingmoatwaf")
#
# The CE layout already uses the kingmoatwaf binary, install dir and service
# name; what is still spelled "kingmoat" after an upgrade is the console
# SQLite file (kingmoat.db) and the environment-variable prefix inside
# /etc/kingmoatwaf/env. This script renames both, with backups, and restarts
# the service.
#
# Environment variables keep working under their legacy names: the binary
# reads KMWAF_* first and falls back to KINGMOAT_*, so a skipped migration
# still boots — it just keeps the old spelling on disk.
#
# Usage:
#   sudo bash deploy/migrate-naming.sh --dry-run   # print the plan only
#   sudo bash deploy/migrate-naming.sh             # execute
#
# Rollback: the script prints the backup location; restoring the unit file and
# the DB file from it (shown at the end) reverts the migration.
set -euo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

TS=$(date +%Y%m%d-%H%M%S)
UNIT="/etc/systemd/system/kingmoatwaf.service"
SVC="kingmoatwaf"
ENV_FILE="/etc/kingmoatwaf/env"
META_FILES=(/etc/kingmoatwaf-install.conf /etc/kingmoat-install.conf)
BACKUP_DIR=""

run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        echo "+ $*"
        "$@"
    fi
}

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || [[ $DRY_RUN == true ]] || die "must run as root"

# ---------------------------------------------------------------- layout
DATA_DIR=""
for f in "${META_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    line=$(grep -E '^DATA_DIR=' "$f" | head -1 || true)
    [[ -n "$line" ]] || continue
    DATA_DIR="${line#DATA_DIR=}"
    DATA_DIR="${DATA_DIR%\"}"
    DATA_DIR="${DATA_DIR#\"}"
    [[ -n "$DATA_DIR" ]] && break
done
[[ -n "$DATA_DIR" ]] || DATA_DIR="/var/lib/kingmoatwaf"

[[ -f "$UNIT" ]] || die "$UNIT not found: this is not a systemd one-click install"

log "unit=$UNIT service=$SVC data_dir=$DATA_DIR"

# ---------------------------------------------------------------- backup
if ! $DRY_RUN; then
    BACKUP_DIR="/var/backups/kingmoatwaf-naming-$TS"
    install -d -m 0755 "$BACKUP_DIR"
    cp -a "$UNIT" "$BACKUP_DIR/kingmoatwaf.service"
    [[ -f "$ENV_FILE" ]] && cp -a "$ENV_FILE" "$BACKUP_DIR/env"
fi

# ---------------------------------------------------------------- database
MOVED_DB=false
DB_OLD="$DATA_DIR/kingmoat.db"
DB_NEW="$DATA_DIR/kingmoatwaf.db"
if [[ -f "$DB_OLD" ]]; then
    if [[ -e "$DB_NEW" ]]; then
        log "both $DB_OLD and $DB_NEW exist; keeping both (no rename). Resolve manually if the new file is stale."
    else
        log "stopping $SVC to rename the database"
        $DRY_RUN || systemctl stop "$SVC"
        for suffix in "" "-wal" "-shm"; do
            if [[ -f "$DB_OLD$suffix" ]]; then
                run mv "$DB_OLD$suffix" "$DB_NEW$suffix"
            fi
        done
        MOVED_DB=true
    fi
else
    log "no $DB_OLD; nothing to rename"
fi

# ---------------------------------------------------------------- unit file
if grep -q -- '-console-db "'"$DATA_DIR"'/kingmoat\.db"' "$UNIT" 2>/dev/null; then
    log "updating -console-db in the unit file"
    $DRY_RUN || sed -i "s|-console-db \"$DATA_DIR/kingmoat\.db\"|-console-db \"$DATA_DIR/kingmoatwaf.db\"|" "$UNIT"
    $DRY_RUN && echo "[dry-run] sed -i s|-console-db \"$DATA_DIR/kingmoat.db\"|-console-db \"$DATA_DIR/kingmoatwaf.db\"| $UNIT"
    $DRY_RUN || systemctl daemon-reload
else
    log "unit file does not point at $DB_OLD; leaving it alone"
fi

# ---------------------------------------------------------------- env file
ENV_RENAMED=0
if [[ -f "$ENV_FILE" ]]; then
    ENV_RENAMED=$(grep -c '^KINGMOAT_' "$ENV_FILE" || true)
    if [[ "$ENV_RENAMED" != "0" ]]; then
        log "renaming $ENV_RENAMED KINGMOAT_* entries to KMWAF_* in $ENV_FILE"
        $DRY_RUN || sed -i 's/^KINGMOAT_/KMWAF_/' "$ENV_FILE"
    else
        log "no legacy KINGMOAT_* entries in $ENV_FILE"
    fi
else
    log "no $ENV_FILE; nothing to rename"
fi

# ---------------------------------------------------------------- restart
if $DRY_RUN; then
    log "dry-run complete; re-run without --dry-run to apply"
    exit 0
fi

log "restarting $SVC"
systemctl start "$SVC"
sleep 2
if systemctl is-active --quiet "$SVC"; then
    log "OK: $SVC is running"
else
    die "$SVC failed to start; restore $BACKUP_DIR/kingmoatwaf.service and the DB backup, then inspect journalctl -u $SVC"
fi

log "summary"
echo "    database: $DB_OLD -> $DB_NEW (moved: $MOVED_DB)"
echo "    env vars renamed: $ENV_RENAMED"
echo "    backups: $BACKUP_DIR"
echo ""
echo "Rollback (if anything looks wrong):"
echo "    systemctl stop $SVC"
echo "    cp -a $BACKUP_DIR/kingmoatwaf.service $UNIT && systemctl daemon-reload"
[[ -f "$BACKUP_DIR/env" ]] && echo "    cp -a $BACKUP_DIR/env $ENV_FILE"
echo "    mv $DB_NEW $DB_OLD   # plus -wal/-shm if they exist"
echo "    systemctl start $SVC"
