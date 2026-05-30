#!/bin/bash
set -euo pipefail

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/wall/backups/pg"
BACKUP_FILE="$BACKUP_DIR/wall_$DATE.sql.gz"
RETENTION_DAYS=7
LOG="/opt/wall/backups/backup.log"

echo "[$DATE] Starting backup..." >> $LOG

docker exec wall-postgres pg_dump -U wall_user -d paramant_wall | gzip > "$BACKUP_FILE"

SIZE=$(stat -c%s "$BACKUP_FILE")
if [ "$SIZE" -lt 1024 ]; then
  echo "[$DATE] ERROR: Backup te klein ($SIZE bytes)" >> $LOG
  exit 1
fi

echo "[$DATE] OK: $BACKUP_FILE ($SIZE bytes)" >> $LOG

find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

ls -lh "$BACKUP_DIR"/*.sql.gz 2>/dev/null >> $LOG
