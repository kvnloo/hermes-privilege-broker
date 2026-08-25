#!/usr/bin/env bash
set -euo pipefail

# Read-only planning aid for the known 4 TB source disk. It never invokes
# mkfs, wipefs, mount, umount, parted, dd, bcachefs format, or sudo.
EXPECTED_DISK=/dev/sdb
EXPECTED_PART=/dev/sdb2
EXPECTED_SERIAL=21410Y800564
EXPECTED_SIZE=4000787030016
EXPECTED_FS=btrfs
EXPECTED_MOUNT=/mnt/zer0models

die() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
for tool in lsblk findmnt df du stat timeout sort; do command -v "$tool" >/dev/null || die "missing read-only prerequisite: $tool"; done

actual_serial=$(lsblk -dn -o SERIAL "$EXPECTED_DISK" | tr -d '[:space:]')
actual_size=$(lsblk -bdn -o SIZE "$EXPECTED_DISK" | tr -d '[:space:]')
actual_fs=$(lsblk -dn -o FSTYPE "$EXPECTED_PART" | tr -d '[:space:]')
actual_source=$(findmnt -n -o SOURCE --target "$EXPECTED_MOUNT" || true)
[[ "$actual_serial" == "$EXPECTED_SERIAL" ]] || die "serial mismatch for $EXPECTED_DISK"
[[ "$actual_size" == "$EXPECTED_SIZE" ]] || die "size mismatch for $EXPECTED_DISK"
[[ "$actual_fs" == "$EXPECTED_FS" ]] || die "expected $EXPECTED_PART to remain $EXPECTED_FS"
[[ "$actual_source" == "$EXPECTED_PART" ]] || die "$EXPECTED_MOUNT is not mounted from $EXPECTED_PART"

printf 'READ-ONLY BCACHEFS MIGRATION DRY RUN\n'
printf 'source_disk=%s serial=%s bytes=%s\n' "$EXPECTED_DISK" "$actual_serial" "$actual_size"
printf 'source_partition=%s filesystem=%s mount=%s\n' "$EXPECTED_PART" "$actual_fs" "$EXPECTED_MOUNT"
df -B1 --output=source,size,used,avail,pcent,target "$EXPECTED_MOUNT"
printf '\nTop-level source usage (read-only; may take time):\n'
if ! timeout 30 du -x -B1 -d1 "$EXPECTED_MOUNT" 2>/dev/null | sort -n; then
    printf 'usage_scan=incomplete (bounded at 30 seconds)\n'
fi

cat <<'EOF'

NO-GO: bcachefs cannot be created in place on this mounted btrfs partition.
A migration requires independently verified backup capacity, byte/hash sampling,
an attended downtime plan, a separate target filesystem, restore verification,
and an explicit later root/reformat approval. This script intentionally emits
no destructive command and performs no unmount, format, conversion, or write.
EOF