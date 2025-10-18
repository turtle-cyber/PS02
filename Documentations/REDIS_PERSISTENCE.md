# Redis Persistence Configuration

## Problem

Previously, Redis data (including feature-crawler tracking counters) was lost whenever you ran:
- `docker-compose down -v` (removes volumes)
- `docker-compose down` (removes container, non-persistent data lost)

This meant all tracking progress was reset:
- `fcrawler:seed:{seed}:total` - Lost ❌
- `fcrawler:seed:{seed}:crawled` - Lost ❌
- `fcrawler:seed:{seed}:failed` - Lost ❌
- All deduplication keys - Lost ❌

## Solution

We've configured Redis with **persistent storage** using:
1. **Docker volume mount** → Data survives container removal
2. **AOF (Append-Only File) persistence** → Data survives Redis crashes

## Changes Made

### 1. Updated `docker-compose.yml` (lines 43-54)

```yaml
redis:
  image: redis:7
  container_name: redis
  ports: ["6379:6379"]
  volumes:
    - ../volumes/redis:/data                                    # ✅ NEW: Persistent volume
  command: redis-server --appendonly yes --appendfsync everysec  # ✅ NEW: AOF persistence
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 5s
    timeout: 3s
    retries: 10
```

**What this does:**
- `volumes`: Maps host directory `Pipeline/volumes/redis/` to container's `/data`
- `--appendonly yes`: Enable AOF persistence mode
- `--appendfsync everysec`: Sync to disk every second (balance between performance and safety)

### 2. Updated `.gitignore` (line 30)

```gitignore
Pipeline/volumes/redis/*
```

This excludes Redis data files from git (they can be large and contain runtime data).

## How It Works

### AOF (Append-Only File) Persistence

Redis now writes **every write operation** to a log file:

```
Pipeline/volumes/redis/
  ├── appendonlydir/
  │   ├── appendonly.aof.1.base.rdb  # Base snapshot
  │   ├── appendonly.aof.1.incr.aof  # Incremental changes
  │   └── appendonly.aof.manifest    # Manifest file
  └── dump.rdb                        # Optional RDB snapshot
```

**Sync modes available:**
- `always` - Sync after every write (slow, safest)
- `everysec` - Sync every second (balanced, we use this) ✅
- `no` - Let OS decide when to sync (fast, less safe)

### Data Lifecycle

**Before (non-persistent):**
```
Start Redis → Write data → Stop container → Data LOST ❌
```

**After (persistent):**
```
Start Redis → Write data → Stop container → Data SAVED ✅
Restart Redis → Data RESTORED ✅
```

## Testing Persistence

### Test 1: Verify Volume is Created

```bash
# Check the volume directory exists
ls -la Pipeline/volumes/redis/

# After Redis starts, you should see:
# appendonlydir/
# appendonly.aof.manifest
# dump.rdb (if RDB snapshots enabled)
```

### Test 2: Test docker-compose down (without -v)

```bash
# Step 1: Set some data
docker exec -it redis redis-cli SET test_key "test_value"
docker exec -it redis redis-cli GET test_key
# Output: "test_value"

# Step 2: Stop containers (WITHOUT -v flag)
cd Pipeline/infra
docker-compose down

# Step 3: Start containers again
docker-compose up -d

# Step 4: Check data is still there
docker exec -it redis redis-cli GET test_key
# Output: "test_value" ✅ Data survived!
```

### Test 3: Test docker-compose down -v (DANGER!)

```bash
# WARNING: -v flag DELETES named volumes but NOT bind mounts!

# Our setup uses BIND MOUNT (../volumes/redis:/data)
# So even with -v, data should survive!

# Step 1: Set data
docker exec -it redis redis-cli SET test_key2 "test_value2"

# Step 2: Stop and remove volumes
docker-compose down -v

# Step 3: Start again
docker-compose up -d

# Step 4: Check data
docker exec -it redis redis-cli GET test_key2
# Output: "test_value2" ✅ Data survived because we use bind mount!
```

### Test 4: Test Feature-Crawler Tracking Persistence

```bash
# Step 1: Submit a domain and let it process
curl -X POST http://localhost:3001/api/submit -H "Content-Type: application/json" -d '{"domain": "test.com"}'

# Step 2: Check progress
curl http://localhost:3001/api/fcrawler/seed/test.com | jq

# Step 3: Stop containers
docker-compose down

# Step 4: Restart
docker-compose up -d

# Step 5: Check progress again
curl http://localhost:3001/api/fcrawler/seed/test.com | jq

# ✅ Progress should be preserved!
```

## Backup and Restore

### Manual Backup

```bash
# Stop Redis to ensure consistent backup
docker-compose stop redis

# Backup the entire volume
cd Pipeline/volumes
tar -czf redis-backup-$(date +%Y%m%d-%H%M%S).tar.gz redis/

# Restart Redis
cd ../infra
docker-compose start redis
```

### Restore from Backup

```bash
# Stop Redis
docker-compose stop redis

# Remove current data
rm -rf Pipeline/volumes/redis/*

# Extract backup
cd Pipeline/volumes
tar -xzf redis-backup-YYYYMMDD-HHMMSS.tar.gz

# Restart Redis
cd ../infra
docker-compose start redis
```

### Automated Backup Script

Create `Pipeline/scripts/backup-redis.sh`:

```bash
#!/bin/bash
BACKUP_DIR="$HOME/redis-backups"
mkdir -p "$BACKUP_DIR"

cd "$(dirname "$0")/../infra"

echo "Stopping Redis..."
docker-compose stop redis

echo "Creating backup..."
tar -czf "$BACKUP_DIR/redis-backup-$(date +%Y%m%d-%H%M%S).tar.gz" \
  -C ../volumes redis/

echo "Starting Redis..."
docker-compose start redis

echo "Backup complete!"
ls -lh "$BACKUP_DIR" | tail -5
```

## Monitoring Persistence

### Check AOF Status

```bash
docker exec -it redis redis-cli INFO persistence

# Look for:
# aof_enabled:1                     # ✅ AOF is enabled
# aof_rewrite_in_progress:0         # No rewrite happening
# aof_last_write_status:ok          # ✅ Last write succeeded
# aof_current_size:1234             # Current AOF size
```

### Check Disk Usage

```bash
# Check Redis volume size
du -sh Pipeline/volumes/redis/

# Check available disk space
df -h Pipeline/volumes/redis/
```

### Monitor Write Performance

```bash
# Watch Redis stats
docker exec -it redis redis-cli --stat

# Watch AOF syncs
docker logs -f redis | grep -i aof
```

## Troubleshooting

### Issue: Redis won't start after restore

**Symptom:**
```
redis | AOF file appendonly.aof.1.incr.aof is corrupted
redis | Fatal error loading the DB
```

**Solution:**
```bash
# Try to fix the AOF file
docker run --rm -v "$(pwd)/Pipeline/volumes/redis:/data" redis:7 \
  redis-check-aof --fix /data/appendonlydir/appendonly.aof.1.incr.aof

# Restart Redis
docker-compose restart redis
```

### Issue: Data not persisting

**Check volume mount:**
```bash
docker inspect redis | jq '.[0].Mounts'

# Should show:
# {
#   "Type": "bind",
#   "Source": ".../Pipeline/volumes/redis",
#   "Destination": "/data",
#   "RW": true
# }
```

**Check AOF is enabled:**
```bash
docker exec -it redis redis-cli CONFIG GET appendonly
# Should return: 1) "appendonly" 2) "yes"
```

**Check write permissions:**
```bash
ls -la Pipeline/volumes/redis/
# Should be writable by Redis user (usually 999)

# Fix permissions if needed
sudo chown -R 999:999 Pipeline/volumes/redis/
```

### Issue: High disk usage

**Trigger AOF rewrite:**
```bash
docker exec -it redis redis-cli BGREWRITEAOF

# This compacts the AOF file by removing redundant operations
```

**Monitor rewrite progress:**
```bash
docker exec -it redis redis-cli INFO persistence | grep aof_rewrite
```

## Performance Considerations

### AOF vs RDB

Our configuration uses **AOF (Append-Only File)**:

**Advantages:**
- ✅ Better durability (data loss limited to 1 second with `everysec`)
- ✅ Log is append-only (no seek, no corruption in case of power failure)
- ✅ Automatic rewrite when AOF gets too big

**Disadvantages:**
- ❌ Larger files than RDB
- ❌ Slower than RDB depending on fsync policy

**RDB (disabled by default in our setup):**
- Faster for large datasets
- Less durable (can lose data since last snapshot)
- Smaller files

### Sync Policy Trade-offs

| Policy | Safety | Performance | Data Loss Risk |
|--------|--------|-------------|----------------|
| `always` | Highest | Slowest | None (except hardware failure) |
| `everysec` | High | Good | Up to 1 second ✅ |
| `no` | Low | Fastest | Unknown (depends on OS) |

We use `everysec` as a balance between durability and performance.

## Configuration Options

You can customize Redis persistence by modifying the `command` in docker-compose.yml:

```yaml
# Current (balanced)
command: redis-server --appendonly yes --appendfsync everysec

# Maximum safety (slower)
command: redis-server --appendonly yes --appendfsync always

# Maximum performance (less safe)
command: redis-server --appendonly yes --appendfsync no

# Enable both AOF and RDB
command: >
  redis-server
  --appendonly yes
  --appendfsync everysec
  --save 900 1
  --save 300 10
  --save 60 10000
```

## Summary

✅ **Before**: Redis data lost on `docker-compose down`
✅ **After**: Redis data persists across restarts
✅ **Storage**: `Pipeline/volumes/redis/` (bind mount)
✅ **Mode**: AOF with `everysec` sync
✅ **Safety**: Up to 1 second of data loss in worst case
✅ **Performance**: Minimal impact (writes buffered)

Your feature-crawler tracking data is now safe! 🎉

## Quick Reference

```bash
# Check persistence status
docker exec -it redis redis-cli INFO persistence

# Check data directory
ls -la Pipeline/volumes/redis/

# Backup Redis data
docker-compose stop redis
tar -czf redis-backup.tar.gz Pipeline/volumes/redis/
docker-compose start redis

# Restore Redis data
docker-compose stop redis
rm -rf Pipeline/volumes/redis/*
tar -xzf redis-backup.tar.gz
docker-compose start redis

# Test persistence
docker exec -it redis redis-cli SET test "value"
docker-compose restart redis
docker exec -it redis redis-cli GET test  # Should return "value"
```
