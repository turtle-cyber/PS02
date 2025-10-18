# Monitoring Configuration Guide

## Overview

The phishing detection pipeline includes a **90-day monitoring system** that automatically tracks suspicious and parked domains, re-crawling them periodically to detect when they transition from inactive to active phishing sites.

---

## Configuration Files

### 1. **Rule Scorer Configuration**
**File**: [`infra/docker-compose.yml`](infra/docker-compose.yml)

**Service**: `rule-scorer`

```yaml
rule-scorer:
  environment:
    # Risk scoring thresholds
    - THRESH_PHISHING=70      # Score ≥70 = phishing
    - THRESH_SUSPICIOUS=40    # Score 40-69 = suspicious
    - THRESH_PARKED=28        # Parked detection threshold

    # Monitoring toggles
    - MONITOR_SUSPICIOUS=true  # Enable monitoring for suspicious domains
    - MONITOR_PARKED=true      # Enable monitoring for parked domains
    - MONITOR_DAYS=90          # Days to monitor before re-check
```

#### Parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `THRESH_PHISHING` | 70 | Minimum score for phishing verdict |
| `THRESH_SUSPICIOUS` | 40 | Minimum score for suspicious verdict |
| `THRESH_PARKED` | 28 | Minimum parked score to flag domain |
| `MONITOR_SUSPICIOUS` | true | Enable 90-day monitoring for suspicious domains |
| `MONITOR_PARKED` | true | Enable 90-day monitoring for parked domains |
| `MONITOR_DAYS` | 90 | Number of days to monitor before automatic re-crawl |

**How to change monitoring period:**
```bash
# Change from 90 days to 30 days
- MONITOR_DAYS=30

# Change to 180 days (6 months)
- MONITOR_DAYS=180

# Disable monitoring completely
- MONITOR_SUSPICIOUS=false
- MONITOR_PARKED=false
```

---

### 2. **Monitor Scheduler Configuration**
**File**: [`infra/docker-compose.yml`](infra/docker-compose.yml)

**Service**: `monitor-scheduler`

```yaml
monitor-scheduler:
  environment:
    # Kafka settings
    - KAFKA_BOOTSTRAP=kafka:9092
    - VERDICTS_TOPIC=phish.rules.verdicts  # Input topic
    - OUTPUT_TOPIC=raw.hosts               # Re-queue topic

    # Redis settings
    - REDIS_HOST=redis
    - REDIS_PORT=6379

    # Monitoring behavior
    - MONITOR_CHECK_INTERVAL=86400  # Check every 24 hours (seconds)
    - MAX_RECHECKS=3                # Maximum re-checks per domain
```

#### Parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MONITOR_CHECK_INTERVAL` | 86400 | How often to check for expired domains (seconds) |
| `MAX_RECHECKS` | 3 | Maximum number of times to re-crawl a domain |
| `VERDICTS_TOPIC` | phish.rules.verdicts | Kafka topic to consume verdicts from |
| `OUTPUT_TOPIC` | raw.hosts | Where to re-queue expired domains |
| `REDIS_HOST` | redis | Redis host for monitoring queue |
| `REDIS_PORT` | 6379 | Redis port |

**How to change check frequency:**
```bash
# Check every 12 hours
- MONITOR_CHECK_INTERVAL=43200

# Check every hour (for testing)
- MONITOR_CHECK_INTERVAL=3600

# Check every week
- MONITOR_CHECK_INTERVAL=604800
```

**How to change max rechecks:**
```bash
# Only re-check once
- MAX_RECHECKS=1

# Re-check up to 5 times
- MAX_RECHECKS=5

# Unlimited rechecks (not recommended)
- MAX_RECHECKS=999
```

---

## Quick Configuration Examples

### Example 1: Aggressive Monitoring (30 days, check daily)
```yaml
rule-scorer:
  environment:
    - MONITOR_DAYS=30
    - MONITOR_SUSPICIOUS=true
    - MONITOR_PARKED=true

monitor-scheduler:
  environment:
    - MONITOR_CHECK_INTERVAL=86400
    - MAX_RECHECKS=5
```

### Example 2: Conservative Monitoring (180 days, check weekly)
```yaml
rule-scorer:
  environment:
    - MONITOR_DAYS=180
    - MONITOR_SUSPICIOUS=true
    - MONITOR_PARKED=false  # Don't monitor parked domains

monitor-scheduler:
  environment:
    - MONITOR_CHECK_INTERVAL=604800  # 7 days
    - MAX_RECHECKS=2
```

### Example 3: Testing Mode (1 day, check hourly)
```yaml
rule-scorer:
  environment:
    - MONITOR_DAYS=1
    - MONITOR_SUSPICIOUS=true
    - MONITOR_PARKED=true

monitor-scheduler:
  environment:
    - MONITOR_CHECK_INTERVAL=3600  # 1 hour
    - MAX_RECHECKS=10
```

### Example 4: Disable Monitoring Completely
```yaml
rule-scorer:
  environment:
    - MONITOR_SUSPICIOUS=false
    - MONITOR_PARKED=false
```

**Note**: If you disable monitoring, you should also stop the monitor-scheduler service:
```bash
docker-compose stop monitor-scheduler
```

---

## Applying Configuration Changes

1. **Edit the configuration file**:
   ```bash
   cd infra
   nano docker-compose.yml  # or use your preferred editor
   ```

2. **Restart the affected services**:
   ```bash
   # For rule-scorer changes
   docker-compose restart rule-scorer

   # For monitor-scheduler changes
   docker-compose restart monitor-scheduler

   # Or restart both
   docker-compose restart rule-scorer monitor-scheduler
   ```

3. **Verify changes**:
   ```bash
   # Check rule-scorer logs
   docker logs rule-scorer | head -20

   # Check monitor-scheduler logs
   docker logs monitor-scheduler | head -20
   ```

---

## Monitoring Redis Queue

### View Monitored Domains
```bash
# Connect to Redis
docker exec -it redis redis-cli

# List all monitored domains
ZRANGE monitoring:queue 0 -1 WITHSCORES

# Count monitored domains
ZCARD monitoring:queue

# Get metadata for a specific domain
HGETALL monitoring:meta:example.com
```

### Manual Operations
```bash
# Add a domain to monitoring queue manually
ZADD monitoring:queue 1735689600 example.com

# Remove a domain from monitoring
ZREM monitoring:queue example.com
DEL monitoring:meta:example.com

# Clear all monitoring data
DEL monitoring:queue
KEYS monitoring:meta:* | xargs DEL
```

---

## Logs and Debugging

### Rule Scorer Logs
```bash
docker logs -f rule-scorer
```

Look for lines like:
```
[scorer] example.com: parked (monitoring: True)
[scorer] test.com: suspicious (monitoring: True)
```

### Monitor Scheduler Logs
```bash
docker logs -f monitor-scheduler
```

Look for lines like:
```
[monitor] Added example.com to monitoring queue (reason: parked, until: 1735689600)
[monitor] Found 5 expired domains to re-check
[monitor] Re-queued example.com (recheck #1)
[monitor] Queue size: 42 domains
```

### ChromaDB Ingestor Logs
```bash
docker logs -f chroma-ingestor
```

Look for verdicts being ingested:
```
[ingestor] Received message 123 (verdict): example.com [parked:0] monitoring=True
```

---

## Environment Variable Reference

### Time Conversions
```
1 hour    = 3600 seconds
12 hours  = 43200 seconds
1 day     = 86400 seconds
1 week    = 604800 seconds
30 days   = 2592000 seconds
90 days   = 7776000 seconds
180 days  = 15552000 seconds
```

### Common Monitoring Periods
| Use Case | MONITOR_DAYS | CHECK_INTERVAL | MAX_RECHECKS |
|----------|--------------|----------------|--------------|
| Production | 90 | 86400 (1 day) | 3 |
| Aggressive | 30 | 43200 (12 hours) | 5 |
| Conservative | 180 | 604800 (7 days) | 2 |
| Testing | 1 | 3600 (1 hour) | 10 |

---

## FAQ

### Q: How do I change from 90 days to 60 days?
**A**: Edit [`infra/docker-compose.yml`](infra/docker-compose.yml), find `rule-scorer` service, change `MONITOR_DAYS=90` to `MONITOR_DAYS=60`, then run:
```bash
cd infra
docker-compose restart rule-scorer
```

### Q: Can I monitor only suspicious domains, not parked ones?
**A**: Yes, set `MONITOR_PARKED=false` in rule-scorer:
```yaml
- MONITOR_SUSPICIOUS=true
- MONITOR_PARKED=false
```

### Q: How do I see what domains are currently being monitored?
**A**: Connect to Redis and query:
```bash
docker exec -it redis redis-cli ZRANGE monitoring:queue 0 -1
```

### Q: What happens after MAX_RECHECKS is reached?
**A**: The domain is removed from the monitoring queue and won't be automatically re-checked again.

### Q: Can I manually trigger a re-check?
**A**: Yes, re-submit the domain via the frontend API or directly to the `raw.hosts` Kafka topic.

### Q: Does changing MONITOR_DAYS affect existing monitored domains?
**A**: No, existing domains keep their original expiry timestamp. Only newly monitored domains use the new setting.

---

## Advanced: Programmatic Configuration

For advanced users, you can configure monitoring via environment variables at runtime:

```bash
# Run with custom monitoring period
docker run -e MONITOR_DAYS=45 -e MONITOR_SUSPICIOUS=true rule-scorer

# Override via docker-compose CLI
MONITOR_DAYS=120 docker-compose up rule-scorer
```

Or create a `.env` file in the `infra/` directory:
```bash
# infra/.env
MONITOR_DAYS=60
MONITOR_CHECK_INTERVAL=43200
MAX_RECHECKS=5
```

Then reference in `docker-compose.yml`:
```yaml
rule-scorer:
  environment:
    - MONITOR_DAYS=${MONITOR_DAYS:-90}
```

---

## Summary

**To change monitoring from 90 days to something else:**

1. Open [`infra/docker-compose.yml`](infra/docker-compose.yml)
2. Find the `rule-scorer` service
3. Change `MONITOR_DAYS=90` to your desired value
4. Run: `docker-compose restart rule-scorer`

**Example**:
```yaml
rule-scorer:
  environment:
    - MONITOR_DAYS=30  # Changed from 90 to 30 days
```

All configuration is centralized in `docker-compose.yml` for easy management.
