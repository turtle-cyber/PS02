# Backend API Audit Report
**Date:** 2025-10-18
**Scope:** Complete Backend API review - all routes, error handling, and integrations

---

## Executive Summary

### 🔴 CRITICAL ISSUES: 4
### ⚠️ WARNING ISSUES: 8
### ✅ WORKING CORRECTLY: Most functionality

The Backend API is mostly well-implemented but has several **critical security and reliability issues** that need immediate attention.

---

## 🔴 CRITICAL ISSUES

### Issue #1: 🔴 Redis Connection Failures Not Handled Properly

**Affected Files:**
- `Backend/routes/dnstwist/dnstwist-stats.js:14`
- `Backend/routes/featureCrawler/fcrawler-stats.js:14`
- `Backend/routes/monitoring/monitoring-stats.js:14`
- `Backend/routes/url-detection.js` (uses ChromaDB client directly)

**Problem:**
```javascript
// Line 14 in multiple files
redisClient.connect().catch(console.error);
```

**Issues:**
1. Connection errors are logged but not fatal
2. No reconnection logic
3. API continues to serve requests even when Redis is down
4. Users get cryptic errors instead of proper 503 responses

**Impact:**
- ❌ APIs return 500 errors instead of 503 when Redis is down
- ❌ No automatic reconnection
- ❌ Silent failures - services appear "up" but are broken

**Current Behavior:**
```bash
# Redis down → API returns:
{
  "success": false,
  "error": "Failed to fetch DNSTwist statistics",
  "details": "Connection refused"
}
# Should return 503 Service Unavailable
```

**Fix Required:**
```javascript
// Add reconnection strategy
const redisClient = redis.createClient({
    socket: {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        reconnectStrategy: (retries) => {
            if (retries > 10) {
                return new Error('Redis connection failed after 10 retries');
            }
            return Math.min(retries * 100, 3000);
        }
    }
});

let isRedisConnected = false;

redisClient.on('connect', () => {
    isRedisConnected = true;
    console.log('✅ Redis connected');
});

redisClient.on('error', (err) => {
    isRedisConnected = false;
    console.error('❌ Redis error:', err);
});

// Middleware to check Redis health
function checkRedis(req, res, next) {
    if (!isRedisConnected) {
        return res.status(503).json({
            success: false,
            error: 'Service temporarily unavailable',
            details: 'Redis connection lost'
        });
    }
    next();
}

// Apply to all routes
router.use(checkRedis);
```

---

### Issue #2: 🔴 Path Traversal Vulnerability in Artifacts API

**Location:** `Backend/routes/artifacts/artifacts.js:18-23, 58-62, 99-103`

**Problem:**
```javascript
// Security check (lines 18-22)
if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({
        success: false,
        error: 'Invalid filename'
    });
}
```

**Vulnerabilities:**
1. ❌ **Incomplete path traversal protection** - Doesn't handle URL-encoded attacks
2. ❌ **No whitelist validation** - Accepts any non-traversal filename
3. ❌ **Exposed filesystem paths** - Returns full paths in error messages

**Attack Vectors:**
```bash
# URL encoding bypass
GET /api/artifacts/html/%2e%2e%2fconfig.json
GET /api/artifacts/html/..%2Fpasswd

# Null byte injection (older Node versions)
GET /api/artifacts/html/file.html%00../../etc/passwd

# Mixed encoding
GET /api/artifacts/html/%252e%252e/secrets.txt
```

**Fix Required:**
```javascript
// Safer path validation
const path = require('path');

function sanitizeFilename(filename) {
    // Remove any path separators
    const basename = path.basename(filename);

    // Validate filename format (alphanumeric, dash, underscore, dot only)
    const validPattern = /^[a-zA-Z0-9._-]+$/;
    if (!validPattern.test(basename)) {
        return null;
    }

    // Ensure file extension is allowed
    const ext = path.extname(basename).toLowerCase();
    const allowedExtensions = ['.html', '.pdf', '.png', '.jpg', '.jpeg'];
    if (!allowedExtensions.includes(ext)) {
        return null;
    }

    return basename;
}

router.get('/artifacts/html/:filename', (req, res) => {
    const filename = sanitizeFilename(req.params.filename);

    if (!filename) {
        return res.status(400).json({
            success: false,
            error: 'Invalid filename format'
        });
    }

    // Resolve absolute path and verify it's within allowed directory
    const filePath = path.resolve(ARTIFACTS_BASE_PATH, 'html', filename);
    const allowedDir = path.resolve(ARTIFACTS_BASE_PATH, 'html');

    if (!filePath.startsWith(allowedDir)) {
        return res.status(403).json({
            success: false,
            error: 'Access denied'
        });
    }

    // ... rest of code
});
```

---

### Issue #3: 🔴 Missing Rate Limiting on Critical Endpoints

**Location:** `Backend/server.js:99-104`

**Problem:**
```javascript
// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);  // ✅ Applied to /api/*
```

**Issues:**
1. ❌ **Same rate limit for ALL endpoints** - No per-endpoint limits
2. ❌ **100 requests/15min is TOO HIGH** for expensive operations
3. ❌ **No separate limit for bulk submissions** - Can DoS the pipeline

**Attack Scenarios:**
```bash
# Attacker can submit 100 URLs in 15 minutes
for i in {1..100}; do
  curl -X POST http://backend:3000/api/submit \
    -H "Content-Type: application/json" \
    -d '{"url": "test'$i'.com", "use_full_pipeline": true}'
done

# Each triggers DNSTwist (expensive!) → 100 * 3-5 minutes = 5-8 hours of processing
# Result: DoS attack with just 100 requests
```

**Fix Required:**
```javascript
// Different limits for different endpoint types
const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,  // Max 10 expensive operations per 15 min
    message: 'Too many submissions. Please wait before submitting more.'
});

const queryLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,  // Max 60 queries per minute
    message: 'Too many queries. Please slow down.'
});

const bulkLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 2,  // Max 2 bulk submissions per hour
    message: 'Bulk submissions limited to 2 per hour.'
});

// Apply different limits
app.post('/api/submit', strictLimiter, ...);
app.post('/api/submit-bulk', bulkLimiter, ...);
app.get('/api/chroma/*', queryLimiter, ...);
app.get('/api/dnstwist/*', queryLimiter, ...);
```

---

### Issue #4: 🔴 ChromaDB Collection Creation Race Condition

**Location:** `Backend/routes/urlDetection/url-detection.js:16-19`

**Problem:**
```javascript
const col = await client.getOrCreateCollection({
    name: 'domains',
    metadata: { "hnsw:space": "cosine" }
});
```

**Issues:**
1. ❌ **Creates collection on every request** - Race condition with ingestor
2. ❌ **No error handling** if collection exists with different metadata
3. ❌ **Conflicts with chroma-ingestor** which also creates collections

**Impact:**
- API might create collection before ingestor
- Ingestor creates collection with different settings
- Collections out of sync
- Potential data corruption

**Fix Required:**
```javascript
// Cache collection reference
let domainsCollection = null;

async function getDomainsCollection() {
    if (domainsCollection) {
        return domainsCollection;
    }

    try {
        // Try to get existing collection first
        domainsCollection = await chroma.getCollection({ name: 'domains' });
        return domainsCollection;
    } catch (error) {
        // Collection doesn't exist - this is an error state
        // Ingestor should create it, not the API
        throw new Error('ChromaDB collection not initialized. Wait for ingestor to start.');
    }
}

async function fetchData() {
    try {
        const col = await getDomainsCollection();
        const res = await col.get();
        // ... rest
    } catch (error) {
        if (error.message.includes('not initialized')) {
            throw new Error('Pipeline not ready. Please wait for initial data ingestion.');
        }
        throw error;
    }
}
```

---

## ⚠️ WARNING ISSUES

### Issue #5: ⚠️ No Input Validation on Query Parameters

**Location:** Multiple routes

**Problem:**
```javascript
// chroma-query.js:153
const limit = Math.min(parseInt(req.query.limit) || 10, 100);
const offset = parseInt(req.query.offset) || 0;
```

**Issues:**
1. ❌ `parseInt()` on user input without validation
2. ❌ No check for negative numbers
3. ❌ `NaN` becomes `0` silently

**Attack:**
```bash
GET /api/chroma/variants?limit=999999999999999999999  # Integer overflow
GET /api/chroma/variants?offset=-1  # Becomes 0, but should error
GET /api/chroma/variants?limit=abc  # Becomes 10, no error
```

**Fix:**
```javascript
function parsePositiveInt(value, defaultValue, max = Infinity) {
    const parsed = parseInt(value);
    if (isNaN(parsed) || parsed < 0) {
        return defaultValue;
    }
    return Math.min(parsed, max);
}

const limit = parsePositiveInt(req.query.limit, 10, 100);
const offset = parsePositiveInt(req.query.offset, 0);
```

---

### Issue #6: ⚠️ Unhandled Promise Rejections in Redis Calls

**Location:** All Redis route files

**Problem:**
```javascript
// dnstwist-stats.js:38
const totalProcessed = await redisClient.get(TOTAL_KEY) || 0;
```

**Issues:**
1. ❌ No try/catch around individual Redis calls
2. ❌ One failed Redis call crashes entire endpoint
3. ❌ No graceful degradation

**Impact:**
If Redis goes down mid-request:
```
Error: Connection lost
  at Redis.get (...)
  → Entire endpoint returns 500
```

**Fix:**
```javascript
async function safeRedisGet(key, defaultValue = null) {
    try {
        return await redisClient.get(key) || defaultValue;
    } catch (error) {
        console.error(`Redis GET failed for ${key}:`, error);
        return defaultValue;
    }
}

const totalProcessed = await safeRedisGet(TOTAL_KEY, 0);
```

---

### Issue #7: ⚠️ Memory Leak in dnstwist-stats.js Search

**Location:** `Backend/routes/dnstwist/dnstwist-stats.js:222`

**Problem:**
```javascript
// Get all domains from history
const allDomains = await redisClient.zRange(HISTORY_KEY, 0, -1, { REV: true });

// Filter domains that match the query
const matchingDomains = allDomains.filter(domain =>
    domain.toLowerCase().includes(q.toLowerCase())
);
```

**Issues:**
1. ❌ **Loads ALL domains into memory** (could be 10,000+)
2. ❌ **No pagination on allDomains** - loads entire sorted set
3. ❌ **O(n) search** on potentially huge dataset

**Impact:**
```bash
# If 10,000 domains in history:
GET /api/dnstwist/search?q=com
→ Loads 10,000 domains into memory
→ Filters all 10,000
→ Returns only 100
→ Waste of 99% of memory and CPU
```

**Fix:**
```javascript
// Use Redis SCAN with pattern matching
const { cursor, keys } = await redisClient.scan(0, {
    MATCH: `dnstwist:variants:*${q}*`,
    COUNT: 100
});

// Or limit the initial fetch
const recentDomains = await redisClient.zRange(HISTORY_KEY, 0, 999, { REV: true });
```

---

### Issue #8: ⚠️ Missing CORS Origin Validation

**Location:** `Backend/server.js:94`

**Problem:**
```javascript
app.use(cors());  // ❌ Allows ALL origins
```

**Issues:**
1. ❌ **Wide-open CORS** - Any website can call the API
2. ❌ **No origin whitelist**
3. ❌ **Enables CSRF attacks**

**Attack:**
```html
<!-- Evil website evil.com -->
<script>
fetch('http://your-backend:3000/api/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        url: 'attacker.com',
        use_full_pipeline: true
    })
});
// Victim's browser sends request → Pipeline processes attacker's URL
</script>
```

**Fix:**
```javascript
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:4173',  // Frontend in dev
            'http://frontend:4173',   // Frontend in Docker
            process.env.FRONTEND_URL  // Production frontend
        ].filter(Boolean);

        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
};

app.use(cors(corsOptions));
```

---

### Issue #9: ⚠️ No Request Body Size Limit

**Location:** `Backend/server.js:95-96`

**Problem:**
```javascript
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
```

**Issues:**
1. ❌ **No size limit** - Accepts unlimited JSON payload
2. ❌ **DoS vector** - Can crash server with huge payloads

**Attack:**
```bash
# Send 1GB JSON payload
curl -X POST http://backend:3000/api/submit-bulk \
  -H "Content-Type: application/json" \
  -d "$(python3 -c 'print("{\"urls\":[" + ",".join(["\"test.com\""]*10000000) + "]}")')"
# → Server runs out of memory and crashes
```

**Fix:**
```javascript
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
```

---

### Issue #10: ⚠️ Error Messages Leak Implementation Details

**Location:** Multiple routes

**Problem:**
```javascript
// artifacts.js:32
return res.status(404).json({
    success: false,
    error: 'File not found',
    path: filename  // ❌ Leaks internal filename
});

// server.js:372
error: 'Failed to submit domain for analysis',
details: error.message  // ❌ May leak database errors, stack traces
```

**Issues:**
1. ❌ **Information disclosure** - Reveals internal paths
2. ❌ **Stack traces in production** - Helps attackers
3. ❌ **Database schema leakage** - Error messages reveal table names

**Fix:**
```javascript
// Production-safe error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error', {
        error: err.message,
        stack: err.stack,
        path: req.path
    });

    // Generic error for production
    const isDev = process.env.NODE_ENV === 'development';
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        ...(isDev && { details: err.message, stack: err.stack })  // Only in dev
    });
});
```

---

### Issue #11: ⚠️ No Health Check for Dependencies

**Location:** `Backend/server.js:161-175`

**Problem:**
```javascript
app.get('/health', (req, res) => {
    const health = {
        status: producerReady ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        kafka: {
            connected: producerReady,
            brokers: KAFKA_BROKERS,
            topic: KAFKA_TOPIC
        }
    };
    // ❌ Only checks Kafka, not Redis or ChromaDB
});
```

**Issues:**
1. ❌ **Doesn't check Redis** - May be down but health returns OK
2. ❌ **Doesn't check ChromaDB** - May be down but health returns OK
3. ❌ **False positive health status**

**Fix:**
```javascript
app.get('/health', async (req, res) => {
    const checks = {
        kafka: producerReady,
        redis: false,
        chromadb: false
    };

    // Check Redis
    try {
        await redisClient.ping();
        checks.redis = true;
    } catch (e) {
        checks.redis = false;
    }

    // Check ChromaDB
    try {
        await chromaClient.heartbeat();
        checks.chromadb = true;
    } catch (e) {
        checks.chromadb = false;
    }

    const allHealthy = Object.values(checks).every(v => v);

    res.status(allHealthy ? 200 : 503).json({
        status: allHealthy ? 'healthy' : 'degraded',
        checks,
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});
```

---

### Issue #12: ⚠️ No Timeout on ChromaDB Queries

**Location:** `Backend/routes/chroma/chroma-query.js` (all query endpoints)

**Problem:**
```javascript
const results = await collection.get({
    where: Object.keys(where).length > 0 ? where : undefined,
    limit: limit,
    offset: offset,
    include: ['metadatas', 'documents']
});
// ❌ No timeout - can hang forever
```

**Impact:**
- Large collections take >30 seconds to query
- No timeout → request hangs forever
- Uses up Node.js event loop threads

**Fix:**
```javascript
function withTimeout(promise, ms) {
    return Promise.race([
        promise,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Request timeout')), ms)
        )
    ]);
}

const results = await withTimeout(
    collection.get({...}),
    10000  // 10 second timeout
);
```

---

## ✅ THINGS WORKING CORRECTLY

1. ✅ **Kafka Integration** - Producer properly initialized with retries
2. ✅ **Logging** - Winston logger well-configured
3. ✅ **Graceful Shutdown** - SIGTERM handled correctly
4. ✅ **Route Organization** - Clean separation by feature
5. ✅ **Error Handling** - Try/catch blocks in most places
6. ✅ **Redis Key Naming** - Consistent schema across routes
7. ✅ **ChromaDB Collections** - Proper use of originals vs variants
8. ✅ **Artifact Serving** - Correct Content-Type headers

---

## Summary Statistics

### Issues by Severity
| Severity | Count | Issues |
|----------|-------|--------|
| 🔴 CRITICAL | 4 | Redis failures, Path traversal, Rate limiting, Collection race |
| ⚠️ WARNING | 8 | Input validation, Promise rejections, Memory leak, CORS, Size limits, Error leakage, Health checks, Timeouts |
| ✅ WORKING | 8 | Kafka, logging, shutdown, routes, error handling, Redis schema, ChromaDB, artifacts |

### Security Score: 6/10
- ❌ Path traversal vulnerability (CRITICAL)
- ❌ Wide-open CORS (HIGH)
- ❌ No request size limits (HIGH)
- ❌ Information disclosure in errors (MEDIUM)
- ✅ Helmet configured
- ✅ Rate limiting present (but needs tuning)

### Reliability Score: 7/10
- ❌ Redis failures not handled (CRITICAL)
- ❌ No reconnection strategy (HIGH)
- ❌ Memory leak in search (MEDIUM)
- ❌ No query timeouts (MEDIUM)
- ✅ Graceful shutdown
- ✅ Good error handling structure
- ✅ Proper logging

---

## Recommended Fixes Priority

### Immediate (Deploy Today)
1. **Fix path traversal vulnerability** - Security critical
2. **Add reconnection strategy for Redis** - Reliability critical
3. **Add per-endpoint rate limiting** - Prevent DoS
4. **Fix CORS to whitelist origins** - Security

### This Week
5. **Add input validation** - Security + reliability
6. **Fix memory leak in search** - Reliability
7. **Add health checks for all dependencies** - Ops visibility
8. **Add query timeouts** - Reliability

### Next Sprint
9. **Fix collection race condition** - Data integrity
10. **Add request size limits** - DoS prevention
11. **Sanitize error messages** - Security
12. **Add promise rejection handlers** - Reliability

---

## Testing Recommendations

### Security Testing
```bash
# Test path traversal
curl http://localhost:3001/api/artifacts/html/..%2F..%2Fetc%2Fpasswd

# Test CORS
curl -H "Origin: http://evil.com" http://localhost:3001/api/submit

# Test rate limiting
for i in {1..200}; do curl http://localhost:3001/api/submit & done
```

### Load Testing
```bash
# Test memory leak
ab -n 1000 -c 10 'http://localhost:3001/api/dnstwist/search?q=com'

# Test Redis failure handling
docker stop redis && curl http://localhost:3001/api/dnstwist/stats
```

---

**All Backend API issues documented. Recommended to fix critical issues before production deployment.**
