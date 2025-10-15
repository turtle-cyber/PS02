const express = require('express');
const redis = require('redis');
const router = express.Router();

// Redis client setup
const redisClient = redis.createClient({
    socket: {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT || '6379')
    }
});

// Connect to Redis
redisClient.connect().catch(console.error);

redisClient.on('error', (err) => {
    console.error('Redis Client Error (DNSTwist Stats):', err);
});

redisClient.on('connect', () => {
    console.log('Redis client connected successfully (DNSTwist Stats)');
});

// Redis keys (matching runner_continuous.py schema)
const VARIANTS_PREFIX = "dnstwist:variants:";
const UNREGISTERED_PREFIX = "dnstwist:unregistered:";
const TIMESTAMP_PREFIX = "dnstwist:timestamp:";
const HISTORY_KEY = "dnstwist:history";
const TOTAL_KEY = "dnstwist:total_processed";

/**
 * GET /api/dnstwist/stats
 * Returns comprehensive DNSTwist statistics
 */
router.get('/dnstwist/stats', async (req, res) => {
    try {
        // Get total processed count
        const totalProcessed = await redisClient.get(TOTAL_KEY) || 0;

        // Get count of entries in history
        const historyCount = await redisClient.zCard(HISTORY_KEY);

        // Get recent 10 domains
        const recentDomains = await redisClient.zRangeWithScores(
            HISTORY_KEY,
            0,
            9,
            { REV: true }
        );

        // Get details for recent domains
        const recentDetails = await Promise.all(
            recentDomains.map(async (item) => {
                const domain = item.value;
                const timestamp = parseInt(item.score);
                const variants = await redisClient.get(`${VARIANTS_PREFIX}${domain}`) || 0;
                const unregistered = await redisClient.get(`${UNREGISTERED_PREFIX}${domain}`) || 0;

                return {
                    domain,
                    variants_count: parseInt(variants),
                    unregistered_count: parseInt(unregistered),
                    processed_at: timestamp,
                    processed_date: new Date(timestamp * 1000).toISOString()
                };
            })
        );

        // Calculate aggregate stats
        let totalVariants = 0;
        let totalUnregistered = 0;

        for (const item of recentDetails) {
            totalVariants += item.variants_count;
            totalUnregistered += item.unregistered_count;
        }

        res.json({
            success: true,
            summary: {
                total_domains_processed: parseInt(totalProcessed),
                domains_in_history: historyCount,
                recent_total_variants: totalVariants,
                recent_total_unregistered: totalUnregistered
            },
            recent_domains: recentDetails,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching DNSTwist stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch DNSTwist statistics',
            details: error.message
        });
    }
});

/**
 * GET /api/dnstwist/domain/:domain
 * Get variant count for a specific domain
 */
router.get('/dnstwist/domain/:domain', async (req, res) => {
    try {
        const { domain } = req.params;

        // Get stats from Redis
        const variants = await redisClient.get(`${VARIANTS_PREFIX}${domain}`);
        const unregistered = await redisClient.get(`${UNREGISTERED_PREFIX}${domain}`);
        const timestamp = await redisClient.get(`${TIMESTAMP_PREFIX}${domain}`);

        if (!variants && !timestamp) {
            return res.status(404).json({
                success: false,
                message: 'Domain not found in DNSTwist processing history',
                domain: domain
            });
        }

        const variantsCount = parseInt(variants) || 0;
        const unregisteredCount = parseInt(unregistered) || 0;
        const processedAt = parseInt(timestamp) || 0;

        res.json({
            success: true,
            domain: domain,
            variants_count: variantsCount,
            unregistered_count: unregisteredCount,
            total_generated: variantsCount + unregisteredCount,
            processed_at: processedAt,
            processed_date: new Date(processedAt * 1000).toISOString(),
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching domain stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch domain statistics',
            details: error.message
        });
    }
});

/**
 * GET /api/dnstwist/recent
 * Get recently processed domains with variant counts
 */
router.get('/dnstwist/recent', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;

        // Get recent domains from sorted set (reverse chronological)
        const domains = await redisClient.zRangeWithScores(
            HISTORY_KEY,
            offset,
            offset + limit - 1,
            { REV: true }
        );

        // Get details for each domain
        const results = await Promise.all(
            domains.map(async (item) => {
                const domain = item.value;
                const timestamp = parseInt(item.score);
                const variants = await redisClient.get(`${VARIANTS_PREFIX}${domain}`) || 0;
                const unregistered = await redisClient.get(`${UNREGISTERED_PREFIX}${domain}`) || 0;

                return {
                    domain,
                    variants_count: parseInt(variants),
                    unregistered_count: parseInt(unregistered),
                    total_generated: parseInt(variants) + parseInt(unregistered),
                    processed_at: timestamp,
                    processed_date: new Date(timestamp * 1000).toISOString()
                };
            })
        );

        // Get total count
        const totalCount = await redisClient.zCard(HISTORY_KEY);

        res.json({
            success: true,
            message: 'Recently processed domains retrieved successfully',
            total_count: totalCount,
            returned_count: results.length,
            offset: offset,
            limit: limit,
            data: results,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching recent domains:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch recent domains',
            details: error.message
        });
    }
});

/**
 * GET /api/dnstwist/search
 * Search for domains by partial match
 */
router.get('/dnstwist/search', async (req, res) => {
    try {
        const { q } = req.query;

        if (!q || q.length < 2) {
            return res.status(400).json({
                success: false,
                error: 'Query parameter "q" must be at least 2 characters'
            });
        }

        // Get all domains from history
        const allDomains = await redisClient.zRange(HISTORY_KEY, 0, -1, { REV: true });

        // Filter domains that match the query
        const matchingDomains = allDomains.filter(domain =>
            domain.toLowerCase().includes(q.toLowerCase())
        );

        // Get details for matching domains (limit to 100)
        const results = await Promise.all(
            matchingDomains.slice(0, 100).map(async (domain) => {
                const variants = await redisClient.get(`${VARIANTS_PREFIX}${domain}`) || 0;
                const unregistered = await redisClient.get(`${UNREGISTERED_PREFIX}${domain}`) || 0;
                const timestamp = await redisClient.get(`${TIMESTAMP_PREFIX}${domain}`) || 0;

                return {
                    domain,
                    variants_count: parseInt(variants),
                    unregistered_count: parseInt(unregistered),
                    total_generated: parseInt(variants) + parseInt(unregistered),
                    processed_at: parseInt(timestamp),
                    processed_date: new Date(parseInt(timestamp) * 1000).toISOString()
                };
            })
        );

        res.json({
            success: true,
            query: q,
            total_matches: matchingDomains.length,
            returned_count: results.length,
            data: results,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error searching domains:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to search domains',
            details: error.message
        });
    }
});

/**
 * GET /api/dnstwist/status/:domain
 * Get processing status for a specific domain
 */
router.get('/dnstwist/status/:domain', async (req, res) => {
    try {
        const { domain } = req.params;

        // Get status
        const status = await redisClient.get(`dnstwist:status:${domain}`);

        // Get progress if processing
        const progress = await redisClient.hGetAll(`dnstwist:progress:${domain}`);

        // Get completion stats if completed
        const variants = await redisClient.get(`dnstwist:variants:${domain}`);
        const unregistered = await redisClient.get(`dnstwist:unregistered:${domain}`);
        const timestamp = await redisClient.get(`dnstwist:timestamp:${domain}`);

        const response = {
            success: true,
            domain,
            status: status || 'not_found',
            timestamp: new Date().toISOString()
        };

        // Add progress info if processing
        if (status === 'processing' && progress && progress.started_at) {
            const startedAt = parseInt(progress.started_at);
            const elapsedSeconds = Math.floor(Date.now() / 1000) - startedAt;

            response.progress = {
                current_pass: progress.current_pass || 'unknown',
                started_at: startedAt,
                started_date: new Date(startedAt * 1000).toISOString(),
                elapsed_seconds: elapsedSeconds,
                cse_id: progress.cse_id
            };
        }

        // Add completion info if completed
        if (status === 'completed') {
            response.result = {
                variants_count: parseInt(variants) || 0,
                unregistered_count: parseInt(unregistered) || 0,
                total_generated: (parseInt(variants) || 0) + (parseInt(unregistered) || 0),
                completed_at: parseInt(timestamp) || 0,
                completed_date: new Date(parseInt(timestamp) * 1000).toISOString()
            };
        }

        res.json(response);

    } catch (error) {
        console.error('Error fetching domain status:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch domain status',
            details: error.message
        });
    }
});

/**
 * GET /api/dnstwist/queue
 * Get currently processing domains
 */
router.get('/dnstwist/queue', async (req, res) => {
    try {
        // Get all domains in active queue
        const activeQueue = await redisClient.zRangeWithScores('dnstwist:queue:active', 0, -1);

        const processing = await Promise.all(
            activeQueue.map(async (item) => {
                const domain = item.value;
                const startedAt = parseInt(item.score);
                const elapsedSeconds = Math.floor(Date.now() / 1000) - startedAt;

                // Get progress
                const progress = await redisClient.hGetAll(`dnstwist:progress:${domain}`);

                return {
                    domain,
                    started_at: startedAt,
                    started_date: new Date(startedAt * 1000).toISOString(),
                    elapsed_seconds: elapsedSeconds,
                    current_pass: progress.current_pass || 'unknown',
                    cse_id: progress.cse_id || 'unknown'
                };
            })
        );

        res.json({
            success: true,
            active_count: processing.length,
            processing: processing,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching queue:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch processing queue',
            details: error.message
        });
    }
});

/**
 * GET /api/dnstwist/current
 * Get the currently processing domain (oldest in queue)
 */
router.get('/dnstwist/current', async (req, res) => {
    try {
        // Get oldest domain in active queue (first to start = currently processing)
        const activeQueue = await redisClient.zRangeWithScores('dnstwist:queue:active', 0, 0);

        if (activeQueue.length === 0) {
            return res.json({
                success: true,
                is_processing: false,
                current: null,
                message: 'No domains currently being processed',
                timestamp: new Date().toISOString()
            });
        }

        const domain = activeQueue[0].value;
        const startedAt = parseInt(activeQueue[0].score);
        const elapsedSeconds = Math.floor(Date.now() / 1000) - startedAt;
        const progress = await redisClient.hGetAll(`dnstwist:progress:${domain}`);

        // Check if variants have been generated (if completed)
        const variants = await redisClient.get(`${VARIANTS_PREFIX}${domain}`);
        const unregistered = await redisClient.get(`${UNREGISTERED_PREFIX}${domain}`);
        const status = await redisClient.get(`dnstwist:status:${domain}`);

        const response = {
            success: true,
            is_processing: true,
            current: {
                domain,
                started_at: startedAt,
                started_date: new Date(startedAt * 1000).toISOString(),
                elapsed_seconds: elapsedSeconds,
                current_pass: progress.current_pass || 'unknown',
                cse_id: progress.cse_id || 'unknown'
            },
            timestamp: new Date().toISOString()
        };

        // Add variant counts if available (as soon as they're stored in Redis)
        if (variants) {
            response.current.variants_generated = {
                registered: parseInt(variants) || 0,
                unregistered: parseInt(unregistered) || 0,
                total: (parseInt(variants) || 0) + (parseInt(unregistered) || 0)
            };
        }

        res.json(response);
    } catch (error) {
        console.error('Error fetching current processing:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch current processing domain',
            details: error.message
        });
    }
});

module.exports = router;
