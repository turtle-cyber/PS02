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
    console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
    console.log('Redis client connected successfully');
});

// Redis keys (matching scheduler.py schema)
const MONITOR_QUEUE = "monitoring:queue";  // Active monitoring (suspicious/parked)
const INACTIVE_QUEUE = "monitoring:inactive";  // Inactive/unregistered domains
const MONITOR_META_PREFIX = "monitoring:meta:";
const INACTIVE_META_PREFIX = "monitoring:meta:inactive:";

/**
 * GET /api/monitoring/stats
 * Returns comprehensive monitoring statistics
 */
router.get('/monitoring/stats', async (req, res) => {
    try {
        // Get counts from Redis sorted sets
        const activeCount = await redisClient.zCard(MONITOR_QUEUE);
        const inactiveCount = await redisClient.zCard(INACTIVE_QUEUE);
        const totalMonitoring = activeCount + inactiveCount;

        // Get all active monitoring domains (optional, can be limited)
        const activeDomains = await redisClient.zRange(MONITOR_QUEUE, 0, -1);

        // Get all inactive monitoring domains
        const inactiveDomains = await redisClient.zRange(INACTIVE_QUEUE, 0, -1);

        // Get monitoring details for a sample (first 10 of each)
        const activeDetails = [];
        for (let i = 0; i < Math.min(10, activeDomains.length); i++) {
            const domain = activeDomains[i];
            const score = await redisClient.zScore(MONITOR_QUEUE, domain);
            const meta = await redisClient.hGetAll(`${MONITOR_META_PREFIX}${domain}`);
            activeDetails.push({
                domain,
                next_check_timestamp: parseInt(score),
                next_check_date: new Date(parseInt(score) * 1000).toISOString(),
                ...meta
            });
        }

        const inactiveDetails = [];
        for (let i = 0; i < Math.min(10, inactiveDomains.length); i++) {
            const domain = inactiveDomains[i];
            const score = await redisClient.zScore(INACTIVE_QUEUE, domain);
            const meta = await redisClient.hGetAll(`${INACTIVE_META_PREFIX}${domain}`);
            inactiveDetails.push({
                domain,
                next_check_timestamp: parseInt(score),
                next_check_date: new Date(parseInt(score) * 1000).toISOString(),
                ...meta
            });
        }

        res.json({
            success: true,
            summary: {
                total_monitoring: totalMonitoring,
                active_monitoring: activeCount,
                inactive_monitoring: inactiveCount
            },
            details: {
                active_domains: {
                    count: activeCount,
                    sample: activeDetails,
                    description: "Suspicious/parked domains being monitored for 90 days"
                },
                inactive_domains: {
                    count: inactiveCount,
                    sample: inactiveDetails,
                    description: "Unregistered/inactive domains being monitored for registration/activation"
                }
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching monitoring stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch monitoring statistics',
            details: error.message
        });
    }
});

/**
 * GET /api/monitoring/active
 * Returns count and list of actively monitored domains (suspicious/parked)
 */
router.get('/monitoring/active', async (req, res) => {
    try {
        const count = await redisClient.zCard(MONITOR_QUEUE);
        const limit = parseInt(req.query.limit) || 100;
        const offset = parseInt(req.query.offset) || 0;

        // Get domains with scores (next check timestamps)
        const domains = await redisClient.zRangeWithScores(MONITOR_QUEUE, offset, offset + limit - 1);

        const results = await Promise.all(
            domains.map(async (item) => {
                const meta = await redisClient.hGetAll(`${MONITOR_META_PREFIX}${item.value}`);
                return {
                    domain: item.value,
                    next_check_timestamp: parseInt(item.score),
                    next_check_date: new Date(parseInt(item.score) * 1000).toISOString(),
                    verdict: meta.verdict,
                    monitor_reason: meta.monitor_reason,
                    recheck_count: parseInt(meta.recheck_count || '0'),
                    url: meta.url,
                    first_seen: meta.first_seen
                };
            })
        );

        res.json({
            success: true,
            message: 'Active monitoring queue retrieved successfully',
            total_count: count,
            returned_count: results.length,
            offset: offset,
            limit: limit,
            data: results,
            description: "Domains flagged as suspicious or parked, being monitored for 90 days",
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching active monitoring:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch active monitoring data',
            details: error.message
        });
    }
});

/**
 * GET /api/monitoring/inactive
 * Returns count and list of inactive/unregistered domains being monitored
 */
router.get('/monitoring/inactive', async (req, res) => {
    try {
        const count = await redisClient.zCard(INACTIVE_QUEUE);
        const limit = parseInt(req.query.limit) || 100;
        const offset = parseInt(req.query.offset) || 0;

        // Get domains with scores (next check timestamps)
        const domains = await redisClient.zRangeWithScores(INACTIVE_QUEUE, offset, offset + limit - 1);

        const results = await Promise.all(
            domains.map(async (item) => {
                const meta = await redisClient.hGetAll(`${INACTIVE_META_PREFIX}${item.value}`);
                return {
                    domain: item.value,
                    next_check_timestamp: parseInt(item.score),
                    next_check_date: new Date(parseInt(item.score) * 1000).toISOString(),
                    status: meta.status,
                    cse_id: meta.cse_id,
                    seed: meta.seed,
                    reasons: meta.reasons,
                    check_count: parseInt(meta.check_count || '0'),
                    first_seen: meta.first_seen
                };
            })
        );

        res.json({
            success: true,
            message: 'Inactive monitoring queue retrieved successfully',
            total_count: count,
            returned_count: results.length,
            offset: offset,
            limit: limit,
            data: results,
            description: "Unregistered or inactive domains being monitored for registration/activation",
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching inactive monitoring:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch inactive monitoring data',
            details: error.message
        });
    }
});

/**
 * GET /api/monitoring/domain/:domain
 * Get monitoring details for a specific domain
 */
router.get('/monitoring/domain/:domain', async (req, res) => {
    try {
        const { domain } = req.params;

        // Check in active monitoring
        const activeScore = await redisClient.zScore(MONITOR_QUEUE, domain);
        const activeMeta = await redisClient.hGetAll(`${MONITOR_META_PREFIX}${domain}`);

        // Check in inactive monitoring
        const inactiveScore = await redisClient.zScore(INACTIVE_QUEUE, domain);
        const inactiveMeta = await redisClient.hGetAll(`${INACTIVE_META_PREFIX}${domain}`);

        if (!activeScore && !inactiveScore) {
            return res.status(404).json({
                success: false,
                message: 'Domain not found in monitoring queues',
                domain: domain
            });
        }

        const response = {
            success: true,
            domain: domain,
            monitoring_type: activeScore ? 'active' : 'inactive',
            timestamp: new Date().toISOString()
        };

        if (activeScore) {
            response.active_monitoring = {
                next_check_timestamp: parseInt(activeScore),
                next_check_date: new Date(parseInt(activeScore) * 1000).toISOString(),
                ...activeMeta
            };
        }

        if (inactiveScore) {
            response.inactive_monitoring = {
                next_check_timestamp: parseInt(inactiveScore),
                next_check_date: new Date(parseInt(inactiveScore) * 1000).toISOString(),
                ...inactiveMeta
            };
        }

        res.json(response);

    } catch (error) {
        console.error('Error fetching domain monitoring details:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch domain monitoring details',
            details: error.message
        });
    }
});

module.exports = router;
