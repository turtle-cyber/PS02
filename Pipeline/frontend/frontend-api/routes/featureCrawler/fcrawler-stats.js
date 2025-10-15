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
    console.error('Redis Client Error (Feature Crawler Stats):', err);
});

redisClient.on('connect', () => {
    console.log('Redis client connected successfully (Feature Crawler Stats)');
});

/**
 * GET /api/fcrawler/seed/:seed
 * Get crawling progress for a specific seed domain
 */
router.get('/fcrawler/seed/:seed', async (req, res) => {
    try {
        const { seed } = req.params;

        // Get progress stats from Redis
        const total = await redisClient.get(`fcrawler:seed:${seed}:total`);
        const crawled = await redisClient.get(`fcrawler:seed:${seed}:crawled`);
        const failed = await redisClient.get(`fcrawler:seed:${seed}:failed`);
        const status = await redisClient.get(`fcrawler:seed:${seed}:status`);
        const lastCrawled = await redisClient.get(`fcrawler:seed:${seed}:last_crawled`);
        const completedAt = await redisClient.get(`fcrawler:seed:${seed}:completed_at`);

        if (!total) {
            return res.status(404).json({
                success: false,
                message: 'Seed domain not found in feature crawler tracking',
                seed: seed
            });
        }

        const totalVariants = parseInt(total) || 0;
        const crawledCount = parseInt(crawled) || 0;
        const failedCount = parseInt(failed) || 0;
        const pendingCount = totalVariants - crawledCount - failedCount;
        const percentage = totalVariants > 0 ? ((crawledCount / totalVariants) * 100).toFixed(2) : 0;

        const response = {
            success: true,
            seed: seed,
            progress: {
                total_variants: totalVariants,
                crawled: crawledCount,
                failed: failedCount,
                pending: pendingCount,
                percentage: parseFloat(percentage),
                status: status || 'unknown'
            },
            timestamp: new Date().toISOString()
        };

        if (lastCrawled) {
            response.progress.last_crawled_at = parseInt(lastCrawled);
            response.progress.last_crawled_date = new Date(parseInt(lastCrawled) * 1000).toISOString();
        }

        if (completedAt) {
            response.progress.completed_at = parseInt(completedAt);
            response.progress.completed_date = new Date(parseInt(completedAt) * 1000).toISOString();
        }

        res.json(response);

    } catch (error) {
        console.error('Error fetching seed progress:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch seed progress',
            details: error.message
        });
    }
});

/**
 * GET /api/fcrawler/active
 * Get all seeds currently being crawled
 */
router.get('/fcrawler/active', async (req, res) => {
    try {
        // Get all active seeds from sorted set
        const activeSeeds = await redisClient.zRangeWithScores('fcrawler:active_seeds', 0, -1, { REV: true });

        const seeds = await Promise.all(
            activeSeeds.map(async (item) => {
                const seed = item.value;
                const lastActivity = parseInt(item.score);

                const total = await redisClient.get(`fcrawler:seed:${seed}:total`);
                const crawled = await redisClient.get(`fcrawler:seed:${seed}:crawled`);
                const failed = await redisClient.get(`fcrawler:seed:${seed}:failed`);
                const status = await redisClient.get(`fcrawler:seed:${seed}:status`);

                const totalVariants = parseInt(total) || 0;
                const crawledCount = parseInt(crawled) || 0;
                const failedCount = parseInt(failed) || 0;
                const percentage = totalVariants > 0 ? ((crawledCount / totalVariants) * 100).toFixed(2) : 0;

                return {
                    seed,
                    total: totalVariants,
                    crawled: crawledCount,
                    failed: failedCount,
                    pending: totalVariants - crawledCount - failedCount,
                    percentage: parseFloat(percentage),
                    status: status || 'unknown',
                    last_activity: lastActivity,
                    last_activity_date: new Date(lastActivity * 1000).toISOString()
                };
            })
        );

        res.json({
            success: true,
            active_count: seeds.length,
            seeds: seeds,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching active seeds:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch active seeds',
            details: error.message
        });
    }
});

/**
 * GET /api/fcrawler/completed
 * Get recently completed seeds
 */
router.get('/fcrawler/completed', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;

        // Get all seeds from dnstwist history
        const allSeeds = await redisClient.zRange('dnstwist:history', 0, -1, { REV: true });

        // Filter for completed seeds
        const completedSeeds = [];
        for (const seed of allSeeds.slice(0, limit * 2)) {  // Check 2x limit to ensure we have enough completed ones
            const status = await redisClient.get(`fcrawler:seed:${seed}:status`);
            if (status === 'completed') {
                const total = await redisClient.get(`fcrawler:seed:${seed}:total`);
                const crawled = await redisClient.get(`fcrawler:seed:${seed}:crawled`);
                const failed = await redisClient.get(`fcrawler:seed:${seed}:failed`);
                const completedAt = await redisClient.get(`fcrawler:seed:${seed}:completed_at`);

                completedSeeds.push({
                    seed,
                    total: parseInt(total) || 0,
                    crawled: parseInt(crawled) || 0,
                    failed: parseInt(failed) || 0,
                    completed_at: parseInt(completedAt) || 0,
                    completed_date: new Date(parseInt(completedAt) * 1000).toISOString()
                });

                if (completedSeeds.length >= limit) break;
            }
        }

        res.json({
            success: true,
            completed_count: completedSeeds.length,
            seeds: completedSeeds,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching completed seeds:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch completed seeds',
            details: error.message
        });
    }
});

/**
 * GET /api/fcrawler/stats
 * Get overall feature crawler statistics
 */
router.get('/fcrawler/stats', async (req, res) => {
    try {
        // Get active seeds count
        const activeCount = await redisClient.zCard('fcrawler:active_seeds');

        // Get a few recent seeds for summary
        const recentSeeds = await redisClient.zRange('dnstwist:history', 0, 9, { REV: true });

        let totalVariants = 0;
        let totalCrawled = 0;
        let totalFailed = 0;
        let completedCount = 0;

        for (const seed of recentSeeds) {
            const total = parseInt(await redisClient.get(`fcrawler:seed:${seed}:total`) || 0);
            const crawled = parseInt(await redisClient.get(`fcrawler:seed:${seed}:crawled`) || 0);
            const failed = parseInt(await redisClient.get(`fcrawler:seed:${seed}:failed`) || 0);
            const status = await redisClient.get(`fcrawler:seed:${seed}:status`);

            totalVariants += total;
            totalCrawled += crawled;
            totalFailed += failed;
            if (status === 'completed') completedCount++;
        }

        res.json({
            success: true,
            summary: {
                active_seeds: activeCount,
                recent_completed_seeds: completedCount,
                recent_total_variants: totalVariants,
                recent_crawled: totalCrawled,
                recent_failed: totalFailed,
                recent_pending: totalVariants - totalCrawled - totalFailed
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching fcrawler stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch feature crawler statistics',
            details: error.message
        });
    }
});

module.exports = router;
