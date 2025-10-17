const express = require('express');
const { client: redisClient, isRedisReady } = require('../../utils/redisClient');
const router = express.Router();

/**
 * GET /api/live-monitoring/current-scan-progress
 * Returns current scanning progress with ETA calculation
 *
 * Response:
 * {
 *   "success": true,
 *   "total_urls": 1134,
 *   "processed": 567,
 *   "percentage": 50.0,
 *   "status": "processing",
 *   "eta_minutes": 47,
 *   "eta_calculation_method": "redis_crawl_rate",
 *   "currently_processing": {
 *     "domain": "example.com",
 *     "current_pass": "B",
 *     "elapsed_seconds": 45,
 *     "type": "dnstwist"
 *   }
 * }
 */
router.get('/live-monitoring/current-scan-progress', async (req, res) => {
    try {
        // Check Redis availability
        if (!isRedisReady()) {
            return res.status(503).json({
                success: false,
                error: 'Redis not available. Please try again later.',
                timestamp: new Date().toISOString()
            });
        }

        console.log('[current-scan] Fetching scan progress...');

        let totalUrls = 0;
        let processedUrls = 0;
        let currentlyProcessing = null;
        let etaMinutes = 0;
        let etaMethod = 'fallback_average';

        // Get all feature crawler seeds
        const seedKeys = await redisClient.keys('fcrawler:seed:*:total');

        console.log('[current-scan] Found', seedKeys.length, 'seed keys');

        if (seedKeys.length > 0) {
            // Aggregate totals across all seeds (filter out completed ones)
            for (const key of seedKeys) {
                // Extract domain from key: fcrawler:seed:{domain}:total
                const parts = key.split(':');
                if (parts.length >= 4) {
                    const domain = parts[2];

                    const total = parseInt(await redisClient.get(`fcrawler:seed:${domain}:total`)) || 0;
                    const crawled = parseInt(await redisClient.get(`fcrawler:seed:${domain}:crawled`)) || 0;
                    const status = await redisClient.get(`fcrawler:seed:${domain}:status`);

                    // Skip completed seeds
                    if (status === 'completed' || crawled >= total) {
                        console.log(`[current-scan] Skipping completed seed: ${domain} (${crawled}/${total}, status: ${status})`);
                        continue;
                    }

                    totalUrls += total;
                    processedUrls += crawled;
                }
            }

            console.log('[current-scan] Active seeds aggregated:', {
                total: totalUrls,
                processed: processedUrls
            });

            // Calculate ETA using Redis crawl metrics
            if (totalUrls > 0 && processedUrls > 0) {
                // Get the most recent active seed for timing calculation
                const firstSeedKey = seedKeys[0];
                const parts = firstSeedKey.split(':');
                const domain = parts[2];

                // Try to get started_at timestamp from dnstwist progress
                const progressData = await redisClient.hGetAll(`dnstwist:progress:${domain}`);

                if (progressData && progressData.started_at) {
                    const startedAt = parseInt(progressData.started_at);
                    const now = Math.floor(Date.now() / 1000);
                    const elapsedSeconds = now - startedAt;
                    const elapsedMinutes = elapsedSeconds / 60;

                    if (elapsedMinutes > 0) {
                        // Calculate processing rate (URLs per minute)
                        const urlsPerMinute = processedUrls / elapsedMinutes;

                        if (urlsPerMinute > 0) {
                            const remaining = totalUrls - processedUrls;
                            etaMinutes = Math.ceil(remaining / urlsPerMinute);
                            etaMethod = 'redis_crawl_rate';

                            console.log('[current-scan] ETA calculation (Redis):', {
                                elapsed_minutes: elapsedMinutes.toFixed(2),
                                urls_per_minute: urlsPerMinute.toFixed(2),
                                remaining: remaining,
                                eta_minutes: etaMinutes
                            });
                        }
                    }
                }
            }

            // Fallback ETA calculation if Redis method failed
            if (etaMethod === 'fallback_average' && totalUrls > 0 && processedUrls > 0) {
                const AVG_SECONDS_PER_URL = 5; // Historical average
                const remaining = totalUrls - processedUrls;
                etaMinutes = Math.ceil((remaining * AVG_SECONDS_PER_URL) / 60);

                console.log('[current-scan] ETA calculation (Fallback):', {
                    avg_seconds_per_url: AVG_SECONDS_PER_URL,
                    remaining: remaining,
                    eta_minutes: etaMinutes
                });
            }
        }

        // Get currently processing domain from DNSTwist queue
        const activeSeed = await redisClient.zRange('dnstwist:queue:active', 0, 0);

        if (activeSeed && activeSeed.length > 0) {
            const domain = activeSeed[0];

            // Check if this domain is actually still being processed
            const crawlerStatus = await redisClient.get(`fcrawler:seed:${domain}:status`);
            const crawled = parseInt(await redisClient.get(`fcrawler:seed:${domain}:crawled`)) || 0;
            const total = parseInt(await redisClient.get(`fcrawler:seed:${domain}:total`)) || 0;

            // If completed, clean up stale entry
            if (crawlerStatus === 'completed' || (total > 0 && crawled >= total)) {
                console.log(`[current-scan] Cleaning up stale active queue entry: ${domain}`);
                await redisClient.zRem('dnstwist:queue:active', domain);
                await redisClient.del(`dnstwist:progress:${domain}`);
            } else {
                // Domain is actively being processed
                const progressData = await redisClient.hGetAll(`dnstwist:progress:${domain}`);

                if (progressData && Object.keys(progressData).length > 0) {
                    const startedAt = parseInt(progressData.started_at || 0);
                    const now = Math.floor(Date.now() / 1000);
                    const elapsedSeconds = startedAt > 0 ? now - startedAt : 0;

                    // Check for stale entries (processing for more than 2 hours)
                    const MAX_PROCESSING_TIME = 2 * 60 * 60; // 2 hours in seconds
                    if (elapsedSeconds > MAX_PROCESSING_TIME) {
                        console.log(`[current-scan] Cleaning up stale entry (${elapsedSeconds}s elapsed): ${domain}`);
                        await redisClient.zRem('dnstwist:queue:active', domain);
                        await redisClient.del(`dnstwist:progress:${domain}`);
                    } else {
                        currentlyProcessing = {
                            domain: domain,
                            current_pass: progressData.current_pass || 'unknown',
                            elapsed_seconds: elapsedSeconds,
                            type: 'dnstwist'
                        };

                        console.log('[current-scan] Currently processing:', currentlyProcessing);
                    }
                }
            }
        }

        // If no DNSTwist processing, check if Feature Crawler is actively working
        if (!currentlyProcessing && totalUrls > 0 && processedUrls < totalUrls) {
            // Find the first seed that's actively being crawled
            for (const key of seedKeys) {
                const parts = key.split(':');
                if (parts.length >= 4) {
                    const domain = parts[2];
                    const status = await redisClient.get(`fcrawler:seed:${domain}:status`);
                    const crawled = parseInt(await redisClient.get(`fcrawler:seed:${domain}:crawled`)) || 0;
                    const total = parseInt(await redisClient.get(`fcrawler:seed:${domain}:total`)) || 0;

                    // Show this domain if it's actively being crawled
                    if (status === 'processing' || (status !== 'completed' && crawled < total)) {
                        currentlyProcessing = {
                            domain: domain,
                            current_progress: `${crawled}/${total}`,
                            elapsed_seconds: 0, // Feature crawler doesn't track start time
                            type: 'feature_crawler'
                        };

                        console.log('[current-scan] Feature crawler processing:', currentlyProcessing);
                        break;
                    }
                }
            }
        }

        // Calculate percentage
        const percentage = totalUrls > 0
            ? parseFloat(((processedUrls / totalUrls) * 100).toFixed(1))
            : 0;

        // Determine status
        let status = 'idle';
        if (totalUrls > 0) {
            if (processedUrls >= totalUrls) {
                status = 'completed';
            } else if (processedUrls > 0) {
                status = 'processing';
            }
        }

        const response = {
            success: true,
            total_urls: totalUrls,
            processed: processedUrls,
            percentage: percentage,
            status: status,
            eta_minutes: etaMinutes,
            eta_calculation_method: etaMethod,
            currently_processing: currentlyProcessing,
            timestamp: new Date().toISOString()
        };

        console.log('[current-scan] Response:', {
            total: totalUrls,
            processed: processedUrls,
            status: status,
            eta: etaMinutes,
            method: etaMethod
        });

        res.json(response);

    } catch (error) {
        console.error('[current-scan] Error:', error.message);
        console.error('[current-scan] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch scan progress',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;
