const express = require('express');
const { ChromaClient } = require('chromadb');
const router = express.Router();

// ChromaDB client setup
const chroma = new ChromaClient({
    path: `http://${process.env.CHROMA_HOST || 'chroma'}:${process.env.CHROMA_PORT || '8000'}`
});

// Simple custom embedding function (no-op) to avoid requiring default-embed package
class SimpleEmbeddingFunction {
    async generate(texts) {
        // Return simple embeddings (vectors of zeros)
        // This is fine if you're just storing/retrieving data without semantic search
        return texts.map(() => new Array(384).fill(0));
    }
}

const COLLECTION_NAME = process.env.CHROMA_COLLECTION || 'domains';
let collection = null;
let chromaReady = false;

// Initialize ChromaDB collection
(async () => {
    try {
        console.log('[live-url-scan] Connecting to ChromaDB...');
        collection = await chroma.getOrCreateCollection({
            name: COLLECTION_NAME,
            embeddingFunction: new SimpleEmbeddingFunction()
        });
        chromaReady = true;
        console.log('[live-url-scan] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[live-url-scan] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * Time interval mapping based on timeframe
 */
const TIMEFRAME_CONFIG = {
    '5min': {
        durationMs: 5 * 60 * 1000,
        intervalSeconds: 10,
        dataPoints: 30
    },
    '30min': {
        durationMs: 30 * 60 * 1000,
        intervalSeconds: 60,
        dataPoints: 30
    },
    '1hour': {
        durationMs: 60 * 60 * 1000,
        intervalSeconds: 120,
        dataPoints: 30
    },
    '24hours': {
        durationMs: 24 * 60 * 60 * 1000,
        intervalSeconds: 1800,
        dataPoints: 48
    }
};

/**
 * GET /api/live-monitoring/scan-timeline
 * Returns time-series data of URLs scanned over a specific timeframe
 *
 * Query Parameters:
 * - timeframe: 5min, 30min, 1hour, 24hours (default: 1hour)
 *
 * Response:
 * {
 *   "success": true,
 *   "timeframe": "30min",
 *   "interval": "1min",
 *   "start_time": "2025-10-17T12:15:00Z",
 *   "end_time": "2025-10-17T12:45:00Z",
 *   "data_points": 30,
 *   "data": [...],
 *   "summary": {...}
 * }
 */
router.get('/live-monitoring/scan-timeline', async (req, res) => {
    try {
        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.'
            });
        }

        // Parse timeframe parameter
        const timeframe = req.query.timeframe || '1hour';
        const config = TIMEFRAME_CONFIG[timeframe];

        if (!config) {
            return res.status(400).json({
                success: false,
                error: 'Invalid timeframe parameter',
                allowed: Object.keys(TIMEFRAME_CONFIG),
                provided: timeframe
            });
        }

        console.log('[live-url-scan] Query timeframe:', timeframe);

        // Calculate time range
        const endTime = new Date();
        const startTime = new Date(endTime.getTime() - config.durationMs);

        console.log('[live-url-scan] Time range:', {
            start: startTime.toISOString(),
            end: endTime.toISOString(),
            interval_seconds: config.intervalSeconds
        });

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[live-url-scan] Found', results.ids?.length || 0, 'total records');

        // Filter records within time range and extract timestamps
        const timestamps = [];

        if (results.metadatas && results.metadatas.length > 0) {
            for (const metadata of results.metadatas) {
                if (metadata.first_seen) {
                    const recordTime = new Date(metadata.first_seen);

                    // Only include if within time range
                    if (recordTime >= startTime && recordTime <= endTime) {
                        timestamps.push(recordTime);
                    }
                }
            }
        }

        console.log('[live-url-scan] Filtered to', timestamps.length, 'records within timeframe');

        // Create time buckets
        const buckets = [];
        const bucketCounts = new Map();

        for (let i = 0; i < config.dataPoints; i++) {
            const bucketStart = new Date(startTime.getTime() + (i * config.intervalSeconds * 1000));
            buckets.push(bucketStart);
            bucketCounts.set(bucketStart.toISOString(), 0);
        }

        // Distribute timestamps into buckets
        for (const timestamp of timestamps) {
            // Find the appropriate bucket
            for (let i = 0; i < buckets.length; i++) {
                const bucketStart = buckets[i];
                const bucketEnd = new Date(bucketStart.getTime() + (config.intervalSeconds * 1000));

                if (timestamp >= bucketStart && timestamp < bucketEnd) {
                    const key = bucketStart.toISOString();
                    bucketCounts.set(key, bucketCounts.get(key) + 1);
                    break;
                }
            }
        }

        // Build response data array
        const data = [];
        let cumulative = 0;
        let peakCount = 0;
        let peakTimestamp = null;
        let totalCount = 0;

        for (const bucket of buckets) {
            const key = bucket.toISOString();
            const count = bucketCounts.get(key) || 0;
            cumulative += count;
            totalCount += count;

            if (count > peakCount) {
                peakCount = count;
                peakTimestamp = key;
            }

            data.push({
                timestamp: key,
                count: count,
                cumulative: cumulative
            });
        }

        // Calculate average per interval
        const avgPerInterval = data.length > 0
            ? parseFloat((totalCount / data.length).toFixed(2))
            : 0;

        // Format interval for display
        const intervalDisplay = config.intervalSeconds < 60
            ? `${config.intervalSeconds}sec`
            : `${config.intervalSeconds / 60}min`;

        const response = {
            success: true,
            timeframe: timeframe,
            interval: intervalDisplay,
            start_time: startTime.toISOString(),
            end_time: endTime.toISOString(),
            data_points: data.length,
            data: data,
            summary: {
                total_scanned: totalCount,
                avg_per_interval: avgPerInterval,
                peak_count: peakCount,
                peak_timestamp: peakTimestamp
            },
            timestamp: new Date().toISOString()
        };

        console.log('[live-url-scan] Summary:', {
            total_scanned: totalCount,
            avg_per_interval: avgPerInterval,
            peak_count: peakCount
        });

        res.json(response);

    } catch (error) {
        console.error('[live-url-scan] Error:', error.message);
        console.error('[live-url-scan] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch scan timeline data',
            details: error.message
        });
    }
});

module.exports = router;
