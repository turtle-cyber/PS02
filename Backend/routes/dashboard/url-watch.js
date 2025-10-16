const express = require('express');
const { ChromaClient } = require('chromadb');
const router = express.Router();

// ChromaDB client setup
const chroma = new ChromaClient({
    path: `http://${process.env.CHROMA_HOST || 'chroma'}:${process.env.CHROMA_PORT || '8000'}`
});

const COLLECTION_NAME = process.env.CHROMA_COLLECTION || 'domains';
let collection = null;
let chromaReady = false;

// Initialize ChromaDB collection
(async () => {
    try {
        console.log('[url-watch] Connecting to ChromaDB...');
        collection = await chroma.getCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[url-watch] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[url-watch] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/dashboard/url-watch
 * Returns daily counts of URLs by verdict type (phishing, suspicious, benign)
 *
 * Query Parameters:
 * - days (optional): Number of days to return (default: 7)
 *
 * Response shape (optimized for UrlWatchArea.tsx):
 * {
 *   "success": true,
 *   "series": {
 *     "dates": ["2025-10-10", "2025-10-11", ...],
 *     "phishing": [15, 23, ...],
 *     "suspicious": [8, 12, ...],
 *     "clean": [45, 67, ...]
 *   }
 * }
 */
router.get('/dashboard/url-watch', async (req, res) => {
    try {
        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.'
            });
        }

        // Parse query parameters
        const days = parseInt(req.query.days) || 7;

        console.log('[url-watch] Query:', { days });

        // Calculate date range
        const endDate = new Date();
        endDate.setHours(23, 59, 59, 999); // End of today

        const startDate = new Date();
        startDate.setDate(startDate.getDate() - (days - 1)); // Include today
        startDate.setHours(0, 0, 0, 0); // Start of day

        console.log('[url-watch] Date range:', {
            start: startDate.toISOString(),
            end: endDate.toISOString()
        });

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[url-watch] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Initialize date buckets for the last N days
        const dateBuckets = new Map();

        for (let i = 0; i < days; i++) {
            const date = new Date(startDate);
            date.setDate(date.getDate() + i);
            const dateKey = date.toISOString().split('T')[0]; // YYYY-MM-DD format

            dateBuckets.set(dateKey, {
                phishing: 0,
                suspicious: 0,
                clean: 0
            });
        }

        // Aggregate URLs by date and verdict
        if (results.metadatas && results.metadatas.length > 0) {
            for (const metadata of results.metadatas) {
                // Get first_seen timestamp
                if (!metadata.first_seen) {
                    continue;
                }

                const recordDate = new Date(metadata.first_seen);

                // Skip if outside date range
                if (recordDate < startDate || recordDate > endDate) {
                    continue;
                }

                // Get date key (YYYY-MM-DD)
                const dateKey = recordDate.toISOString().split('T')[0];

                // Get bucket for this date
                const bucket = dateBuckets.get(dateKey);
                if (!bucket) {
                    continue; // Skip if date not in range
                }

                // Get verdict and normalize
                const verdict = (metadata.verdict || 'unknown').toLowerCase();

                // Categorize verdict
                if (verdict === 'phishing') {
                    bucket.phishing++;
                } else if (verdict === 'suspicious') {
                    bucket.suspicious++;
                } else if (verdict === 'benign' || verdict === 'clean') {
                    bucket.clean++;
                }
                // Ignore 'unknown' or other verdicts
            }
        }

        // Convert to arrays for chart (sorted by date)
        const sortedDates = Array.from(dateBuckets.keys()).sort();
        const dates = [];
        const phishing = [];
        const suspicious = [];
        const clean = [];

        for (const dateKey of sortedDates) {
            const bucket = dateBuckets.get(dateKey);
            dates.push(dateKey);
            phishing.push(bucket.phishing);
            suspicious.push(bucket.suspicious);
            clean.push(bucket.clean);
        }

        console.log('[url-watch] Returning data for', dates.length, 'days');

        res.json({
            success: true,
            series: {
                dates,
                phishing,
                suspicious,
                clean
            },
            query: {
                days,
                start_date: startDate.toISOString().split('T')[0],
                end_date: endDate.toISOString().split('T')[0]
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[url-watch] Error:', error.message);
        console.error('[url-watch] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch URL watch data',
            details: error.message
        });
    }
});

module.exports = router;
