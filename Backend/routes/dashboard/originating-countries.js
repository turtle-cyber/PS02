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
        console.log('[originating-countries] Connecting to ChromaDB...');
        collection = await chroma.getCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[originating-countries] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[originating-countries] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/dashboard/originating-countries
 * Returns aggregated count of domains by country code (top originating locations)
 *
 * Query Parameters:
 * - limit (optional): Number of top countries to return (default: 20)
 * - min_count (optional): Minimum domain count to include (default: 1)
 * - verdict (optional): Filter by verdict (e.g., "phishing", "benign", "suspicious")
 * - start_time (optional): ISO 8601 timestamp (defaults to 24 hours ago)
 * - end_time (optional): ISO 8601 timestamp (defaults to now)
 *
 * Response shape:
 * {
 *   "success": true,
 *   "data": [
 *     { "country": "US", "count": 150, "percentage": 35.5 },
 *     { "country": "IN", "count": 89, "percentage": 21.1 }
 *   ],
 *   "total_domains": 423,
 *   "countries_count": 45,
 *   "timestamp": "2025-10-16T..."
 * }
 */
router.get('/dashboard/originating-countries', async (req, res) => {
    try {
        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.'
            });
        }

        // Parse query parameters
        const limit = parseInt(req.query.limit) || 20;
        const minCount = parseInt(req.query.min_count) || 1;
        const verdictFilter = req.query.verdict ? req.query.verdict.toLowerCase() : null;
        const { start_time, end_time } = req.query;

        // Default to last 24 hours if not provided
        let startTimeISO, endTimeISO;

        if (!start_time || !end_time) {
            const now = new Date();
            const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

            startTimeISO = last24Hours.toISOString();
            endTimeISO = now.toISOString();

            console.log('[originating-countries] Using default time range (last 24 hours)');
        } else {
            startTimeISO = new Date(start_time).toISOString();
            endTimeISO = new Date(end_time).toISOString();

            console.log('[originating-countries] Using custom time range:', { start: startTimeISO, end: endTimeISO });
        }

        console.log('[originating-countries] Query:', {
            limit,
            min_count: minCount,
            verdict: verdictFilter,
            start_time: startTimeISO,
            end_time: endTimeISO
        });

        // Fetch all records from ChromaDB with metadata
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[originating-countries] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Aggregate by country
        const countryMap = new Map();
        let totalDomains = 0;

        if (results.metadatas && results.metadatas.length > 0) {
            for (const metadata of results.metadatas) {
                // Apply time filter if first_seen is available
                if (metadata.first_seen) {
                    const recordTime = new Date(metadata.first_seen);
                    const startTime = new Date(startTimeISO);
                    const endTime = new Date(endTimeISO);

                    // Skip if outside time range
                    if (recordTime < startTime || recordTime > endTime) {
                        continue;
                    }
                }

                // Apply verdict filter if specified
                if (verdictFilter && metadata.verdict?.toLowerCase() !== verdictFilter) {
                    continue;
                }

                // Get country code
                const country = metadata.country;

                // Skip records without country information
                if (!country) {
                    continue;
                }

                // Count by country
                countryMap.set(country, (countryMap.get(country) || 0) + 1);
                totalDomains++;
            }
        }

        // Convert map to array and calculate percentages
        const countryData = Array.from(countryMap.entries())
            .map(([country, count]) => ({
                country,
                count,
                percentage: totalDomains > 0 ? parseFloat(((count / totalDomains) * 100).toFixed(2)) : 0
            }))
            // Sort by count descending
            .sort((a, b) => b.count - a.count)
            // Filter by minimum count
            .filter(item => item.count >= minCount)
            // Limit results
            .slice(0, limit);

        console.log('[originating-countries] Returning', countryData.length, 'countries (total domains:', totalDomains, ')');

        res.json({
            success: true,
            total_domains: totalDomains,
            countries_count: countryData.length,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                default_range: (!start_time || !end_time) ? 'last_24_hours' : null
            },
            filters: {
                limit,
                min_count: minCount,
                verdict: verdictFilter
            },
            data: countryData,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[originating-countries] Error:', error.message);
        console.error('[originating-countries] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch originating countries data',
            details: error.message
        });
    }
});

module.exports = router;
