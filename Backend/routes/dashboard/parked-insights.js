const express = require('express');
const { ChromaClient } = require('chromadb');
const { formatTimestamp } = require('../../utils/dateFormatter');
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
        console.log('[parked-insights] Connecting to ChromaDB...');
        collection = await chroma.getCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[parked-insights] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[parked-insights] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/dashboard/parked-insights
 * Returns table of parked domains with monitoring information
 *
 * Query Parameters:
 * - limit (optional): Number of records to return (default: 50)
 * - cse_id (optional): Filter by brand/CSE
 * - country (optional): Filter by country code
 * - start_time (optional): ISO 8601 timestamp (defaults to 24 hours ago)
 * - end_time (optional): ISO 8601 timestamp (defaults to now)
 *
 * Response shape:
 * {
 *   "success": true,
 *   "data": [
 *     {
 *       "domain": "example.com",
 *       "parked_since": "16-10-2025 12:34",
 *       "verdict": "parked",
 *       "target_brand": "SBI",
 *       "seed_domain": "sbi.co.in",
 *       "monitoring_until": "14-01-2026 12:34",
 *       "country": "US",
 *       "mx_count": 0
 *     }
 *   ],
 *   "total": 45
 * }
 */
router.get('/dashboard/parked-insights', async (req, res) => {
    try {
        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.'
            });
        }

        // Parse query parameters
        const limit = parseInt(req.query.limit) || 50;
        const cseFilter = req.query.cse_id;
        const countryFilter = req.query.country;
        const { start_time, end_time } = req.query;

        // Default to last 24 hours if not provided
        let startTimeISO, endTimeISO;

        if (!start_time || !end_time) {
            const now = new Date();
            const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

            startTimeISO = last24Hours.toISOString();
            endTimeISO = now.toISOString();

            console.log('[parked-insights] Using default time range (last 24 hours)');
        } else {
            startTimeISO = new Date(start_time).toISOString();
            endTimeISO = new Date(end_time).toISOString();

            console.log('[parked-insights] Using custom time range:', { start: startTimeISO, end: endTimeISO });
        }

        console.log('[parked-insights] Query:', {
            limit,
            cse_id: cseFilter,
            country: countryFilter,
            start_time: startTimeISO,
            end_time: endTimeISO
        });

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas", "documents"]
        });

        console.log('[parked-insights] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Filter and transform results
        const parkedDomains = [];

        if (results.metadatas && results.metadatas.length > 0) {
            for (let i = 0; i < results.metadatas.length; i++) {
                const metadata = results.metadatas[i];
                const document = results.documents?.[i] || '';

                // Filter: Only parked domains
                if (metadata.verdict !== 'parked') {
                    continue;
                }

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

                // Apply CSE filter if specified
                if (cseFilter && metadata.cse_id !== cseFilter) {
                    continue;
                }

                // Apply country filter if specified
                if (countryFilter && metadata.country !== countryFilter) {
                    continue;
                }

                // Extract country from document if not in metadata
                let country = metadata.country || null;
                if (!country) {
                    const countryMatch = document.match(/Country:\s*([A-Z]{2})/);
                    if (countryMatch) {
                        country = countryMatch[1];
                    }
                }

                parkedDomains.push({
                    domain: metadata.registrable || metadata.url || 'N/A',
                    parked_since: formatTimestamp(metadata.first_seen),
                    parked_since_iso: metadata.first_seen || null,
                    verdict: metadata.verdict || 'parked',
                    target_brand: metadata.cse_id || 'Unknown',
                    seed_domain: metadata.seed_registrable || 'Unknown',
                    monitoring_until: formatTimestamp(metadata.monitor_until),
                    monitoring_until_iso: metadata.monitor_until || null,
                    country: country || 'Unknown',
                    mx_count: metadata.mx_count || 0,
                    requires_monitoring: metadata.requires_monitoring || false,
                    monitor_reason: metadata.monitor_reason || 'parked'
                });
            }
        }

        // Sort by parked_since descending (most recent first)
        parkedDomains.sort((a, b) => {
            const dateA = new Date(a.parked_since_iso || 0);
            const dateB = new Date(b.parked_since_iso || 0);
            return dateB - dateA;
        });

        console.log('[parked-insights] Found', parkedDomains.length, 'parked domains');

        // Limit results
        const limitedData = parkedDomains.slice(0, limit);

        console.log('[parked-insights] Returning', limitedData.length, 'records');

        res.json({
            success: true,
            data: limitedData,
            total: parkedDomains.length,
            returned: limitedData.length,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                default_range: (!start_time || !end_time) ? 'last_24_hours' : null
            },
            filters: {
                limit,
                cse_id: cseFilter || null,
                country: countryFilter || null
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[parked-insights] Error:', error.message);
        console.error('[parked-insights] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch parked insights',
            details: error.message
        });
    }
});

module.exports = router;
