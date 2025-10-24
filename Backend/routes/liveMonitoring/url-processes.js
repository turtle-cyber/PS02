const express = require('express');
const { ChromaClient } = require('chromadb');
const { getCseName } = require('../../utils/cse_list');
const router = express.Router();

// ChromaDB client setup
const chroma = new ChromaClient({
    path: `http://${process.env.CHROMA_HOST || 'chroma'}:${process.env.CHROMA_PORT || '8000'}`
});

/**
 * Convert UTC timestamp to IST (Indian Standard Time) format
 * IST is UTC+5:30
 * @param {string|Date} timestamp - ISO timestamp or Date object
 * @returns {string} Formatted timestamp in IST (dd-mm-yyyy hh:mm)
 */
function formatToIST(timestamp) {
    if (!timestamp) {
        return 'N/A';
    }

    try {
        const date = new Date(timestamp);

        // Validate date
        if (isNaN(date.getTime())) {
            return 'N/A';
        }

        // Convert to IST by adding 5 hours and 30 minutes
        const istOffset = 5.5 * 60 * 60 * 1000; // 5.5 hours in milliseconds
        const istDate = new Date(date.getTime() + istOffset);

        // Extract date components
        const day = String(istDate.getUTCDate()).padStart(2, '0');
        const month = String(istDate.getUTCMonth() + 1).padStart(2, '0');
        const year = istDate.getUTCFullYear();
        const hours = String(istDate.getUTCHours()).padStart(2, '0');
        const minutes = String(istDate.getUTCMinutes()).padStart(2, '0');

        // Return in "dd-mm-yyyy hh:mm" format
        return `${day}-${month}-${year} ${hours}:${minutes}`;
    } catch (error) {
        return 'N/A';
    }
}

const COLLECTION_NAME = process.env.CHROMA_COLLECTION || 'domains';
let collection = null;
let chromaReady = false;

// Initialize ChromaDB collection
(async () => {
    try {
        console.log('[url-processes] Connecting to ChromaDB...');
        collection = await chroma.getCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[url-processes] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[url-processes] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/live-monitoring/url-processes
 * Returns URL process table with recent detections
 *
 * Query Parameters:
 * - limit: Number of results to return (default: 20)
 * - start_time: ISO 8601 timestamp (optional)
 * - end_time: ISO 8601 timestamp (optional)
 * - fallback_timeframe: Hours to look back when start_time/end_time not provided (default: 24)
 *
 * Response:
 * {
 *   "success": true,
 *   "query": {
 *     "start_time": "2025-10-17T00:00:00Z",
 *     "end_time": "2025-10-18T00:00:00Z",
 *     "limit": 20,
 *     "used_fallback": true
 *   },
 *   "total_found": 150,
 *   "returned": 20,
 *   "data": [
 *     {
 *       "org_urls": "https://example.com",
 *       "risk_score": 85.5,
 *       "country": "IN",
 *       "first_seen": "17-10-2025 18:04",
 *       "cse": "State Bank of India (SBI)",
 *       "verdict": "phishing"
 *     }
 *   ]
 * }
 */
router.get('/live-monitoring/url-processes', async (req, res) => {
    try {
        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.',
                timestamp: new Date().toISOString()
            });
        }

        // Parse query parameters
        const {
            limit = 20,
            start_time,
            end_time,
            fallback_timeframe = 24
        } = req.query;

        // Parse limit and validate
        const limitInt = parseInt(limit);
        if (isNaN(limitInt) || limitInt < 1 || limitInt > 1000) {
            return res.status(400).json({
                success: false,
                error: 'Invalid limit. Must be between 1 and 1000.',
                timestamp: new Date().toISOString()
            });
        }

        // Determine time range
        let startTimeISO, endTimeISO, usedFallback = false;

        if (start_time && end_time) {
            // Use provided time range
            try {
                startTimeISO = new Date(start_time).toISOString();
                endTimeISO = new Date(end_time).toISOString();
                console.log('[url-processes] Using custom time range:', { start: startTimeISO, end: endTimeISO });
            } catch (error) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid timestamp format. Use ISO 8601 format.',
                    timestamp: new Date().toISOString()
                });
            }
        } else {
            // Use fallback timeframe
            usedFallback = true;
            const fallbackHours = parseInt(fallback_timeframe) || 24;
            const now = new Date();
            const fallbackTime = new Date(now.getTime() - fallbackHours * 60 * 60 * 1000);

            startTimeISO = fallbackTime.toISOString();
            endTimeISO = now.toISOString();

            console.log('[url-processes] Using fallback timeframe:', fallbackHours, 'hours');
            console.log('[url-processes] Time range:', { start: startTimeISO, end: endTimeISO });
        }

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[url-processes] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Transform and filter results
        const processedData = [];

        if (results.metadatas && results.metadatas.length > 0) {
            for (const metadata of results.metadatas) {
                // Filter by time range using first_seen
                if (metadata.first_seen) {
                    const recordTime = new Date(metadata.first_seen);
                    const startTime = new Date(startTimeISO);
                    const endTime = new Date(endTimeISO);

                    // Skip if outside time range
                    if (recordTime < startTime || recordTime > endTime) {
                        continue;
                    }
                }

                // Get CSE name - prefer cse_id, fallback to getCseName from seed domain
                let cseName = 'Unknown';
                if (metadata.cse_id) {
                    cseName = metadata.cse_id;
                } else if (metadata.seed_registrable) {
                    cseName = getCseName(metadata.seed_registrable);
                }

                // Build process entry
                processedData.push({
                    org_urls: metadata.url || metadata.registrable || 'N/A',
                    risk_score: metadata.risk_score || metadata.score || 0,
                    country: metadata.country || 'Unknown',
                    first_seen: formatToIST(metadata.first_seen),
                    first_seen_raw: metadata.first_seen || 'N/A', // Keep raw for sorting
                    cse: cseName,
                    verdict: metadata.verdict || 'unknown'
                });
            }
        }

        // Sort by first_seen_raw descending (newest first)
        // Handle N/A and invalid dates by putting them at the end
        processedData.sort((a, b) => {
            // Treat N/A as invalid (put at end)
            if (a.first_seen_raw === 'N/A' && b.first_seen_raw === 'N/A') return 0;
            if (a.first_seen_raw === 'N/A') return 1;  // a goes to end
            if (b.first_seen_raw === 'N/A') return -1; // b goes to end

            const dateA = new Date(a.first_seen_raw);
            const dateB = new Date(b.first_seen_raw);

            // Handle invalid dates
            if (isNaN(dateA.getTime()) && isNaN(dateB.getTime())) return 0;
            if (isNaN(dateA.getTime())) return 1;  // a goes to end
            if (isNaN(dateB.getTime())) return -1; // b goes to end

            return dateB - dateA; // Descending order
        });

        console.log('[url-processes] Filtered to', processedData.length, 'records within time range');

        // Apply limit
        const limitedData = processedData.slice(0, limitInt);

        // Remove first_seen_raw from response (only used for sorting)
        limitedData.forEach(item => {
            delete item.first_seen_raw;
        });

        console.log('[url-processes] Returning', limitedData.length, 'most recent records');

        // Build response
        const response = {
            success: true,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                limit: limitInt,
                used_fallback: usedFallback,
                fallback_hours: usedFallback ? (parseInt(fallback_timeframe) || 24) : null
            },
            total_found: processedData.length,
            returned: limitedData.length,
            data: limitedData,
            timestamp: new Date().toISOString()
        };

        res.json(response);

    } catch (error) {
        console.error('[url-processes] Error:', error.message);
        console.error('[url-processes] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch URL processes',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;
