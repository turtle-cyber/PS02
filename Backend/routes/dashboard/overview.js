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
        console.log('[overview] Connecting to ChromaDB...');
        collection = await chroma.getOrCreateCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[overview] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[overview] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/dashboard/overview
 * Returns overview statistics for dashboard cards
 *
 * Query Parameters:
 * - start_time (optional): ISO 8601 timestamp (defaults to 24 hours ago)
 * - end_time (optional): ISO 8601 timestamp (defaults to now)
 *
 * Response shape:
 * {
 *   "success": true,
 *   "overview": {
 *     "total_scans": 12456,
 *     "total_phishing": 342,
 *     "total_suspicious": 789,
 *     "total_benign": 10234,
 *     "total_parked": 1091,
 *     "avg_risk_score": 45.6,
 *     "active_monitoring": 456,
 *     "brands_tracked": 12,
 *     "new_last_24h": 89,
 *     "last_updated": "16-10-2025 12:34"
 *   }
 * }
 */
router.get('/dashboard/overview', async (req, res) => {
    try {
        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.'
            });
        }

        // Parse query parameters
        const { start_time, end_time } = req.query;

        // Default to last 24 hours if not provided
        let startTimeISO, endTimeISO;

        if (!start_time || !end_time) {
            const now = new Date();
            const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

            startTimeISO = last24Hours.toISOString();
            endTimeISO = now.toISOString();

            console.log('[overview] Using default time range (last 24 hours)');
        } else {
            startTimeISO = new Date(start_time).toISOString();
            endTimeISO = new Date(end_time).toISOString();

            console.log('[overview] Using custom time range:', { start: startTimeISO, end: endTimeISO });
        }

        console.log('[overview] Fetching overview statistics...');

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[overview] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Initialize counters
        let totalScans = 0;
        let totalPhishing = 0;
        let totalSuspicious = 0;
        let totalBenign = 0;
        let totalParked = 0;
        let totalRiskScore = 0;
        let riskScoreCount = 0;
        let activeMonitoring = 0;
        const brandsSet = new Set();
        let newLast24h = 0;

        // Calculate 24 hours ago timestamp (for new_last_24h metric)
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        // Process all records
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

                // Count this record
                totalScans++;

                // Count by verdict
                const verdict = (metadata.verdict || '').toLowerCase();
                if (verdict === 'phishing') {
                    totalPhishing++;
                } else if (verdict === 'suspicious') {
                    totalSuspicious++;
                } else if (verdict === 'benign' || verdict === 'clean') {
                    totalBenign++;
                } else if (verdict === 'parked') {
                    totalParked++;
                }

                // Aggregate risk scores
                if (metadata.risk_score !== null && metadata.risk_score !== undefined) {
                    totalRiskScore += metadata.risk_score;
                    riskScoreCount++;
                }

                // Count active monitoring
                if (metadata.requires_monitoring === true || metadata.requires_monitoring === 'true') {
                    activeMonitoring++;
                }

                // Track unique brands
                if (metadata.cse_id) {
                    brandsSet.add(metadata.cse_id);
                }

                // Count new detections in last 24h
                if (metadata.first_seen) {
                    const firstSeenDate = new Date(metadata.first_seen);
                    if (firstSeenDate >= twentyFourHoursAgo) {
                        newLast24h++;
                    }
                }
            }
        }

        // Calculate average risk score
        const avgRiskScore = riskScoreCount > 0
            ? parseFloat((totalRiskScore / riskScoreCount).toFixed(2))
            : 0;

        const overview = {
            total_scans: totalScans,
            total_phishing: totalPhishing,
            total_suspicious: totalSuspicious,
            total_benign: totalBenign,
            total_parked: totalParked,
            avg_risk_score: avgRiskScore,
            active_monitoring: activeMonitoring,
            brands_tracked: brandsSet.size,
            new_last_24h: newLast24h,
            last_updated: formatTimestamp(new Date()),
            last_updated_iso: new Date().toISOString()
        };

        console.log('[overview] Overview stats:', {
            total_scans: totalScans,
            phishing: totalPhishing,
            suspicious: totalSuspicious,
            benign: totalBenign,
            parked: totalParked,
            brands: brandsSet.size
        });

        res.json({
            success: true,
            overview,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                default_range: (!start_time || !end_time) ? 'last_24_hours' : null
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[overview] Error:', error.message);
        console.error('[overview] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch overview statistics',
            details: error.message
        });
    }
});

module.exports = router;
