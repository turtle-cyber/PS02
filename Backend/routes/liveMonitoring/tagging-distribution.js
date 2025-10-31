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
        console.log('[tagging-distribution] Connecting to ChromaDB...');
        collection = await chroma.getOrCreateCollection({
            name: COLLECTION_NAME,
            embeddingFunction: new SimpleEmbeddingFunction()
        });
        chromaReady = true;
        console.log('[tagging-distribution] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[tagging-distribution] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/live-monitoring/tagging-distribution
 * Returns distribution of URLs by verdict tags (phishing, parked, suspicious, benign)
 *
 * Query Parameters:
 * - timeframe: 24hours, 7days, 30days, all (default: all)
 * - start_time: ISO 8601 timestamp (overrides timeframe)
 * - end_time: ISO 8601 timestamp (overrides timeframe)
 *
 * Response:
 * {
 *   "success": true,
 *   "distribution": {
 *     "phishing": 234,
 *     "parked": 456,
 *     "suspicious": 128,
 *     "benign": 892,
 *     "total": 1710
 *   },
 *   "percentages": {
 *     "phishing": 13.7,
 *     "parked": 26.7,
 *     "suspicious": 7.5,
 *     "benign": 52.1
 *   }
 * }
 */
router.get('/live-monitoring/tagging-distribution', async (req, res) => {
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
        const { timeframe, start_time, end_time } = req.query;

        let startTimeISO = null;
        let endTimeISO = null;

        // Determine time range
        if (start_time && end_time) {
            // Custom time range provided
            startTimeISO = new Date(start_time).toISOString();
            endTimeISO = new Date(end_time).toISOString();
            console.log('[tagging-distribution] Using custom time range:', { start: startTimeISO, end: endTimeISO });
        } else if (timeframe && timeframe !== 'all') {
            // Use predefined timeframe
            const now = new Date();
            endTimeISO = now.toISOString();

            switch (timeframe) {
                case '24hours':
                    startTimeISO = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
                    break;
                case '7days':
                    startTimeISO = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
                    break;
                case '30days':
                    startTimeISO = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
                    break;
                default:
                    startTimeISO = null;
                    endTimeISO = null;
            }
            console.log('[tagging-distribution] Using timeframe:', timeframe, { start: startTimeISO, end: endTimeISO });
        } else {
            console.log('[tagging-distribution] Using all-time data');
        }

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[tagging-distribution] Found', results.ids?.length || 0, 'total records');

        // Initialize counters
        const distribution = {
            phishing: 0,
            parked: 0,
            suspicious: 0,
            benign: 0,
            total: 0
        };

        // Process records and apply time filter if needed
        if (results.metadatas && results.metadatas.length > 0) {
            for (const metadata of results.metadatas) {
                // Apply time filter if specified
                if (startTimeISO && endTimeISO && metadata.first_seen) {
                    const recordTime = new Date(metadata.first_seen);
                    const startTime = new Date(startTimeISO);
                    const endTime = new Date(endTimeISO);

                    // Skip if outside time range
                    if (recordTime < startTime || recordTime > endTime) {
                        continue;
                    }
                }

                // Count by verdict
                const verdict = (metadata.verdict || '').toLowerCase();

                if (verdict === 'phishing') {
                    distribution.phishing++;
                } else if (verdict === 'parked') {
                    distribution.parked++;
                } else if (verdict === 'suspicious') {
                    distribution.suspicious++;
                } else if (verdict === 'benign' || verdict === 'clean') {
                    distribution.benign++;
                }

                distribution.total++;
            }
        }

        console.log('[tagging-distribution] Distribution:', distribution);

        // Calculate percentages
        const percentages = {
            phishing: distribution.total > 0
                ? parseFloat(((distribution.phishing / distribution.total) * 100).toFixed(1))
                : 0,
            parked: distribution.total > 0
                ? parseFloat(((distribution.parked / distribution.total) * 100).toFixed(1))
                : 0,
            suspicious: distribution.total > 0
                ? parseFloat(((distribution.suspicious / distribution.total) * 100).toFixed(1))
                : 0,
            benign: distribution.total > 0
                ? parseFloat(((distribution.benign / distribution.total) * 100).toFixed(1))
                : 0
        };

        console.log('[tagging-distribution] Percentages:', percentages);

        const response = {
            success: true,
            distribution: distribution,
            percentages: percentages,
            timestamp: new Date().toISOString()
        };

        res.json(response);

    } catch (error) {
        console.error('[tagging-distribution] Error:', error.message);
        console.error('[tagging-distribution] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch tagging distribution',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;
