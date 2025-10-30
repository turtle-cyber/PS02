const express = require('express');
const { ChromaClient } = require('chromadb');
const { getCseCategory } = require('../../utils/cse_list');
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
        console.log('[threat-landscape] Connecting to ChromaDB...');
        collection = await chroma.getOrCreateCollection({
            name: COLLECTION_NAME,
            embeddingFunction: new SimpleEmbeddingFunction()
        });
        chromaReady = true;
        console.log('[threat-landscape] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[threat-landscape] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/dashboard/threat-landscape
 * Returns verdict distribution with contributing CSEs and their categories
 *
 * Query Parameters:
 * - start_time: ISO 8601 timestamp (optional, defaults to 24 hours ago)
 * - end_time: ISO 8601 timestamp (optional, defaults to now)
 *
 * Response:
 * {
 *   "success": true,
 *   "data": {
 *     "phishing": {
 *       "count": 2,
 *       "hits": [
 *         {"name": "Reserve Bank of India (RBI)", "category": "BFSI"},
 *         {"name": "UIDAI", "category": "Government"}
 *       ]
 *     },
 *     "suspicious": {
 *       "count": 5,
 *       "hits": [...]
 *     },
 *     "benign": {
 *       "count": 3,
 *       "hits": [...]
 *     },
 *     "inactive": {
 *       "count": 2,
 *       "hits": [...]
 *     },
 *     "parked": {
 *       "count": 5,
 *       "hits": [...]
 *     }
 *   }
 * }
 */
router.get('/dashboard/threat-landscape', async (req, res) => {
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
        const { start_time, end_time } = req.query;

        // Default to last 24 hours if not provided
        let startTimeISO, endTimeISO;

        if (!start_time || !end_time) {
            const now = new Date();
            const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

            startTimeISO = last24Hours.toISOString();
            endTimeISO = now.toISOString();

            console.log('[threat-landscape] Using default time range (last 24 hours)');
        } else {
            startTimeISO = new Date(start_time).toISOString();
            endTimeISO = new Date(end_time).toISOString();

            console.log('[threat-landscape] Using custom time range:', { start: startTimeISO, end: endTimeISO });
        }

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[threat-landscape] Found', results.ids?.length || 0, 'total records');

        // Initialize verdict groups with CSE tracking
        const verdictGroups = {
            phishing: new Map(),
            suspicious: new Map(),
            benign: new Map(),
            inactive: new Map(),
            parked: new Map()
        };

        // Process records and apply time filter
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

                // Get verdict (normalize to lowercase)
                const verdict = (metadata.verdict || '').toLowerCase();

                // Skip if verdict is not one of the expected types
                if (!verdictGroups[verdict]) {
                    continue;
                }

                // Get CSE name from metadata
                const cseName = metadata.cse_id || 'Unknown';

                // Get CSE category using seed_registrable (the original domain)
                const seedDomain = metadata.seed_registrable || metadata.registrable || '';
                const cseCategory = getCseCategory(seedDomain);

                // Track unique CSE with its category for this verdict
                if (!verdictGroups[verdict].has(cseName)) {
                    verdictGroups[verdict].set(cseName, cseCategory);
                }
            }
        }

        // Build response data
        const responseData = {};

        for (const [verdict, cseMap] of Object.entries(verdictGroups)) {
            const hits = Array.from(cseMap.entries()).map(([name, category]) => ({
                name: name,
                category: category
            }));

            responseData[verdict] = {
                count: hits.length,
                hits: hits
            };
        }

        console.log('[threat-landscape] Verdict distribution:', {
            phishing: responseData.phishing.count,
            suspicious: responseData.suspicious.count,
            benign: responseData.benign.count,
            inactive: responseData.inactive.count,
            parked: responseData.parked.count
        });

        const response = {
            success: true,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                default_range: (!start_time || !end_time) ? 'last_24_hours' : null
            },
            data: responseData,
            timestamp: new Date().toISOString()
        };

        res.json(response);

    } catch (error) {
        console.error('[threat-landscape] Error:', error.message);
        console.error('[threat-landscape] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch threat landscape',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;
