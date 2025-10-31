const express = require('express');
const { ChromaClient } = require('chromadb');
const { client: redisClient, isRedisReady } = require('../../utils/redisClient');
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
        console.log('[unique-domain-count] Connecting to ChromaDB...');
        collection = await chroma.getOrCreateCollection({
            name: COLLECTION_NAME,
            embeddingFunction: new SimpleEmbeddingFunction()
        });
        chromaReady = true;
        console.log('[unique-domain-count] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[unique-domain-count] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/live-monitoring/unique-domains-count
 * Returns count of unique domains and registrables
 *
 * Query Parameters:
 * - include_stats: boolean (default: false) - Include detailed enrichment breakdown
 *
 * Response (Basic):
 * {
 *   "success": true,
 *   "unique_domains": 847,
 *   "unique_registrables": 732,
 *   "total_urls": 1134,
 *   "ratio": {
 *     "domains_per_registrable": 1.16,
 *     "description": "Average variants per unique domain"
 *   },
 *   "last_updated": "2025-10-17T12:45:30Z",
 *   "data_source": "chromadb"
 * }
 *
 * Response (With Stats - include_stats=true):
 * {
 *   ...basic fields,
 *   "enrichment_breakdown": {...},
 *   "verdict_breakdown": {...},
 *   "crawl_status": {...}
 * }
 */
router.get('/live-monitoring/unique-domains-count', async (req, res) => {
    try {
        // Parse query parameters
        const includeStats = req.query.include_stats === 'true';

        console.log('[unique-domain-count] Query:', { include_stats: includeStats });

        // Check ChromaDB availability
        if (!chromaReady || !collection) {
            // Try Redis fallback
            if (isRedisReady()) {
                console.log('[unique-domain-count] ChromaDB unavailable, using Redis fallback');

                const totalProcessed = await redisClient.get('dnstwist:total_processed');
                const historySize = await redisClient.zCard('dnstwist:history');

                return res.json({
                    success: false,
                    error: 'ChromaDB not available',
                    fallback: {
                        available: true,
                        unique_domains: parseInt(totalProcessed) || 0,
                        data_source: 'redis'
                    },
                    timestamp: new Date().toISOString()
                });
            }

            return res.status(503).json({
                success: false,
                error: 'ChromaDB not available. Please try again later.',
                timestamp: new Date().toISOString()
            });
        }

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[unique-domain-count] Found', results.ids?.length || 0, 'total records');

        // Calculate unique counts
        const uniqueRegistrables = new Set();
        const uniqueDomains = new Set();

        // For stats (if requested)
        const enrichmentCounts = {
            fully_enriched: 0,
            with_features: 0,
            domain_only: 0,
            verdict_only: 0
        };

        let withVerdict = 0;
        let withoutVerdict = 0;
        let successful = 0;
        let failed = 0;
        let pending = 0;

        if (results.metadatas && results.metadatas.length > 0) {
            for (const metadata of results.metadatas) {
                // Track unique registrables
                if (metadata.registrable) {
                    uniqueRegistrables.add(metadata.registrable);
                }

                // Track unique domains (FQDNs)
                const domain = metadata.canonical_fqdn || metadata.fqdn || metadata.url;
                if (domain) {
                    // Extract domain from URL if needed
                    let cleanDomain = domain;
                    if (domain.includes('://')) {
                        try {
                            cleanDomain = new URL(domain).hostname;
                        } catch (e) {
                            // Keep original if URL parsing fails
                        }
                    }
                    uniqueDomains.add(cleanDomain);
                }

                // Collect stats if requested
                if (includeStats) {
                    // Enrichment breakdown
                    const recordType = metadata.record_type || 'unknown';
                    if (enrichmentCounts.hasOwnProperty(recordType)) {
                        enrichmentCounts[recordType]++;
                    }

                    // Verdict breakdown
                    if (metadata.has_verdict === true || metadata.has_verdict === 'true' || metadata.verdict) {
                        withVerdict++;
                    } else {
                        withoutVerdict++;
                    }

                    // Crawl status
                    if (metadata.crawl_failed === true || metadata.crawl_failed === 'true') {
                        failed++;
                    } else if (metadata.enrichment_level >= 1) {
                        successful++;
                    } else {
                        pending++;
                    }
                }
            }
        }

        // Calculate ratio
        const ratio = uniqueRegistrables.size > 0
            ? parseFloat((uniqueDomains.size / uniqueRegistrables.size).toFixed(2))
            : 0;

        // Build basic response
        const response = {
            success: true,
            unique_domains: uniqueDomains.size,
            unique_registrables: uniqueRegistrables.size,
            total_urls: results.ids?.length || 0,
            ratio: {
                domains_per_registrable: ratio,
                description: "Average variants per unique domain"
            },
            last_updated: new Date().toISOString(),
            data_source: 'chromadb'
        };

        // Add detailed stats if requested
        if (includeStats) {
            response.enrichment_breakdown = enrichmentCounts;
            response.verdict_breakdown = {
                with_verdict: withVerdict,
                without_verdict: withoutVerdict
            };
            response.crawl_status = {
                successful: successful,
                failed: failed,
                pending: pending
            };
        }

        console.log('[unique-domain-count] Response:', {
            unique_domains: uniqueDomains.size,
            unique_registrables: uniqueRegistrables.size,
            total: results.ids?.length || 0,
            include_stats: includeStats
        });

        res.json(response);

    } catch (error) {
        console.error('[unique-domain-count] Error:', error.message);
        console.error('[unique-domain-count] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch unique domain count',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;
