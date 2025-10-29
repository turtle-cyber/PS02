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
        console.log('[domain-stats] Connecting to ChromaDB...');
        collection = await chroma.getOrCreateCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[domain-stats] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[domain-stats] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * GET /api/dashboard/domain-stats
 * Returns domain statistics for dashboard cards
 *
 * Query Parameters:
 * - start_time (optional): ISO 8601 timestamp (defaults to 24 hours ago)
 * - end_time (optional): ISO 8601 timestamp (defaults to now)
 *
 * Response shape:
 * {
 *   "success": true,
 *   "domains": {
 *     "lookalike_domains": 1234,
 *     "domains_with_mx": 856,
 *     "total_active_domains": 11365,
 *     "total_parked_domains": 1091,
 *     "total_inactive_domains": 2345
 *   },
 *   "mx_stats": {
 *     "total_mx_records": 2456,
 *     "avg_mx_per_domain": 2.87
 *   }
 * }
 */
router.get('/dashboard/domain-stats', async (req, res) => {
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

            console.log('[domain-stats] Using default time range (last 24 hours)');
        } else {
            startTimeISO = new Date(start_time).toISOString();
            endTimeISO = new Date(end_time).toISOString();

            console.log('[domain-stats] Using custom time range:', { start: startTimeISO, end: endTimeISO });
        }

        console.log('[domain-stats] Fetching domain statistics...');

        // Fetch all records from ChromaDB
        const results = await collection.get({
            include: ["metadatas"]
        });

        console.log('[domain-stats] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Initialize counters
        let lookalikeCount = 0;
        let domainsWithMx = 0;
        let totalActiveDomains = 0;
        let totalParkedDomains = 0;
        let totalInactiveDomains = 0;
        let totalMxRecords = 0;
        let mxDomainCount = 0;

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

                // Count lookalike domains (variants that differ from seed domain)
                // A lookalike is:
                // 1. Has a seed_registrable (target brand)
                // 2. registrable != seed_registrable (it's a variant, not the original)
                // 3. Has verdict (has been analyzed)
                if (metadata.seed_registrable && metadata.registrable) {
                    // Normalize for comparison
                    const seedDomain = (metadata.seed_registrable || '').toLowerCase().trim();
                    const variantDomain = (metadata.registrable || '').toLowerCase().trim();

                    if (seedDomain && variantDomain && seedDomain !== variantDomain) {
                        // This is a variant (lookalike)
                        if (metadata.has_verdict === true || metadata.has_verdict === 'true' || metadata.verdict) {
                            lookalikeCount++;
                        }
                    }
                }

                // Count domains with MX records
                const mxCount = parseInt(metadata.mx_count) || 0;
                if (mxCount > 0) {
                    domainsWithMx++;
                    totalMxRecords += mxCount;
                    mxDomainCount++;
                }

                // Count active domains (not inactive/unregistered)
                const isInactive = metadata.is_inactive === true ||
                                   metadata.is_inactive === 'true' ||
                                   metadata.record_type === 'inactive' ||
                                   metadata.inactive_status === 'inactive' ||
                                   metadata.inactive_status === 'unregistered';

                if (!isInactive) {
                    // Check if it has domain data (enrichment_level >= 1)
                    const enrichmentLevel = parseInt(metadata.enrichment_level) || 0;
                    if (enrichmentLevel >= 1 || metadata.record_type === 'domain_only' ||
                        metadata.record_type === 'with_features' || metadata.record_type === 'verdict_only' ||
                        metadata.record_type === 'fully_enriched') {
                        totalActiveDomains++;
                    }
                } else {
                    totalInactiveDomains++;
                }

                // Count parked domains
                const verdict = (metadata.verdict || '').toLowerCase();
                if (verdict === 'parked') {
                    totalParkedDomains++;
                }
            }
        }

        // Calculate average MX records per domain
        const avgMxPerDomain = mxDomainCount > 0
            ? parseFloat((totalMxRecords / mxDomainCount).toFixed(2))
            : 0;

        const stats = {
            domains: {
                lookalike_domains: lookalikeCount,
                domains_with_mx: domainsWithMx,
                total_active_domains: totalActiveDomains,
                total_parked_domains: totalParkedDomains,
                total_inactive_domains: totalInactiveDomains
            },
            mx_stats: {
                total_mx_records: totalMxRecords,
                avg_mx_per_domain: avgMxPerDomain
            }
        };

        console.log('[domain-stats] Domain stats:', {
            lookalikes: lookalikeCount,
            with_mx: domainsWithMx,
            active: totalActiveDomains,
            parked: totalParkedDomains,
            inactive: totalInactiveDomains
        });

        res.json({
            success: true,
            ...stats,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                default_range: (!start_time || !end_time) ? 'last_24_hours' : null
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[domain-stats] Error:', error.message);
        console.error('[domain-stats] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch domain statistics',
            details: error.message
        });
    }
});

module.exports = router;
