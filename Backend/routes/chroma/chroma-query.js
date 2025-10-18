const express = require('express');
const { ChromaClient } = require('chromadb');
const winston = require('winston');
const redis = require('redis');
const { formatTimestamp } = require('../../utils/dateFormatter');

const router = express.Router();

// Logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(({ timestamp, level, message, ...meta }) => {
                    return `${timestamp} [${level}] ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
                })
            )
        })
    ]
});

// ChromaDB Configuration
const CHROMA_HOST = process.env.CHROMA_HOST || 'localhost';
const CHROMA_PORT = process.env.CHROMA_PORT || '8000';
const VARIANTS_COLLECTION = process.env.CHROMA_COLLECTION || 'domains';
const ORIGINALS_COLLECTION = process.env.CHROMA_ORIGINAL_COLLECTION || 'original_domains';

// Redis Configuration
const redisClient = redis.createClient({
    socket: {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT || '6379')
    }
});

// Connect to Redis
redisClient.connect().catch(err => {
    logger.error(`❌ Redis connection failed: ${err.message}`);
});

redisClient.on('error', (err) => {
    logger.error(`Redis Client Error (Chroma Query): ${err.message}`);
});

redisClient.on('connect', () => {
    logger.info('✅ Redis client connected (Chroma Query)');
});

// Initialize ChromaDB client
let chromaClient = null;
try {
    chromaClient = new ChromaClient({
        path: `http://${CHROMA_HOST}:${CHROMA_PORT}`
    });
    logger.info(`✅ ChromaDB client initialized: ${CHROMA_HOST}:${CHROMA_PORT}`);
} catch (error) {
    logger.error(`❌ Failed to initialize ChromaDB client: ${error.message}`);
}

/**
 * Helper function to extract first IPv4 address from document text
 * @param {string} document - The document text
 * @returns {string|null} First IPv4 address or null if not found
 */
function extractIPv4(document) {
    if (!document || typeof document !== 'string') {
        return null;
    }

    // Match IPv4 pattern: A (IPv4): 192.168.1.1 or just any IPv4 address
    const ipv4Match = document.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
    return ipv4Match ? ipv4Match[0] : null;
}

/**
 * Helper function to extract first nameserver from document text
 * @param {string} document - The document text
 * @returns {string|null} First nameserver or null if not found
 */
function extractNameserver(document) {
    if (!document || typeof document !== 'string') {
        return null;
    }

    // Match nameserver patterns:
    // - "NS (Nameservers): ns1.example.com, ns2.example.com"
    // - "NS: ns1.example.com"
    // - "Nameserver: ns1.example.com"
    // - "Name Server: ns1.example.com"
    const nsMatch = document.match(/NS\s*\(Nameservers\):\s*([a-zA-Z0-9.-]+)/i) ||
                    document.match(/(?:NS|Nameserver|Name Server):\s*([a-zA-Z0-9.-]+)/i);
    return nsMatch ? nsMatch[1] : null;
}

/**
 * Helper function to fetch DNSTwist variant statistics from Redis
 * @param {string} domain - The domain to fetch stats for
 * @returns {Object|null} DNSTwist stats or null if not available
 */
async function getDnstwistStats(domain) {
    try {
        const variants = await redisClient.get(`dnstwist:variants:${domain}`);
        const unregistered = await redisClient.get(`dnstwist:unregistered:${domain}`);
        const timestamp = await redisClient.get(`dnstwist:timestamp:${domain}`);

        if (!variants && !timestamp) {
            return null; // Not processed by DNSTwist yet
        }

        const variantsCount = parseInt(variants) || 0;
        const unregisteredCount = parseInt(unregistered) || 0;
        const processedAt = parseInt(timestamp) || 0;

        return {
            variants_registered: variantsCount,
            variants_unregistered: unregisteredCount,
            total_variants_generated: variantsCount + unregisteredCount,
            processed_at: processedAt,
            processed_date: processedAt ? new Date(processedAt * 1000).toISOString() : null
        };
    } catch (error) {
        logger.warn(`⚠️ Could not fetch DNSTwist stats for ${domain}: ${error.message}`);
        return null;
    }
}

/**
 * GET /api/chroma/collections
 * List all available collections
 */
router.get('/collections', async (req, res) => {
    try {
        if (!chromaClient) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB client not initialized'
            });
        }

        const collections = await chromaClient.listCollections();

        logger.info('📋 Listed ChromaDB collections', { count: collections.length });

        res.json({
            success: true,
            collections: collections.map(c => ({
                name: c.name,
                metadata: c.metadata
            })),
            count: collections.length
        });
    } catch (error) {
        logger.error('❌ Failed to list collections', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to list collections',
            details: error.message
        });
    }
});

/**
 * GET /api/chroma/originals
 * Query original seed domains
 *
 * Query params:
 * - limit: Number of results (default: 10, max: 100)
 * - offset: Skip first N results (default: 0)
 * - registrable: Filter by registrable domain (exact match)
 * - cse_id: Filter by CSE ID (brand identifier)
 * - has_verdict: Filter by verdict presence (true/false)
 * - verdict: Filter by verdict value (e.g., "phishing", "suspicious", "clean")
 */
router.get('/originals', async (req, res) => {
    try {
        if (!chromaClient) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB client not initialized'
            });
        }

        const limit = Math.min(parseInt(req.query.limit) || 10, 100);
        const offset = parseInt(req.query.offset) || 0;

        // Build where filter
        const where = {};
        if (req.query.registrable) {
            where.registrable = req.query.registrable;
        }
        if (req.query.cse_id) {
            where.cse_id = req.query.cse_id;
        }
        if (req.query.has_verdict !== undefined) {
            where.has_verdict = req.query.has_verdict === 'true';
        }
        if (req.query.verdict) {
            where.verdict = req.query.verdict;
        }

        const collection = await chromaClient.getCollection({ name: ORIGINALS_COLLECTION });

        // Get results with filters
        const results = await collection.get({
            where: Object.keys(where).length > 0 ? where : undefined,
            limit: limit,
            offset: offset,
            include: ['metadatas', 'documents']
        });

        logger.info('🔍 Queried original domains', {
            collection: ORIGINALS_COLLECTION,
            filters: where,
            count: results.ids.length,
            limit,
            offset
        });

        // Format response - extract IPv4 and nameserver from document
        const domains = results.ids.map((id, idx) => {
            const metadata = results.metadatas[idx];
            const document = results.documents[idx];

            // Extract IPv4 address from document
            const ipv4 = extractIPv4(document);

            // Extract nameserver from document
            const nameserver = extractNameserver(document);

            // Format first_seen timestamp to human-readable format
            const firstSeenFormatted = metadata.first_seen
                ? formatTimestamp(metadata.first_seen)
                : null;

            // Create enhanced metadata with extracted fields
            // Remove first_seen and replace with first_seen_formatted
            const { first_seen, ...metadataWithoutFirstSeen } = metadata;
            const enhancedMetadata = {
                ...metadataWithoutFirstSeen,
                ipv4: ipv4,
                nameserver: nameserver,
                first_seen: firstSeenFormatted
            };

            return {
                id: id,
                metadata: enhancedMetadata,
                document: document
            };
        });

        res.json({
            success: true,
            collection: ORIGINALS_COLLECTION,
            count: domains.length,
            limit: limit,
            offset: offset,
            filters: where,
            domains: domains
        });

    } catch (error) {
        logger.error('❌ Failed to query original domains', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to query original domains',
            details: error.message
        });
    }
});

/**
 * GET /api/chroma/variants
 * Query lookalike/variant domains
 *
 * Query params:
 * - limit: Number of results (default: 10, max: 1000)
 * - offset: Skip first N results (default: 0)
 * - registrable: Filter by registrable domain (exact match)
 * - seed_registrable: Filter by seed (original brand)
 * - cse_id: Filter by CSE ID (brand identifier)
 * - has_verdict: Filter by verdict presence (true/false)
 * - verdict: Filter by verdict value (e.g., "phishing", "suspicious", "parked")
 * - risk_score_min: Minimum risk score (0-100)
 * - risk_score_max: Maximum risk score (0-100)
 * - is_newly_registered: Filter newly registered domains (true/false)
 */
router.get('/variants', async (req, res) => {
    try {
        if (!chromaClient) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB client not initialized'
            });
        }

        const limit = Math.min(parseInt(req.query.limit) || 10, 1000);
        const offset = parseInt(req.query.offset) || 0;

        // Build where filter
        const where = {};
        if (req.query.registrable) {
            where.registrable = req.query.registrable;
        }
        if (req.query.seed_registrable) {
            where.seed_registrable = req.query.seed_registrable;
        }
        if (req.query.cse_id) {
            where.cse_id = req.query.cse_id;
        }
        if (req.query.has_verdict !== undefined) {
            where.has_verdict = req.query.has_verdict === 'true';
        }
        if (req.query.verdict) {
            where.verdict = req.query.verdict;
        }
        if (req.query.is_newly_registered !== undefined) {
            where.is_newly_registered = req.query.is_newly_registered === 'true';
        }

        // Handle risk score range (requires special handling in ChromaDB)
        if (req.query.risk_score_min !== undefined || req.query.risk_score_max !== undefined) {
            const min = parseInt(req.query.risk_score_min) || 0;
            const max = parseInt(req.query.risk_score_max) || 100;
            where.risk_score = { $gte: min, $lte: max };
        }

        const collection = await chromaClient.getCollection({ name: VARIANTS_COLLECTION });

        // Get results with filters
        const results = await collection.get({
            where: Object.keys(where).length > 0 ? where : undefined,
            limit: limit,
            offset: offset,
            include: ['metadatas', 'documents']
        });

        logger.info('🔍 Queried variant domains', {
            collection: VARIANTS_COLLECTION,
            filters: where,
            count: results.ids.length,
            limit,
            offset
        });

        // Format response
        const domains = results.ids.map((id, idx) => ({
            id: id,
            metadata: results.metadatas[idx],
            document: results.documents[idx]
        }));

        res.json({
            success: true,
            collection: VARIANTS_COLLECTION,
            count: domains.length,
            limit: limit,
            offset: offset,
            filters: where,
            domains: domains
        });

    } catch (error) {
        logger.error('❌ Failed to query variant domains', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to query variant domains',
            details: error.message
        });
    }
});

/**
 * GET /api/chroma/search
 * Semantic search across collections using natural language
 *
 * Query params:
 * - query: Natural language search query (required)
 * - collection: Which collection to search ("originals", "variants", or "both", default: "both")
 * - limit: Number of results per collection (default: 5, max: 50)
 */
router.get('/search', async (req, res) => {
    try {
        if (!chromaClient) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB client not initialized'
            });
        }

        const query = req.query.query;
        if (!query) {
            return res.status(400).json({
                success: false,
                error: 'Missing required parameter: query'
            });
        }

        const collectionType = req.query.collection || 'both';
        const limit = Math.min(parseInt(req.query.limit) || 5, 50);

        const results = {};

        // Search originals
        if (collectionType === 'originals' || collectionType === 'both') {
            try {
                const originalsCol = await chromaClient.getCollection({ name: ORIGINALS_COLLECTION });
                const originalsResults = await originalsCol.query({
                    queryTexts: [query],
                    nResults: limit,
                    include: ['metadatas', 'documents', 'distances']
                });

                results.originals = originalsResults.ids[0].map((id, idx) => ({
                    id: id,
                    metadata: originalsResults.metadatas[0][idx],
                    document: originalsResults.documents[0][idx],
                    distance: originalsResults.distances[0][idx],
                    similarity: (1 - originalsResults.distances[0][idx]).toFixed(4)
                }));
            } catch (error) {
                logger.warn(`⚠️ Could not search originals collection: ${error.message}`);
                results.originals = [];
            }
        }

        // Search variants
        if (collectionType === 'variants' || collectionType === 'both') {
            try {
                const variantsCol = await chromaClient.getCollection({ name: VARIANTS_COLLECTION });
                const variantsResults = await variantsCol.query({
                    queryTexts: [query],
                    nResults: limit,
                    include: ['metadatas', 'documents', 'distances']
                });

                results.variants = variantsResults.ids[0].map((id, idx) => ({
                    id: id,
                    metadata: variantsResults.metadatas[0][idx],
                    document: variantsResults.documents[0][idx],
                    distance: variantsResults.distances[0][idx],
                    similarity: (1 - variantsResults.distances[0][idx]).toFixed(4)
                }));
            } catch (error) {
                logger.warn(`⚠️ Could not search variants collection: ${error.message}`);
                results.variants = [];
            }
        }

        logger.info('🔎 Semantic search completed', {
            query,
            collectionType,
            originals_count: results.originals?.length || 0,
            variants_count: results.variants?.length || 0
        });

        res.json({
            success: true,
            query: query,
            collection_type: collectionType,
            limit: limit,
            results: results
        });

    } catch (error) {
        logger.error('❌ Semantic search failed', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Semantic search failed',
            details: error.message
        });
    }
});

/**
 * GET /api/chroma/domain/:domain
 * Get full details for a specific domain (searches both collections)
 */
router.get('/domain/:domain', async (req, res) => {
    try {
        if (!chromaClient) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB client not initialized'
            });
        }

        const domain = req.params.domain;
        let found = null;
        let collectionName = null;

        // Search in originals first - try multiple strategies
        try {
            const originalsCol = await chromaClient.getCollection({ name: ORIGINALS_COLLECTION });

            // Strategy 1: Get all IDs and find by prefix match (since ID format is "domain:hash")
            const allOriginals = await originalsCol.get({
                limit: 10000,  // Get all (reasonable limit)
                include: ['metadatas', 'documents']
            });

            // Find by ID prefix match (ID format: "sbi.bank.in:hash")
            const matchIndex = allOriginals.ids.findIndex(id => id.startsWith(domain + ':'));

            if (matchIndex >= 0) {
                found = {
                    id: allOriginals.ids[matchIndex],
                    metadata: allOriginals.metadatas[matchIndex],
                    document: allOriginals.documents[matchIndex]
                };
                collectionName = ORIGINALS_COLLECTION;
            }
        } catch (error) {
            logger.warn(`⚠️ Could not search originals: ${error.message}`);
        }

        // If not found in originals, search variants
        if (!found) {
            try {
                const variantsCol = await chromaClient.getCollection({ name: VARIANTS_COLLECTION });

                // Strategy 1: Get all IDs and find by prefix match
                const allVariants = await variantsCol.get({
                    limit: 50000,  // Variants collection may be larger
                    include: ['metadatas', 'documents']
                });

                // Find by ID prefix match
                const matchIndex = allVariants.ids.findIndex(id => id.startsWith(domain + ':'));

                if (matchIndex >= 0) {
                    found = {
                        id: allVariants.ids[matchIndex],
                        metadata: allVariants.metadatas[matchIndex],
                        document: allVariants.documents[matchIndex]
                    };
                    collectionName = VARIANTS_COLLECTION;
                }
            } catch (error) {
                logger.warn(`⚠️ Could not search variants: ${error.message}`);
            }
        }

        if (!found) {
            logger.info(`🔍 Domain not found: ${domain}`);
            return res.status(404).json({
                success: false,
                error: 'Domain not found',
                domain: domain
            });
        }

        logger.info('✅ Domain found', { domain, collection: collectionName });

        // Build response object
        const response = {
            success: true,
            domain: domain,
            collection: collectionName,
            is_original_seed: collectionName === ORIGINALS_COLLECTION,
            data: found
        };

        // Add DNSTwist stats for original seeds only
        if (collectionName === ORIGINALS_COLLECTION && found.metadata) {
            // Check if stats are already in metadata (ingested from Redis)
            if (found.metadata.dnstwist_variants_registered !== undefined ||
                found.metadata.dnstwist_total_generated !== undefined) {
                response.dnstwist_stats = {
                    variants_registered: found.metadata.dnstwist_variants_registered || 0,
                    variants_unregistered: found.metadata.dnstwist_variants_unregistered || 0,
                    total_variants_generated: found.metadata.dnstwist_total_generated || 0,
                    processed_at: found.metadata.dnstwist_processed_at || 0,
                    processed_date: found.metadata.dnstwist_processed_at ?
                        new Date(found.metadata.dnstwist_processed_at * 1000).toISOString() : null
                };
                logger.info('📊 Added DNSTwist stats from metadata', {
                    domain,
                    registered: response.dnstwist_stats.variants_registered,
                    unregistered: response.dnstwist_stats.variants_unregistered
                });
            } else {
                // Fallback: fetch from Redis if not in metadata (for existing data)
                const dnstwistStats = await getDnstwistStats(domain);
                if (dnstwistStats) {
                    response.dnstwist_stats = dnstwistStats;
                    logger.info('📊 Added DNSTwist stats from Redis (fallback)', {
                        domain,
                        registered: dnstwistStats.variants_registered,
                        unregistered: dnstwistStats.variants_unregistered
                    });
                }
            }
        }

        res.json(response);

    } catch (error) {
        logger.error('❌ Failed to get domain details', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to get domain details',
            details: error.message
        });
    }
});

/**
 * GET /api/chroma/stats
 * Get collection statistics
 */
router.get('/stats', async (req, res) => {
    try {
        if (!chromaClient) {
            return res.status(503).json({
                success: false,
                error: 'ChromaDB client not initialized'
            });
        }

        const stats = {};

        // Get originals stats
        try {
            const originalsCol = await chromaClient.getCollection({ name: ORIGINALS_COLLECTION });
            const originalsCount = await originalsCol.count();
            stats.originals = {
                name: ORIGINALS_COLLECTION,
                count: originalsCount
            };
        } catch (error) {
            stats.originals = { error: error.message };
        }

        // Get variants stats
        try {
            const variantsCol = await chromaClient.getCollection({ name: VARIANTS_COLLECTION });
            const variantsCount = await variantsCol.count();
            stats.variants = {
                name: VARIANTS_COLLECTION,
                count: variantsCount
            };
        } catch (error) {
            stats.variants = { error: error.message };
        }

        logger.info('📊 Collection stats retrieved');

        res.json({
            success: true,
            chroma_host: `${CHROMA_HOST}:${CHROMA_PORT}`,
            collections: stats,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        logger.error('❌ Failed to get stats', { error: error.message });
        res.status(500).json({
            success: false,
            error: 'Failed to get collection stats',
            details: error.message
        });
    }
});

module.exports = router;
