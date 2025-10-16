const express = require('express');
const { ChromaClient } = require('chromadb');
const router = express.Router();

// Chroma DB client setup
const chroma = new ChromaClient({
    path: `http://${process.env.CHROMA_HOST || 'chroma'}:${process.env.CHROMA_PORT || '8000'}`
});

const SEED_COLLECTION = 'seed_domains';
const VARIANTS_COLLECTION = 'domains';

/**
 * Helper: Compute registration date from domain_age_days
 */
function computeRegistrationDate(domainAgeDays) {
    if (!domainAgeDays || domainAgeDays < 0) return null;
    const date = new Date();
    date.setDate(date.getDate() - domainAgeDays);
    return date.toISOString().split('T')[0];
}

/**
 * Helper: Extract first element from comma-separated string
 */
function extractFirst(csvString) {
    if (!csvString) return null;
    const parts = csvString.split(',').map(s => s.trim()).filter(s => s);
    return parts.length > 0 ? parts[0] : null;
}

/**
 * GET /api/reports/lookalikes
 * Returns lookalike/variant domains detected via DNSTwist
 */
router.get('/reports/lookalikes', async (req, res) => {
    try {
        // Parse query parameters
        const seed = req.query.seed;
        const verdict = req.query.verdict;
        const fuzzer = req.query.fuzzer;
        const registrar = req.query.registrar;
        const minRiskScore = parseInt(req.query.min_risk_score) || 0;
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const sortBy = req.query.sort_by || 'risk_score';
        const order = req.query.order === 'asc' ? 'asc' : 'desc';

        // Connect to ChromaDB collection
        const collection = await chroma.getCollection({ name: 'domains' });

        // Build where clause for filtering
        const where = {};
        if (seed) where.seed_registrable = seed;
        if (verdict) where.verdict = verdict.toLowerCase();
        if (fuzzer) where.fuzzer = fuzzer;
        if (registrar) where.registrar = registrar;

        // Query ChromaDB
        const results = await collection.get({
            where: Object.keys(where).length > 0 ? where : undefined,
            limit: limit + offset, // Get more to handle offset
            include: ['metadatas', 'documents']
        });

        if (!results || !results.metadatas) {
            return res.json({
                success: true,
                total_count: 0,
                returned_count: 0,
                limit: limit,
                offset: offset,
                data: [],
                timestamp: new Date().toISOString()
            });
        }

        // Transform and filter results
        let transformed = results.metadatas.map((meta, idx) => {
            // Get DNS data from document (if available)
            let ipAddress = null;
            let nameserver = null;
            let mxRecord = null;

            // Try to parse document for DNS data
            try {
                const doc = results.documents[idx];
                if (doc) {
                    // Extract IP from A records mention in document text
                    const ipMatch = doc.match(/A \(IPv4\): ([\d.]+)/);
                    if (ipMatch) ipAddress = ipMatch[1];

                    // Extract MX from document text
                    const mxMatch = doc.match(/MX \(Mail\): ([^\n]+)/);
                    if (mxMatch) mxRecord = mxMatch[1].split(',')[0].trim();

                    // Extract NS from document text
                    const nsMatch = doc.match(/NS \(Nameservers\): ([^\n]+)/);
                    if (nsMatch) nameserver = nsMatch[1].split(',')[0].trim();
                }
            } catch (e) {
                // Ignore parsing errors
            }

            return {
                domain: meta.registrable || meta.url || results.ids[idx],
                seed_domain: meta.seed_registrable || null,
                ip_address: ipAddress,
                fuzzer: meta.fuzzer || 'Generated',
                risk_score: parseInt(meta.risk_score) || 0,
                verdict: meta.verdict || 'unknown',
                nameserver: nameserver,
                mx_record: mxRecord,
                registration_date: computeRegistrationDate(meta.domain_age_days),
                registrar: meta.registrar || null,
                mx_count: parseInt(meta.mx_count) || 0,
                ns_count: parseInt(meta.ns_count) || 0,
                a_count: parseInt(meta.a_count) || 0,
                first_seen: meta.first_seen || null,
                cse_id: meta.cse_id || null,
                country: meta.country || null
            };
        });

        // Apply risk score filter
        if (minRiskScore > 0) {
            transformed = transformed.filter(item => item.risk_score >= minRiskScore);
        }

        // Sort results
        transformed.sort((a, b) => {
            let aVal = a[sortBy];
            let bVal = b[sortBy];

            // Handle null values
            if (aVal === null || aVal === undefined) return 1;
            if (bVal === null || bVal === undefined) return -1;

            // Numeric comparison
            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return order === 'asc' ? aVal - bVal : bVal - aVal;
            }

            // String comparison
            aVal = String(aVal).toLowerCase();
            bVal = String(bVal).toLowerCase();
            if (order === 'asc') {
                return aVal.localeCompare(bVal);
            } else {
                return bVal.localeCompare(aVal);
            }
        });

        // Apply pagination
        const totalCount = transformed.length;
        const paginated = transformed.slice(offset, offset + limit);

        res.json({
            success: true,
            total_count: totalCount,
            returned_count: paginated.length,
            limit: limit,
            offset: offset,
            filters: {
                seed: seed || null,
                verdict: verdict || null,
                fuzzer: fuzzer || null,
                registrar: registrar || null,
                min_risk_score: minRiskScore
            },
            data: paginated,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching lookalike reports:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch lookalike reports',
            details: error.message
        });
    }
});

/**
 * GET /api/reports/lookalikes/seeds
 * Returns list of available seed domains with their details
 */
router.get('/reports/lookalikes/seeds', async (req, res) => {
    try {
        const collection = await chroma.getCollection({ name: 'domains' });

        // Get all records
        const results = await collection.get({
            include: ['metadatas', 'documents']
        });

        if (!results || !results.metadatas) {
            return res.json({
                success: true,
                seeds: [],
                count: 0
            });
        }

        // Extract unique seed domains and find their own records
        const seedsMap = new Map();

        results.metadatas.forEach((meta, idx) => {
            const seedDomain = meta.seed_registrable;
            const currentDomain = meta.registrable;

            // If this IS the seed domain itself (not a variant)
            if (seedDomain && currentDomain === seedDomain && !seedsMap.has(seedDomain)) {
                // Parse DNS data from document
                let ipAddress = null;
                let nameserver = null;
                let mxRecord = null;

                try {
                    const doc = results.documents[idx];
                    if (doc) {
                        const ipMatch = doc.match(/A \(IPv4\): ([\d.]+)/);
                        if (ipMatch) ipAddress = ipMatch[1];

                        const mxMatch = doc.match(/MX \(Mail\): ([^\n]+)/);
                        if (mxMatch) mxRecord = mxMatch[1].split(',')[0].trim();

                        const nsMatch = doc.match(/NS \(Nameservers\): ([^\n]+)/);
                        if (nsMatch) nameserver = nsMatch[1].split(',')[0].trim();
                    }
                } catch (e) {
                    // Ignore parsing errors
                }

                seedsMap.set(seedDomain, {
                    seed_domain: seedDomain,
                    ip_address: ipAddress,
                    url: meta.url || `https://${seedDomain}`,
                    risk_score: parseInt(meta.risk_score) || null,
                    verdict: meta.verdict || null,
                    nameserver: nameserver,
                    mx_record: mxRecord,
                    registration_date: computeRegistrationDate(meta.domain_age_days),
                    registrar: meta.registrar || null,
                    cse_id: meta.cse_id || null,
                    country: meta.country || null,
                    mx_count: parseInt(meta.mx_count) || 0,
                    ns_count: parseInt(meta.ns_count) || 0,
                    a_count: parseInt(meta.a_count) || 0
                });
            }
        });

        // If seed domain itself is not in ChromaDB, still collect unique seeds without details
        results.metadatas.forEach(meta => {
            const seedDomain = meta.seed_registrable;
            if (seedDomain && !seedsMap.has(seedDomain)) {
                seedsMap.set(seedDomain, {
                    seed_domain: seedDomain,
                    ip_address: null,
                    url: `https://${seedDomain}`,
                    risk_score: null,
                    verdict: null,
                    nameserver: null,
                    mx_record: null,
                    registration_date: null,
                    registrar: null,
                    cse_id: null,
                    country: null,
                    mx_count: 0,
                    ns_count: 0,
                    a_count: 0
                });
            }
        });

        const seeds = Array.from(seedsMap.values()).sort((a, b) =>
            a.seed_domain.localeCompare(b.seed_domain)
        );

        res.json({
            success: true,
            count: seeds.length,
            seeds: seeds,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching seed domains:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch seed domains',
            details: error.message
        });
    }
});

/**
 * GET /api/reports/lookalikes/stats
 * Returns summary statistics for lookalike domains
 */
router.get('/reports/lookalikes/stats', async (req, res) => {
    try {
        const seed = req.query.seed;
        const collection = await chroma.getCollection({ name: 'domains' });

        const where = seed ? { seed_registrable: seed } : undefined;

        const results = await collection.get({
            where: where,
            include: ['metadatas']
        });

        if (!results || !results.metadatas) {
            return res.json({
                success: true,
                stats: {
                    total: 0,
                    by_verdict: {},
                    by_fuzzer: {},
                    avg_risk_score: 0
                }
            });
        }

        // Calculate statistics
        const stats = {
            total: results.metadatas.length,
            by_verdict: {},
            by_fuzzer: {},
            by_registrar: {},
            avg_risk_score: 0
        };

        let totalRiskScore = 0;
        let riskScoreCount = 0;

        results.metadatas.forEach(meta => {
            // Verdict breakdown
            const verdict = meta.verdict || 'unknown';
            stats.by_verdict[verdict] = (stats.by_verdict[verdict] || 0) + 1;

            // Fuzzer breakdown
            const fuzzer = meta.fuzzer || 'unknown';
            stats.by_fuzzer[fuzzer] = (stats.by_fuzzer[fuzzer] || 0) + 1;

            // Registrar breakdown
            const registrar = meta.registrar || 'unknown';
            stats.by_registrar[registrar] = (stats.by_registrar[registrar] || 0) + 1;

            // Risk score average
            if (meta.risk_score) {
                totalRiskScore += parseInt(meta.risk_score);
                riskScoreCount++;
            }
        });

        stats.avg_risk_score = riskScoreCount > 0 ?
            Math.round(totalRiskScore / riskScoreCount) : 0;

        res.json({
            success: true,
            seed: seed || null,
            stats: stats,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error fetching lookalike stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch lookalike statistics',
            details: error.message
        });
    }
});

module.exports = router;
