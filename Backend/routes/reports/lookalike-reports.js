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
 * Helper: Calculate risk level based on variant counts
 */
function calculateRisk(variantCounts) {
    const { phishing = 0, suspicious = 0, parked = 0, inactive = 0, unregistered = 0, total = 0 } = variantCounts;

    if (total === 0) return { level: 'Low', score: 0 };

    // Calculate risk score (0-100)
    const phishingWeight = phishing * 10;
    const suspiciousWeight = suspicious * 5;
    const parkedWeight = parked * 3;
    const inactiveWeight = inactive * 1;

    const rawScore = phishingWeight + suspiciousWeight + parkedWeight + inactiveWeight;
    const normalizedScore = Math.min(100, Math.round((rawScore / total) * 10));

    // Determine risk level
    let level;
    if (normalizedScore >= 75) level = 'Critical';
    else if (normalizedScore >= 50) level = 'High';
    else if (normalizedScore >= 25) level = 'Moderate';
    else if (normalizedScore >= 10) level = 'Elevated';
    else level = 'Low';

    return { level, score: normalizedScore };
}

/**
 * GET /api/reports/lookalikes
 * Returns lookalike/variant domains detected via DNSTwist
 */
router.get('/reports/lookalikes', async (req, res) => {
    try {
        const seed = req.query.seed;
        const verdict = req.query.verdict;
        const fuzzer = req.query.fuzzer;
        const registrar = req.query.registrar;
        const minRiskScore = parseInt(req.query.min_risk_score) || 0;
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const sortBy = req.query.sort_by || 'risk_score';
        const order = req.query.order === 'asc' ? 'asc' : 'desc';

        const collection = await chroma.getCollection({ name: VARIANTS_COLLECTION });

        const where = {};
        if (seed) where.seed_registrable = seed;
        if (verdict) where.verdict = verdict.toLowerCase();
        if (fuzzer) where.fuzzer = fuzzer;
        if (registrar) where.registrar = registrar;

        const results = await collection.get({
            where: Object.keys(where).length > 0 ? where : undefined,
            limit: limit + offset,
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

        let transformed = results.metadatas.map((meta, idx) => {
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
            } catch (e) {}

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

        if (minRiskScore > 0) {
            transformed = transformed.filter(item => item.risk_score >= minRiskScore);
        }

        transformed.sort((a, b) => {
            let aVal = a[sortBy];
            let bVal = b[sortBy];
            if (aVal === null || aVal === undefined) return 1;
            if (bVal === null || bVal === undefined) return -1;
            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return order === 'asc' ? aVal - bVal : bVal - aVal;
            }
            aVal = String(aVal).toLowerCase();
            bVal = String(bVal).toLowerCase();
            return order === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });

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
 * Returns list of seed domains with risk calculation
 * NEW: Queries seed_domains collection directly, then calculates variant stats from domains collection
 */
router.get('/reports/lookalikes/seeds', async (req, res) => {
    try {
        // Get seed domains collection
        const seedDomainsCollection = await chroma.getCollection({ name: 'seed_domains' });
        const variantsCollection = await chroma.getCollection({ name: VARIANTS_COLLECTION });

        // Fetch all seed domains
        const seedResults = await seedDomainsCollection.get({
            include: ['metadatas', 'documents']
        });

        if (!seedResults || !seedResults.metadatas || seedResults.metadatas.length === 0) {
            return res.json({
                success: true,
                seeds: [],
                count: 0
            });
        }

        // Fetch all variants to calculate counts per seed
        const variantResults = await variantsCollection.get({
            include: ['metadatas']
        });

        // Calculate variant counts per seed
        const variantCountsPerSeed = new Map();

        if (variantResults && variantResults.metadatas) {
            variantResults.metadatas.forEach(meta => {
                const seed = meta.seed_registrable;
                if (!seed) return;

                if (!variantCountsPerSeed.has(seed)) {
                    variantCountsPerSeed.set(seed, {
                        phishing: 0,
                        suspicious: 0,
                        parked: 0,
                        clean: 0,
                        inactive: 0,
                        unregistered: 0,
                        total: 0
                    });
                }

                const counts = variantCountsPerSeed.get(seed);
                counts.total++;

                const verdict = (meta.verdict || 'unknown').toLowerCase();
                const isInactive = meta.is_inactive || meta.inactive_status;

                if (isInactive || verdict === 'inactive' || verdict === 'unregistered') {
                    counts.inactive++;
                } else if (verdict === 'phishing') {
                    counts.phishing++;
                } else if (verdict === 'suspicious') {
                    counts.suspicious++;
                } else if (verdict === 'parked') {
                    counts.parked++;
                } else if (verdict === 'clean') {
                    counts.clean++;
                }
            });
        }

        // Build seeds array from seed_domains collection
        const seeds = seedResults.metadatas.map((seedMeta, idx) => {
            const seedDomain = seedMeta.registrable || seedMeta.seed_registrable;

            // Get variant counts for this seed (may be 0 if no variants yet)
            const variantCounts = variantCountsPerSeed.get(seedDomain) || {
                phishing: 0,
                suspicious: 0,
                parked: 0,
                clean: 0,
                inactive: 0,
                unregistered: 0,
                total: 0
            };

            const risk = calculateRisk(variantCounts);

            // Extract DNS data from seed document
            let ipAddress = null;
            let nameserver = null;
            let mxRecord = null;

            if (seedResults.documents && seedResults.documents[idx]) {
                try {
                    const doc = seedResults.documents[idx];
                    if (doc) {
                        const ipMatch = doc.match(/A \(IPv4\): ([\d.]+)/);
                        if (ipMatch) ipAddress = ipMatch[1];

                        const mxMatch = doc.match(/MX \(Mail\): ([^\n]+)/);
                        if (mxMatch) mxRecord = mxMatch[1].split(',')[0].trim();

                        const nsMatch = doc.match(/NS \(Nameservers\): ([^\n]+)/);
                        if (nsMatch) nameserver = nsMatch[1].split(',')[0].trim();
                    }
                } catch (e) {}
            }

            return {
                seed_domain: seedDomain,
                ip_address: ipAddress,
                url: seedMeta.url || `https://${seedDomain}`,
                nameserver: nameserver,
                mx_record: mxRecord,
                registration_date: computeRegistrationDate(seedMeta.domain_age_days),
                registrar: seedMeta.registrar || null,
                risk_score: risk.score,
                variant_counts: variantCounts
            };
        });

        seeds.sort((a, b) => {
            const domainA = a.seed_domain || '';
            const domainB = b.seed_domain || '';
            return domainA.localeCompare(domainB);
        });

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
        const collection = await chroma.getCollection({ name: VARIANTS_COLLECTION });

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
            const verdict = meta.verdict || 'unknown';
            stats.by_verdict[verdict] = (stats.by_verdict[verdict] || 0) + 1;

            const fuzzer = meta.fuzzer || 'unknown';
            stats.by_fuzzer[fuzzer] = (stats.by_fuzzer[fuzzer] || 0) + 1;

            const registrar = meta.registrar || 'unknown';
            stats.by_registrar[registrar] = (stats.by_registrar[registrar] || 0) + 1;

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
