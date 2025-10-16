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
        console.log('[url-insights] Connecting to ChromaDB...');
        collection = await chroma.getCollection({ name: COLLECTION_NAME });
        chromaReady = true;
        console.log('[url-insights] ChromaDB collection connected successfully');
    } catch (error) {
        console.error('[url-insights] Failed to connect to ChromaDB:', error.message);
        chromaReady = false;
    }
})();

/**
 * Helper: Parse timestamp to ISO string
 */
function parseTimestamp(input) {
    if (!input) return null;

    // If it's already ISO format
    if (typeof input === 'string' && input.includes('T')) {
        return new Date(input).toISOString();
    }

    // If it's Unix timestamp (seconds)
    const timestamp = parseInt(input);
    if (!isNaN(timestamp)) {
        // If timestamp is in milliseconds (13 digits), convert to seconds
        const timestampSeconds = timestamp > 9999999999 ? Math.floor(timestamp / 1000) : timestamp;
        return new Date(timestampSeconds * 1000).toISOString();
    }

    // Try to parse as date string
    try {
        return new Date(input).toISOString();
    } catch (error) {
        return null;
    }
}

/**
 * GET /api/dashboard/url-insights
 * Returns last 10 phishing detections within a time frame for table display
 */
router.get('/dashboard/url-insights', async (req, res) => {
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
            // Default: last 24 hours
            const now = new Date();
            const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

            startTimeISO = last24Hours.toISOString();
            endTimeISO = now.toISOString();

            console.log('[url-insights] Using default time range (last 24 hours)');
        } else {
            // Parse timestamps
            startTimeISO = parseTimestamp(start_time);
            endTimeISO = parseTimestamp(end_time);
        }

        if (!startTimeISO || !endTimeISO) {
            return res.status(400).json({
                success: false,
                error: 'Invalid timestamp format. Use ISO 8601 (2025-10-15T00:00:00Z) or Unix timestamp'
            });
        }

        // Convert ISO timestamps to Unix epoch (seconds) for ChromaDB comparison
        const startTimeUnix = Math.floor(new Date(startTimeISO).getTime() / 1000);
        const endTimeUnix = Math.floor(new Date(endTimeISO).getTime() / 1000);

        console.log('[url-insights] Query:', {
            start_time: startTimeISO,
            end_time: endTimeISO,
            start_unix: startTimeUnix,
            end_unix: endTimeUnix
        });

        // Query ChromaDB - fetch ALL records to ensure we get the most recent ones
        // ChromaDB stores timestamps as strings, making numeric comparison difficult
        // We filter by time range and sort in JavaScript to get truly "top 10 recent"
        const results = await collection.get({
            // No limit - fetch all records to guarantee we have the newest ones
            include: ["metadatas", "documents"]
        });

        console.log('[url-insights] Found', results.ids?.length || 0, 'total records in ChromaDB');

        // Safety check for large datasets
        if (results.ids && results.ids.length > 50000) {
            console.warn('[url-insights] ⚠️  Large dataset detected:', results.ids.length, 'records - query may be slow');
        }

        // Transform results to table format and filter by time range
        const tableData = [];

        if (results.metadatas && results.metadatas.length > 0) {
            for (let i = 0; i < results.metadatas.length; i++) {
                const metadata = results.metadatas[i];
                const document = results.documents?.[i] || '';

                // Filter by time range - parse first_seen timestamp
                if (metadata.first_seen) {
                    const recordTime = new Date(metadata.first_seen).getTime();
                    const startTime = new Date(startTimeISO).getTime();
                    const endTime = new Date(endTimeISO).getTime();

                    // Skip if outside time range
                    if (recordTime < startTime || recordTime > endTime) {
                        continue;
                    }
                }

                // Extract IP address from document text
                // Format in document: "   A (IPv4): 192.168.1.1, 203.0.113.45"
                let ipAddress = 'N/A';
                const ipMatch = document.match(/A \(IPv4\):\s*([0-9.]+)/);
                if (ipMatch && ipMatch[1]) {
                    ipAddress = ipMatch[1].trim();
                }

                // Extract ASN and organization from document text
                // Format in document: "   ASN: AS12345 (Organization Name)" or "   ASN: AS12345"
                let hostingProvider = 'Unknown';
                let asn = null;
                let asnOrg = null;

                // Try to extract ASN with organization
                const asnMatchWithOrg = document.match(/ASN:\s*(AS\d+)\s*\(([^)]+)\)/);
                if (asnMatchWithOrg) {
                    asn = asnMatchWithOrg[1];
                    asnOrg = asnMatchWithOrg[2].trim();
                } else {
                    // Try to extract ASN without organization
                    const asnMatchOnly = document.match(/ASN:\s*(AS\d+)/);
                    if (asnMatchOnly) {
                        asn = asnMatchOnly[1];
                    }
                }

                // Extract country from document text
                // Format: "   Country: IN" or "   Country: IN, Mumbai"
                let country = metadata.country || null;
                if (!country) {
                    const countryMatch = document.match(/Country:\s*([A-Z]{2})/);
                    if (countryMatch) {
                        country = countryMatch[1];
                    }
                }

                // Build hosting provider string
                if (asnOrg) {
                    hostingProvider = asnOrg;
                    if (asn) {
                        hostingProvider += ` (${asn})`;
                    }
                    if (country) {
                        hostingProvider += ` - ${country}`;
                    }
                } else if (asn) {
                    hostingProvider = asn;
                    if (country) {
                        hostingProvider += ` - ${country}`;
                    }
                } else if (country) {
                    hostingProvider = country;
                }

                tableData.push({
                    source_url: metadata.url || 'N/A',
                    ip_address: ipAddress,
                    hosting_provider: hostingProvider,
                    cse_intended: metadata.seed_registrable || 'Unknown',
                    verdict: metadata.verdict || 'unknown',
                    risk_score: metadata.risk_score || metadata.score || 0,
                    confidence: metadata.confidence || 0,
                    first_seen: metadata.first_seen || 'N/A',
                    domain: metadata.registrable || 'N/A'
                });
            }
        }

        // Sort by first_seen descending (newest first) to get "last 10"
        tableData.sort((a, b) => {
            const dateA = new Date(a.first_seen);
            const dateB = new Date(b.first_seen);
            return dateB - dateA;
        });

        console.log('[url-insights] Filtered to', tableData.length, 'records within time range');

        // Limit to last 10 results
        const limitedTableData = tableData.slice(0, 10);

        console.log('[url-insights] Returning top', limitedTableData.length, 'most recent records');

        // Log the date range of returned records for debugging
        if (limitedTableData.length > 0) {
            const newest = limitedTableData[0].first_seen;
            const oldest = limitedTableData[limitedTableData.length - 1].first_seen;
            console.log('[url-insights] Date range:', oldest, 'to', newest);
        }

        res.json({
            success: true,
            query: {
                start_time: startTimeISO,
                end_time: endTimeISO,
                default_range: (!start_time || !end_time) ? 'last_24_hours' : null,
                limit: 10
            },
            total_found: tableData.length,
            returned: limitedTableData.length,
            table_data: limitedTableData,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[url-insights] Error:', error.message);
        console.error('[url-insights] Stack:', error.stack);

        res.status(500).json({
            success: false,
            error: 'Failed to fetch URL insights',
            details: error.message
        });
    }
});

module.exports = router;
