const express = require('express');
const { Kafka } = require('kafkajs');
const winston = require('winston');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { URL } = require('url');
const urlDetectionRouter = require('./routes/urlDetection/url-detection');
const monitoringStatsRouter = require('./routes/monitoring/monitoring-stats');
const dnstwistStatsRouter = require('./routes/dnstwist/dnstwist-stats');
const fcrawlerStatsRouter = require('./routes/featureCrawler/fcrawler-stats');
const artifactsRouter = require('./routes/artifacts/artifacts');
const chromaQueryRouter = require('./routes/chroma/chroma-query');

// ============================================
// Configuration
// ============================================
const PORT = process.env.PORT || 3000;
const KAFKA_BROKERS = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');
const KAFKA_TOPIC = process.env.KAFKA_TOPIC || 'raw.hosts';

// ============================================
// Logger Setup
// ============================================
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

logger.info('🚀 Starting Phishing Detection Frontend API');
logger.info(`📋 Configuration: PORT=${PORT}, KAFKA_BROKERS=${KAFKA_BROKERS.join(',')}, KAFKA_TOPIC=${KAFKA_TOPIC}`);

// ============================================
// Kafka Setup
// ============================================
const kafka = new Kafka({
    clientId: 'frontend-api',
    brokers: KAFKA_BROKERS,
    retry: {
        initialRetryTime: 100,
        retries: 8
    }
});

const producer = kafka.producer();
let producerReady = false;

// In-memory job tracking (for bulk submissions)
const bulkJobs = new Map(); // jobId -> { status, total, completed, errors, startTime, ... }

// Initialize Kafka producer
(async () => {
    try {
        logger.info('🔌 Connecting to Kafka...');
        await producer.connect();
        producerReady = true;
        logger.info('✅ Kafka producer connected successfully');
    } catch (error) {
        logger.error('❌ Failed to connect Kafka producer', { error: error.message });
        process.exit(1);
    }
})();

// Graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('🛑 SIGTERM received, shutting down gracefully');
    await producer.disconnect();
    process.exit(0);
});

// ============================================
// Express App Setup
// ============================================
const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false  // Allow inline styles for simple HTML
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Request logging middleware
app.use((req, res, next) => {
    logger.info('📥 Incoming request', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    next();
});

// ============================================
// Helper Functions
// ============================================

/**
 * Extract domain from URL or return as-is if already a domain
 */
function extractDomain(input) {
    try {
        if (input.startsWith('http://') || input.startsWith('https://')) {
            const parsed = new URL(input);
            return parsed.hostname;
        }
        // Already a domain
        return input.toLowerCase().trim();
    } catch (error) {
        // If parsing fails, return cleaned input
        return input.toLowerCase().trim();
    }
}

/**
 * Validate domain format
 */
function isValidDomain(domain) {
    // Basic domain validation regex
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
}

// ============================================
// API Routes
// ============================================

app.use('/api', urlDetectionRouter);
app.use('/api', monitoringStatsRouter);
app.use('/api', dnstwistStatsRouter);
app.use('/api', fcrawlerStatsRouter);
app.use('/api', artifactsRouter);
app.use('/api/chroma', chromaQueryRouter);

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
    const health = {
        status: producerReady ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        kafka: {
            connected: producerReady,
            brokers: KAFKA_BROKERS,
            topic: KAFKA_TOPIC
        }
    };

    logger.debug('🏥 Health check', health);
    res.json(health);
});

/**
 * Submit URL/domain for analysis
 */
app.post('/api/submit', async (req, res) => {
    const startTime = Date.now();
    const { url, domain, cse_id, notes, use_full_pipeline } = req.body;
    const inputUrl = url || domain;
    const useFullPipeline = use_full_pipeline === true || use_full_pipeline === 'true';

    logger.info('🎯 New submission request', {
        input: inputUrl,
        cse_id: cse_id,
        notes: notes,
        use_full_pipeline: useFullPipeline,
        ip: req.ip
    });

    // Validation
    if (!inputUrl) {
        logger.warn('⚠️ Submission rejected: Missing URL/domain', { ip: req.ip });
        return res.status(400).json({
            success: false,
            error: 'Missing required field: url or domain'
        });
    }

    if (!producerReady) {
        logger.error('❌ Submission rejected: Kafka not ready', { input: inputUrl });
        return res.status(503).json({
            success: false,
            error: 'Service temporarily unavailable. Kafka not connected.'
        });
    }

    try {
        // Extract domain from URL
        const extractedDomain = extractDomain(inputUrl);
        logger.info('🔍 Extracted domain', {
            input: inputUrl,
            extracted: extractedDomain
        });

        // Validate domain
        if (!isValidDomain(extractedDomain)) {
            logger.warn('⚠️ Submission rejected: Invalid domain format', {
                input: inputUrl,
                extracted: extractedDomain
            });
            return res.status(400).json({
                success: false,
                error: 'Invalid domain format',
                domain: extractedDomain
            });
        }

        // Determine target topic and message format based on pipeline choice
        let targetTopic;
        let message;
        let pipelineDescription;
        let estimatedTime;

        if (useFullPipeline) {
            // Full pipeline: raw.hosts → DNSTwist → CT-Watcher → Normalizer → ...
            targetTopic = 'raw.hosts';
            message = {
                fqdn: extractedDomain,
                source: 'frontend_api',
                timestamp: Math.floor(Date.now() / 1000),
                cse_id: cse_id,
                notes: notes,
                original_input: inputUrl,
                submitter_ip: req.ip,
                is_original_seed: true  // Mark as original seed for ChromaDB routing
            };
            pipelineDescription = 'full (includes DNSTwist variant generation)';
            estimatedTime = '3-5 minutes';
        } else {
            // Direct pipeline: domains.candidates → DNS Collector → ...
            targetTopic = 'domains.candidates';
            message = {
                fqdn: extractedDomain,
                canonical_fqdn: extractedDomain,
                registrable: extractedDomain,
                seed_registrable: extractedDomain,  // For tracking: no variants in direct flow
                source: 'frontend_api_direct',
                timestamp: Math.floor(Date.now() / 1000),
                cse_id: cse_id,
                notes: notes,
                original_input: inputUrl,
                submitter_ip: req.ip
            };
            pipelineDescription = 'direct (skips DNSTwist/CT-Watcher)';
            estimatedTime = '2-3 minutes';
        }

        // Submit to Kafka with chosen topic and message
        logger.info('📤 Submitting to Kafka', {
            topic: targetTopic,
            domain: extractedDomain,
            pipeline: pipelineDescription,
            message: message
        });

        const result = await producer.send({
            topic: targetTopic,
            messages: [
                {
                    key: extractedDomain,
                    value: JSON.stringify(message),
                    timestamp: Date.now().toString()
                }
            ]
        });

        const duration = Date.now() - startTime;

        logger.info('✅ Successfully submitted to Kafka', {
            domain: extractedDomain,
            topic: targetTopic,
            partition: result[0].partition,
            offset: result[0].offset,
            pipeline: pipelineDescription
        });

        logger.info('🎉 Submission successful', {
            domain: extractedDomain,
            duration_ms: duration,
            kafka_topic: targetTopic,
            kafka_partition: result[0].partition,
            kafka_offset: result[0].offset
        });

        res.json({
            success: true,
            message: 'Domain submitted successfully for analysis',
            domain: extractedDomain,
            original_input: inputUrl,
            kafka_topic: targetTopic,
            kafka_partition: result[0].partition,
            kafka_offset: result[0].offset,
            estimated_processing_time: estimatedTime,
            pipeline: pipelineDescription,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        const duration = Date.now() - startTime;
        logger.error('💥 Submission failed', {
            input: inputUrl,
            error: error.message,
            duration_ms: duration,
            stack: error.stack
        });

        res.status(500).json({
            success: false,
            error: 'Failed to submit domain for analysis',
            details: error.message
        });
    }
});

/**
 * Submit multiple URLs/domains for analysis (bulk submission)
 */
app.post('/api/submit-bulk', async (req, res) => {
    const startTime = Date.now();
    const { urls, use_full_pipeline, cse_id, notes } = req.body;
    const useFullPipeline = use_full_pipeline === true || use_full_pipeline === 'true';
    const jobId = `bulk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    logger.info('📦 Bulk submission request', {
        job_id: jobId,
        url_count: Array.isArray(urls) ? urls.length : 0,
        use_full_pipeline: useFullPipeline,
        cse_id: cse_id,
        ip: req.ip
    });

    // Validation
    if (!Array.isArray(urls) || urls.length === 0) {
        logger.warn('⚠️ Bulk submission rejected: Invalid URLs array', { ip: req.ip });
        return res.status(400).json({
            success: false,
            error: 'urls must be a non-empty array'
        });
    }

    // Limit batch size
    const MAX_BATCH_SIZE = 10000;
    if (urls.length > MAX_BATCH_SIZE) {
        logger.warn('⚠️ Bulk submission rejected: Batch too large', {
            count: urls.length,
            max: MAX_BATCH_SIZE
        });
        return res.status(400).json({
            success: false,
            error: `Batch size exceeds maximum of ${MAX_BATCH_SIZE} URLs`,
            provided: urls.length,
            max: MAX_BATCH_SIZE
        });
    }

    if (!producerReady) {
        logger.error('❌ Bulk submission rejected: Kafka not ready');
        return res.status(503).json({
            success: false,
            error: 'Service temporarily unavailable. Kafka not connected.'
        });
    }

    // Determine target topic and pipeline description
    let targetTopic;
    let pipelineDescription;
    let estimatedTimePerUrl;

    if (useFullPipeline) {
        targetTopic = 'raw.hosts';
        pipelineDescription = 'full (includes DNSTwist variant generation)';
        estimatedTimePerUrl = '3-5 minutes';
    } else {
        targetTopic = 'domains.candidates';
        pipelineDescription = 'direct (skips DNSTwist/CT-Watcher)';
        estimatedTimePerUrl = '2-3 minutes';
    }

    // Initialize job tracking
    bulkJobs.set(jobId, {
        status: 'processing',
        total: urls.length,
        completed: 0,
        successful: 0,
        failed: 0,
        startTime: new Date().toISOString(),
        pipeline: pipelineDescription,
        topic: targetTopic
    });

    // Process all URLs
    const results = [];
    const errors = [];
    let successCount = 0;

    try {
        for (let i = 0; i < urls.length; i++) {
            const inputUrl = urls[i];

            try {
                // Extract and validate domain
                const extractedDomain = extractDomain(inputUrl);

                if (!isValidDomain(extractedDomain)) {
                    errors.push({
                        index: i,
                        url: inputUrl,
                        error: 'Invalid domain format',
                        domain: extractedDomain
                    });
                    continue;
                }

                // Create message based on pipeline choice
                let message;
                if (useFullPipeline) {
                    message = {
                        fqdn: extractedDomain,
                        source: 'frontend_api_bulk',
                        timestamp: Math.floor(Date.now() / 1000),
                        cse_id: cse_id,
                        notes: notes,
                        original_input: inputUrl,
                        submitter_ip: req.ip,
                        bulk_batch_index: i,
                        is_original_seed: true  // Mark as original seed for ChromaDB routing
                    };
                } else {
                    message = {
                        fqdn: extractedDomain,
                        canonical_fqdn: extractedDomain,
                        registrable: extractedDomain,
                        seed_registrable: extractedDomain,  // For tracking: no variants in direct flow
                        source: 'frontend_api_bulk_direct',
                        timestamp: Math.floor(Date.now() / 1000),
                        cse_id: cse_id,
                        notes: notes,
                        original_input: inputUrl,
                        submitter_ip: req.ip,
                        bulk_batch_index: i
                    };
                }

                // Send to Kafka
                const result = await producer.send({
                    topic: targetTopic,
                    messages: [
                        {
                            key: extractedDomain,
                            value: JSON.stringify(message),
                            timestamp: Date.now().toString()
                        }
                    ]
                });

                results.push({
                    index: i,
                    url: inputUrl,
                    domain: extractedDomain,
                    status: 'queued',
                    partition: result[0].partition,
                    offset: result[0].offset
                });

                successCount++;

                // Update job progress
                const job = bulkJobs.get(jobId);
                if (job) {
                    job.completed = i + 1;
                    job.successful = successCount;
                }

                // Log progress every 100 URLs
                if ((i + 1) % 100 === 0) {
                    logger.info(`📦 Bulk progress: ${i + 1}/${urls.length} URLs queued`);
                }

            } catch (error) {
                logger.error('❌ Failed to process URL in bulk', {
                    index: i,
                    url: inputUrl,
                    error: error.message
                });
                errors.push({
                    index: i,
                    url: inputUrl,
                    error: error.message
                });
            }
        }

        const duration = Date.now() - startTime;

        logger.info('🎉 Bulk submission completed', {
            total: urls.length,
            success: successCount,
            failed: errors.length,
            duration_ms: duration,
            kafka_topic: targetTopic,
            pipeline: pipelineDescription
        });

        // Estimate total processing time
        const avgMinutes = useFullPipeline ? 4 : 2.5; // Average of range
        const totalEstimatedMinutes = Math.ceil(successCount * avgMinutes);
        const estimatedCompletion = new Date(Date.now() + totalEstimatedMinutes * 60 * 1000).toISOString();

        // Mark job as completed
        const job = bulkJobs.get(jobId);
        if (job) {
            job.status = 'completed';
            job.endTime = new Date().toISOString();
            job.failed = errors.length;
        }

        res.json({
            success: true,
            job_id: jobId,
            message: 'Bulk submission completed',
            summary: {
                total_submitted: urls.length,
                successfully_queued: successCount,
                failed: errors.length,
                kafka_topic: targetTopic,
                pipeline: pipelineDescription
            },
            timing: {
                submission_time_ms: duration,
                estimated_time_per_url: estimatedTimePerUrl,
                estimated_total_minutes: totalEstimatedMinutes,
                estimated_completion: estimatedCompletion
            },
            results: results,
            errors: errors.length > 0 ? errors : undefined,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        const duration = Date.now() - startTime;
        logger.error('💥 Bulk submission failed critically', {
            total_urls: urls.length,
            processed: successCount,
            error: error.message,
            duration_ms: duration,
            stack: error.stack
        });

        res.status(500).json({
            success: false,
            error: 'Bulk submission failed',
            details: error.message,
            processed: successCount,
            total: urls.length
        });
    }
});

/**
 * Get bulk job status
 */
app.get('/api/job/:jobId', (req, res) => {
    const { jobId } = req.params;

    const job = bulkJobs.get(jobId);

    if (!job) {
        return res.status(404).json({
            success: false,
            error: 'Job not found',
            job_id: jobId
        });
    }

    const progress = job.total > 0 ? Math.round((job.completed / job.total) * 100) : 0;

    res.json({
        success: true,
        job_id: jobId,
        status: job.status,
        progress: {
            total: job.total,
            completed: job.completed,
            successful: job.successful,
            failed: job.failed,
            percentage: progress
        },
        timing: {
            start_time: job.startTime,
            end_time: job.endTime || null
        },
        pipeline: {
            mode: job.pipeline,
            topic: job.topic
        }
    });
});

/**
 * Get submission statistics
 */
app.get('/api/stats', (req, res) => {
    const stats = {
        uptime_seconds: Math.floor(process.uptime()),
        kafka_connected: producerReady,
        kafka_topic: KAFKA_TOPIC,
        timestamp: new Date().toISOString()
    };

    logger.debug('📊 Stats request', stats);
    res.json(stats);
});

// ============================================
// Serve Static Frontend
// ============================================
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// Error Handler
// ============================================
app.use((err, req, res, next) => {
    logger.error('💥 Unhandled error', {
        error: err.message,
        stack: err.stack,
        path: req.path
    });

    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// ============================================
// Start Server
// ============================================
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`✅ Server listening on port ${PORT}`);
    logger.info(`🌐 Access the frontend at http://localhost:${PORT}`);
    logger.info(`📡 API endpoint: http://localhost:${PORT}/api/submit`);
});
