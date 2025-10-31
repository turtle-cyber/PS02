const { client: redisClient, isRedisReady } = require('./redisClient');

const JOB_TTL = 24 * 60 * 60; // 24 hours
const MAX_ERRORS_STORED = 100;

class BulkJobManager {
  /**
   * Create a new bulk job
   */
  async createJob(jobId, metadata) {
    if (!isRedisReady()) {
      console.warn('[BulkJobManager] Redis not available, using in-memory fallback');
      return jobId;
    }

    const now = new Date().toISOString();

    try {
      // Store metadata
      await redisClient.hSet(`bulk:job:${jobId}:meta`, {
        job_id: jobId,
        status: 'queuing',
        created_at: now,
        updated_at: now,
        ...metadata
      });

      // Initialize progress
      await redisClient.hSet(`bulk:job:${jobId}:progress`, {
        total: 0,
        parsed: 0,
        queued: 0,
        processing: 0,
        completed: 0,
        failed: 0,
        percentage: '0'
      });

      // Add to active jobs sorted set (score = timestamp)
      await redisClient.zAdd('bulk:jobs:active', {
        score: Date.now(),
        value: jobId
      });

      // Set TTL
      await redisClient.expire(`bulk:job:${jobId}:meta`, JOB_TTL);
      await redisClient.expire(`bulk:job:${jobId}:progress`, JOB_TTL);

      console.log('[BulkJobManager] Created job:', jobId);
      return jobId;
    } catch (error) {
      console.error('[BulkJobManager] Error creating job:', error.message);
      throw error;
    }
  }

  /**
   * Update job progress
   */
  async updateProgress(jobId, progressData) {
    if (!isRedisReady()) return;

    try {
      const percentage = progressData.total > 0
        ? ((progressData.completed + progressData.failed) / progressData.total) * 100
        : 0;

      await redisClient.hSet(`bulk:job:${jobId}:progress`, {
        total: String(progressData.total || 0),
        parsed: String(progressData.parsed || 0),
        queued: String(progressData.queued || 0),
        processing: String(progressData.processing || 0),
        completed: String(progressData.completed || 0),
        failed: String(progressData.failed || 0),
        percentage: percentage.toFixed(2)
      });

      await redisClient.hSet(`bulk:job:${jobId}:meta`, {
        updated_at: new Date().toISOString()
      });
    } catch (error) {
      console.error('[BulkJobManager] Error updating progress:', error.message);
    }
  }

  /**
   * Update job status
   */
  async updateStatus(jobId, status) {
    if (!isRedisReady()) return;

    try {
      const updates = {
        status,
        updated_at: new Date().toISOString()
      };

      if (status === 'completed' || status === 'failed') {
        updates.completed_at = new Date().toISOString();

        // Move from active to history
        await redisClient.zRem('bulk:jobs:active', jobId);
        await redisClient.zAdd('bulk:jobs:history', {
          score: Date.now(),
          value: jobId
        });

        // Trim history to last 1000 jobs
        const historyCount = await redisClient.zCard('bulk:jobs:history');
        if (historyCount > 1000) {
          await redisClient.zRemRangeByRank('bulk:jobs:history', 0, historyCount - 1001);
        }
      }

      await redisClient.hSet(`bulk:job:${jobId}:meta`, updates);
      console.log('[BulkJobManager] Updated job status:', jobId, status);
    } catch (error) {
      console.error('[BulkJobManager] Error updating status:', error.message);
    }
  }

  /**
   * Add error to job
   */
  async addError(jobId, errorData) {
    if (!isRedisReady()) return;

    try {
      const errorEntry = JSON.stringify({
        ...errorData,
        timestamp: new Date().toISOString()
      });

      await redisClient.lPush(`bulk:job:${jobId}:errors`, errorEntry);
      await redisClient.lTrim(`bulk:job:${jobId}:errors`, 0, MAX_ERRORS_STORED - 1);
      await redisClient.expire(`bulk:job:${jobId}:errors`, JOB_TTL);
    } catch (error) {
      console.error('[BulkJobManager] Error adding error:', error.message);
    }
  }

  /**
   * Get job details
   */
  async getJob(jobId) {
    if (!isRedisReady()) {
      throw new Error('Redis not available');
    }

    try {
      const [meta, progress, errorsList] = await Promise.all([
        redisClient.hGetAll(`bulk:job:${jobId}:meta`),
        redisClient.hGetAll(`bulk:job:${jobId}:progress`),
        redisClient.lRange(`bulk:job:${jobId}:errors`, 0, 9) // Get first 10 errors
      ]);

      if (!meta || Object.keys(meta).length === 0) {
        return null;
      }

      // Parse errors
      const errors = errorsList.map(e => {
        try {
          return JSON.parse(e);
        } catch {
          return { error: e };
        }
      });

      // Calculate timing
      const createdAt = new Date(meta.created_at);
      const now = new Date();
      const elapsedSeconds = Math.floor((now - createdAt) / 1000);

      const completed = parseInt(progress.completed) || 0;
      const failed = parseInt(progress.failed) || 0;
      const processed = completed + failed;
      const total = parseInt(progress.total) || 1;
      const urlsPerSecond = elapsedSeconds > 0 ? processed / elapsedSeconds : 0;
      const remaining = total - processed;
      const estimatedRemainingSeconds = urlsPerSecond > 0
        ? Math.ceil(remaining / urlsPerSecond)
        : 0;

      return {
        job: meta,
        progress: {
          total: parseInt(progress.total) || 0,
          parsed: parseInt(progress.parsed) || 0,
          queued: parseInt(progress.queued) || 0,
          processing: parseInt(progress.processing) || 0,
          completed: parseInt(progress.completed) || 0,
          failed: parseInt(progress.failed) || 0,
          percentage: parseFloat(progress.percentage) || 0
        },
        timing: {
          elapsed_seconds: elapsedSeconds,
          estimated_remaining_seconds: estimatedRemainingSeconds,
          urls_per_second: parseFloat(urlsPerSecond.toFixed(2))
        },
        errors: {
          count: errors.length,
          sample: errors
        }
      };
    } catch (error) {
      console.error('[BulkJobManager] Error getting job:', error.message);
      throw error;
    }
  }

  /**
   * Get all active jobs
   */
  async getActiveJobs({ limit = 20 } = {}) {
    if (!isRedisReady()) {
      throw new Error('Redis not available');
    }

    try {
      // Get active job IDs (most recent first)
      const jobIds = await redisClient.zRange('bulk:jobs:active', 0, limit - 1, {
        REV: true
      });

      if (jobIds.length === 0) {
        return {
          total: 0,
          jobs: []
        };
      }

      // Fetch job summaries
      const jobs = await Promise.all(
        jobIds.map(async (jobId) => {
          try {
            const meta = await redisClient.hGetAll(`bulk:job:${jobId}:meta`);
            const progress = await redisClient.hGetAll(`bulk:job:${jobId}:progress`);

            if (!meta || Object.keys(meta).length === 0) {
              return null;
            }

            return {
              job_id: meta.job_id,
              status: meta.status,
              created_at: meta.created_at,
              updated_at: meta.updated_at,
              file_name: meta.file_name || 'N/A',
              total_urls: parseInt(progress.total) || 0,
              completed: parseInt(progress.completed) || 0,
              failed: parseInt(progress.failed) || 0,
              percentage: parseFloat(progress.percentage) || 0,
              pipeline: meta.pipeline || 'unknown'
            };
          } catch (error) {
            console.error('[BulkJobManager] Error fetching job summary:', jobId, error.message);
            return null;
          }
        })
      );

      // Filter out null entries
      const validJobs = jobs.filter(j => j !== null);

      return {
        total: validJobs.length,
        jobs: validJobs
      };
    } catch (error) {
      console.error('[BulkJobManager] Error getting active jobs:', error.message);
      throw error;
    }
  }

  /**
   * Delete/cancel a job
   */
  async deleteJob(jobId) {
    if (!isRedisReady()) {
      throw new Error('Redis not available');
    }

    try {
      await Promise.all([
        redisClient.del(`bulk:job:${jobId}:meta`),
        redisClient.del(`bulk:job:${jobId}:progress`),
        redisClient.del(`bulk:job:${jobId}:errors`),
        redisClient.zRem('bulk:jobs:active', jobId),
        redisClient.zRem('bulk:jobs:history', jobId)
      ]);

      console.log('[BulkJobManager] Deleted job:', jobId);
    } catch (error) {
      console.error('[BulkJobManager] Error deleting job:', error.message);
      throw error;
    }
  }
}

module.exports = new BulkJobManager();
