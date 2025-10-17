const redis = require('redis');

// Redis configuration
const REDIS_HOST = process.env.REDIS_HOST || 'redis';
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379');

// Create Redis client
const client = redis.createClient({
    socket: {
        host: REDIS_HOST,
        port: REDIS_PORT,
        reconnectStrategy: (retries) => {
            if (retries > 10) {
                console.error('[redis] Max reconnection attempts reached');
                return new Error('Max reconnection attempts reached');
            }
            // Exponential backoff
            return Math.min(retries * 100, 3000);
        }
    }
});

// Connection status
let isConnected = false;

// Event handlers
client.on('connect', () => {
    console.log(`[redis] Connecting to ${REDIS_HOST}:${REDIS_PORT}...`);
});

client.on('ready', () => {
    isConnected = true;
    console.log('[redis] ✅ Connected successfully');
});

client.on('error', (err) => {
    isConnected = false;
    console.error('[redis] ❌ Error:', err.message);
});

client.on('reconnecting', () => {
    console.log('[redis] 🔄 Reconnecting...');
});

client.on('end', () => {
    isConnected = false;
    console.log('[redis] Connection closed');
});

// Initialize connection
(async () => {
    try {
        await client.connect();
    } catch (error) {
        console.error('[redis] Failed to connect:', error.message);
    }
})();

// Helper function to check if Redis is available
const isRedisReady = () => {
    return isConnected && client.isOpen;
};

// Graceful shutdown
process.on('SIGTERM', async () => {
    if (client.isOpen) {
        await client.quit();
    }
});

module.exports = {
    client,
    isRedisReady
};
