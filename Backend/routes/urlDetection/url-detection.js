const express = require('express');
const { ChromaClient } = require('chromadb');
const router = express.Router();

// Chroma DB client setup
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

// Helper function to get count from Chroma DB
async function getCount() {
    try {
        // Connect to Chroma DB and get/create the collection
        const client = chroma;

        // Use getOrCreateCollection to avoid "collection not found" errors
        const col = await client.getOrCreateCollection({
            name: 'domains',
            metadata: { "hnsw:space": "cosine" },
            embeddingFunction: new SimpleEmbeddingFunction()
        });

        // Get total count only
        const totalCount = await col.count();

        return totalCount;
    } catch (error) {
        console.error("Error fetching count from Chroma DB:", error);
        throw error;
    }
}

// Define the /url-detection endpoint
router.get('/url-detection', async (req, res) => {
    try {
        const totalCount = await getCount();

        if (totalCount === 0) {
            return res.status(200).json({
                success: true,
                message: 'No domains have been processed yet. Submit URLs to begin analysis.',
                count: 0
            });
        }

        res.json({
            success: true,
            message: 'Data fetched successfully from Chroma DB',
            rowCount: totalCount
        });
    } catch (error) {
        console.error('ChromaDB error details:', {
            message: error.message,
            name: error.name,
            stack: error.stack
        });

        res.status(500).json({
            success: false,
            error: 'Failed to fetch count from Chroma DB',
            details: error.message,
            hint: 'Ensure ChromaDB service is running and accessible'
        });
    }
});

// Export the router
module.exports = router;
