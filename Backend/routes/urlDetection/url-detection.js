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

// Helper function to fetch data directly from Chroma DB
async function fetchData() {
    try {
        // Connect to Chroma DB and get/create the collection
        const client = chroma;
        // Use getOrCreateCollection to avoid "collection not found" errors
        const col = await client.getOrCreateCollection({
            name: 'domains',
            metadata: { "hnsw:space": "cosine" },
            embeddingFunction: new SimpleEmbeddingFunction()
        });

        // Query Chroma DB to get all records
        const res = await col.get(); // Returns { ids, documents, metadatas }

        // Extract the IDs array (each ID represents one record/URL)
        const rows = res?.ids || [];

        return rows; // Return the array of IDs (each represents one domain/URL)
    } catch (error) {
        console.error("Error fetching data from Chroma DB:", error);
        throw error;
    }
}

// Define the /url-detection endpoint
router.get('/url-detection', async (req, res) => {
    try {
        const rows = await fetchData();

        if (rows.length === 0) {
            return res.status(200).json({
                success: true,
                message: 'No domains have been processed yet. Submit URLs to begin analysis.',
                rowCount: 0,
                data: [],
            });
        }

        res.json({
            success: true,
            message: 'Data fetched successfully from Chroma DB',
            rowCount: rows.length,
            data: rows, // Return the rows directly in the response
        });
    } catch (error) {
        console.error('ChromaDB error details:', {
            message: error.message,
            name: error.name,
            stack: error.stack
        });

        res.status(500).json({
            success: false,
            error: 'Failed to fetch data from Chroma DB',
            details: error.message,
            hint: 'Ensure ChromaDB service is running and accessible'
        });
    }
});

// Export the router
module.exports = router;
