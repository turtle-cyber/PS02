const express = require('express');
const { ChromaClient } = require('chromadb'); 
const router = express.Router();

// Chroma DB client setup
const chroma = new ChromaClient({
    path: `http://${process.env.CHROMA_HOST || 'chroma'}:${process.env.CHROMA_PORT || '8000'}`
});

// Helper function to fetch data directly from Chroma DB
async function fetchData() {
    try {
        // Connect to Chroma DB and get the collection
        const client = chroma;
        const col = await client.getCollection({ name: 'domains' }); // Get collection by name

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
            return res.status(404).json({
                success: false,
                message: 'No records found in Chroma DB',
            });
        }

        res.json({
            success: true,
            message: 'Data fetched successfully from Chroma DB',
            rowCount: rows.length,
            data: rows, // Return the rows directly in the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to fetch data from Chroma DB',
            details: error.message,
        });
    }
});

// Export the router
module.exports = router;
