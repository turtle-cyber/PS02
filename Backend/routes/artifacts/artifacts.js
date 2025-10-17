const express = require('express');
const path = require('path');
const fs = require('fs');
const router = express.Router();

// Configuration
const ARTIFACTS_BASE_PATH = process.env.ARTIFACTS_PATH || '/home/turtleneck/Desktop/PS02/Pipeline/out';

/**
 * Serve HTML artifacts
 * GET /api/artifacts/html/:filename
 */
router.get('/artifacts/html/:filename', (req, res) => {
    try {
        const filename = req.params.filename;

        // Security: Prevent directory traversal attacks
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.status(400).json({
                success: false,
                error: 'Invalid filename'
            });
        }

        const filePath = path.join(ARTIFACTS_BASE_PATH, 'html', filename);

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                error: 'File not found',
                path: filename
            });
        }

        // Serve the HTML file with proper content type
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.sendFile(filePath);
    } catch (error) {
        console.error('Error serving HTML artifact:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to serve HTML artifact',
            details: error.message
        });
    }
});

/**
 * Serve PDF artifacts
 * GET /api/artifacts/pdf/:filename
 */
router.get('/artifacts/pdf/:filename', (req, res) => {
    try {
        const filename = req.params.filename;

        // Security: Prevent directory traversal attacks
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.status(400).json({
                success: false,
                error: 'Invalid filename'
            });
        }

        const filePath = path.join(ARTIFACTS_BASE_PATH, 'pdfs', filename);

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                error: 'File not found',
                path: filename
            });
        }

        // Serve the PDF file with proper content type
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
        res.sendFile(filePath);
    } catch (error) {
        console.error('Error serving PDF artifact:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to serve PDF artifact',
            details: error.message
        });
    }
});

/**
 * Serve screenshot artifacts
 * GET /api/artifacts/screenshot/:filename
 */
router.get('/artifacts/screenshot/:filename', (req, res) => {
    try {
        const filename = req.params.filename;

        // Security: Prevent directory traversal attacks
        if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
            return res.status(400).json({
                success: false,
                error: 'Invalid filename'
            });
        }

        const filePath = path.join(ARTIFACTS_BASE_PATH, 'screenshots', filename);

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                error: 'File not found',
                path: filename
            });
        }

        // Serve the screenshot with proper content type
        res.setHeader('Content-Type', 'image/png');
        res.sendFile(filePath);
    } catch (error) {
        console.error('Error serving screenshot artifact:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to serve screenshot artifact',
            details: error.message
        });
    }
});

/**
 * Get artifact info (check if files exist)
 * POST /api/artifacts/check
 * Body: { html_path, pdf_path, screenshot_path }
 */
router.post('/artifacts/check', (req, res) => {
    try {
        const { html_path, pdf_path, screenshot_path } = req.body;
        const result = {
            html: { exists: false, path: null, url: null },
            pdf: { exists: false, path: null, url: null },
            screenshot: { exists: false, path: null, url: null }
        };

        // Check HTML
        if (html_path) {
            const htmlExists = fs.existsSync(html_path);
            const htmlFilename = path.basename(html_path);
            result.html = {
                exists: htmlExists,
                path: html_path,
                url: htmlExists ? `/api/artifacts/html/${htmlFilename}` : null
            };
        }

        // Check PDF
        if (pdf_path && pdf_path !== 'None') {
            const pdfExists = fs.existsSync(pdf_path);
            const pdfFilename = path.basename(pdf_path);
            result.pdf = {
                exists: pdfExists,
                path: pdf_path,
                url: pdfExists ? `/api/artifacts/pdf/${pdfFilename}` : null
            };
        }

        // Check Screenshot
        if (screenshot_path) {
            const screenshotExists = fs.existsSync(screenshot_path);
            const screenshotFilename = path.basename(screenshot_path);
            result.screenshot = {
                exists: screenshotExists,
                path: screenshot_path,
                url: screenshotExists ? `/api/artifacts/screenshot/${screenshotFilename}` : null
            };
        }

        res.json({
            success: true,
            artifacts: result
        });
    } catch (error) {
        console.error('Error checking artifacts:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to check artifacts',
            details: error.message
        });
    }
});

module.exports = router;
