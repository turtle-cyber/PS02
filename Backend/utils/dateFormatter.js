/**
 * Global helper utilities for date/time formatting across all API endpoints
 */

/**
 * Convert ISO timestamp to "dd-mm-yyyy hh:mm" format
 * @param {string|number|Date} timestamp - ISO string, Unix timestamp (seconds), or Date object
 * @returns {string} Formatted date string in "dd-mm-yyyy hh:mm" format
 * @example
 * formatTimestamp("2025-10-16T12:34:56.789Z") // "16-10-2025 12:34"
 * formatTimestamp(1697462096) // "16-10-2023 12:34"
 * formatTimestamp(new Date()) // "16-10-2025 12:34"
 */
function formatTimestamp(timestamp) {
    if (!timestamp) {
        return 'N/A';
    }

    let date;

    // Handle different input types
    if (timestamp instanceof Date) {
        date = timestamp;
    } else if (typeof timestamp === 'string') {
        // ISO string format
        date = new Date(timestamp);
    } else if (typeof timestamp === 'number') {
        // Unix timestamp - check if in seconds or milliseconds
        // Timestamps > 9999999999 are in milliseconds (13+ digits)
        const timestampMs = timestamp > 9999999999 ? timestamp : timestamp * 1000;
        date = new Date(timestampMs);
    } else {
        return 'N/A';
    }

    // Validate date
    if (isNaN(date.getTime())) {
        return 'N/A';
    }

    // Extract date components
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');

    // Return in "dd-mm-yyyy hh:mm" format
    return `${day}-${month}-${year} ${hours}:${minutes}`;
}

/**
 * Convert ISO timestamp to ISO date string (YYYY-MM-DD)
 * @param {string|number|Date} timestamp - ISO string, Unix timestamp, or Date object
 * @returns {string} ISO date string in "YYYY-MM-DD" format
 */
function toISODate(timestamp) {
    if (!timestamp) {
        return null;
    }

    let date;

    if (timestamp instanceof Date) {
        date = timestamp;
    } else if (typeof timestamp === 'string') {
        date = new Date(timestamp);
    } else if (typeof timestamp === 'number') {
        const timestampMs = timestamp > 9999999999 ? timestamp : timestamp * 1000;
        date = new Date(timestampMs);
    } else {
        return null;
    }

    if (isNaN(date.getTime())) {
        return null;
    }

    return date.toISOString().split('T')[0];
}

/**
 * Parse various timestamp formats to JavaScript Date object
 * @param {string|number|Date} input - Timestamp in various formats
 * @returns {Date|null} Date object or null if invalid
 */
function parseTimestamp(input) {
    if (!input) {
        return null;
    }

    if (input instanceof Date) {
        return input;
    }

    // If it's already ISO format
    if (typeof input === 'string' && input.includes('T')) {
        const date = new Date(input);
        return isNaN(date.getTime()) ? null : date;
    }

    // If it's Unix timestamp (seconds)
    const timestamp = parseInt(input);
    if (!isNaN(timestamp)) {
        // If timestamp is in milliseconds (13 digits), convert to seconds
        const timestampSeconds = timestamp > 9999999999 ? Math.floor(timestamp / 1000) : timestamp;
        const date = new Date(timestampSeconds * 1000);
        return isNaN(date.getTime()) ? null : date;
    }

    // Try to parse as date string
    try {
        const date = new Date(input);
        return isNaN(date.getTime()) ? null : date;
    } catch (error) {
        return null;
    }
}

module.exports = {
    formatTimestamp,
    toISODate,
    parseTimestamp
};
