/**
 * Transform backend screenshot path to accessible URL via backend API
 *
 * Backend returns paths like: "/workspace/out/screenshots/filename.png"
 * We extract the filename and construct a full backend API URL
 *
 * @param screenshotPath - Path from API response
 * @returns Full backend API URL that serves the screenshot
 */
export const transformScreenshotPath = (screenshotPath: string | null | undefined): string | null => {
  if (!screenshotPath) return null;

  // Extract filename from path
  const filename = screenshotPath.split('/').pop();
  if (!filename) return null;

  // Construct backend URL based on current location
  // If accessing via 192.168.0.104:4173, backend will be at 192.168.0.104:3001
  // If accessing via localhost:4173, backend will be at localhost:3001
  const protocol = window.location.protocol; // http: or https:
  const hostname = window.location.hostname; // e.g., 192.168.0.104 or localhost
  const backendPort = '3001';

  // Construct full backend API URL
  return `${protocol}//${hostname}:${backendPort}/api/artifacts/screenshot/${filename}`;
};

/**
 * Get just the filename from a screenshot path
 *
 * @param screenshotPath - Full path from API
 * @returns Just the filename
 */
export const getScreenshotFilename = (screenshotPath: string | null | undefined): string => {
  if (!screenshotPath) return 'screenshot.png';

  const parts = screenshotPath.split('/');
  return parts[parts.length - 1] || 'screenshot.png';
};
