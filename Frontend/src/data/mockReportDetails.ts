// Mock data for report detail pages
// TODO: Replace with real API calls

export interface UrlDetailData {
  // Header meta
  sourceUrl: string;
  destinationUrl: string;
  ipAddress: string;
  aCount: number;
  country: string;
  risk: number;
  mxRecord: string;
  registrar: string;
  domainAge: string;
  verdict: string;
  darkWebPresence: boolean;
  confidence: number;
  lastScan: string;

  // Domain Analysis
  nsCount: number;
  mxCount: number;

  // Domain Age WHOIS
  isNewlyRegistered: boolean;
  isVeryNew: boolean;
  daysUntilExpiry: number;

  // Geo Location
  geoPoints: Array<{ name: string; value: [number, number, number] }>;

  // Feature Metrics
  urlLength: number;
  urlEntropy: number;
  numSubdomains: number;
  hasMixedScript: boolean;
  formCount: number;
  passwordFields: number;
  emailFields: number;
  phishingKeywords: number;
  htmlSize: string;
  externalLinks: number;
  iframeCount: number;

  // Favicon
  faviconMd5: string;
  faviconSha256: string;

  // Redirects
  redirectCount: number;
  hasRedirects: boolean;

  // JS Analysis
  isObfuscated: boolean;
  evalCount: number;
  encodingCount: number;
  hasKeylogger: boolean;
  hasFormManipulation: boolean;
  hasRedirectDetection: boolean;
  jsRiskScore: number;

  // SSL Certificate
  hasSuspiciousForms: boolean;
  sslName: string;
  formsToIp: boolean;
  formsToPrivateIp: boolean;

  // Screenshots
  screenshots: string[];
}

export interface LookalikeDetailData extends UrlDetailData {
  totalSimilarDomains: number;
  totalActiveDomains: number;
  totalParkedDomains: number;
  isp: string;
  asn: string;
  location: string;
}

export const getMockUrlDetail = (): UrlDetailData => ({
  sourceUrl: "https://icici.in",
  destinationUrl: "https://icici.in",
  ipAddress: "44.239.107.153",
  aCount: 2,
  country: "United States",
  risk: 85,
  mxRecord: "mx.icici.in",
  registrar: "GoDaddy",
  domainAge: "2 days",
  verdict: "Phishing",
  darkWebPresence: true,
  confidence: 92,
  lastScan: "2025-10-11T16:54:48",

  nsCount: 2,
  mxCount: 1,

  isNewlyRegistered: true,
  isVeryNew: true,
  daysUntilExpiry: 363,

  geoPoints: [
    { name: "United States", value: [-95.7129, 37.0902, 1] },
    { name: "India", value: [78.9629, 20.5937, 3] }
  ],

  urlLength: 14,
  urlEntropy: 2.85,
  numSubdomains: 0,
  hasMixedScript: false,
  formCount: 3,
  passwordFields: 2,
  emailFields: 1,
  phishingKeywords: 5,
  htmlSize: "45.2 KB",
  externalLinks: 12,
  iframeCount: 0,

  faviconMd5: "a1b2c3d4e5f6",
  faviconSha256: "1234567890abcdef",

  redirectCount: 2,
  hasRedirects: true,

  isObfuscated: true,
  evalCount: 3,
  encodingCount: 2,
  hasKeylogger: true,
  hasFormManipulation: true,
  hasRedirectDetection: false,
  jsRiskScore: 78,

  hasSuspiciousForms: true,
  sslName: "Let's Encrypt",
  formsToIp: true,
  formsToPrivateIp: false,

  screenshots: [
    "/placeholder.svg",
    "/placeholder.svg",
    "/placeholder.svg",
    "/placeholder.svg"
  ]
});

export const getMockLookalikeDetail = (): LookalikeDetailData => ({
  ...getMockUrlDetail(),
  sourceUrl: "https://icici.in",
  totalSimilarDomains: 356,
  totalActiveDomains: 210,
  totalParkedDomains: 146,
  isp: "Amazon AWS",
  asn: "AS16509",
  location: "Virginia, US",
  risk: 92,
  verdict: "Suspicious",
  domainAge: "5 days"
});
