export const mockDashboard = {
  totals: {
    scans: 3781,
    confidence: 88,
    cses: 50,
    phishingUrls: 2010,
  },

  domainsSummary: {
    lookAlike: 2011,
    mxRecords: 600,
    activeDetected: 1044,
    parked: 967,
  },

  urlWatchSeries: {
    dates: [
      '2025-08-01', '2025-08-05', '2025-08-10', '2025-08-15', '2025-08-20', 
      '2025-08-25', '2025-08-30', '2025-09-01', '2025-09-05', '2025-09-10',
      '2025-09-15', '2025-09-20', '2025-09-25', '2025-09-30'
    ],
    phishing: [120, 145, 180, 220, 195, 240, 280, 260, 310, 290, 340, 320, 380, 360],
    suspicious: [80, 95, 110, 130, 115, 140, 160, 150, 180, 170, 200, 190, 220, 210],
    clean: [200, 210, 230, 250, 240, 270, 290, 280, 310, 300, 330, 320, 350, 340],
  },

  originCountries: {
    heat: [
      { name: 'India', value: 1240 },
      { name: 'United States', value: 890 },
      { name: 'China', value: 760 },
      { name: 'Russia', value: 620 },
      { name: 'Brazil', value: 450 },
      { name: 'United Kingdom', value: 380 },
    ],
    cities: [
      { name: 'Mumbai', lat: 19.0760, lng: 72.8777, value: 523 },
      { name: 'New York', lat: 40.7128, lng: -74.0060, value: 412 },
      { name: 'Beijing', lat: 39.9042, lng: 116.4074, value: 356 },
      { name: 'Moscow', lat: 55.7558, lng: 37.6173, value: 289 },
      { name: 'São Paulo', lat: -23.5505, lng: -46.6333, value: 234 },
    ],
  },

  urlInsightsRows: [
    { sourceUrl: 'http://uidai-verification.in', ip: '103.21.244.12', provider: 'Cloudflare', cseIntended: 'Government', verdict: 'Phishing' },
    { sourceUrl: 'https://secure-paypal-verify.com', ip: '185.220.101.34', provider: 'DigitalOcean', cseIntended: 'Bank & Finance', verdict: 'Phishing' },
    { sourceUrl: 'http://amazon-account-update.net', ip: '172.67.135.88', provider: 'AWS', cseIntended: 'E-commerce', verdict: 'Suspicious' },
    { sourceUrl: 'https://microsoft-365-login.com', ip: '104.21.45.67', provider: 'Cloudflare', cseIntended: 'Technology', verdict: 'Phishing' },
    { sourceUrl: 'http://hdfc-bank-verify.in', ip: '192.168.1.45', provider: 'Local ISP', cseIntended: 'Bank & Finance', verdict: 'Suspicious' },
    { sourceUrl: 'https://irctc-ticket-booking.com', ip: '103.45.78.90', provider: 'NIC', cseIntended: 'Government', verdict: 'Phishing' },
    { sourceUrl: 'http://sbi-secure-login.net', ip: '172.67.200.10', provider: 'Cloudflare', cseIntended: 'Bank & Finance', verdict: 'Clean' },
    { sourceUrl: 'https://google-drive-share.com', ip: '185.220.102.50', provider: 'Google Cloud', cseIntended: 'Technology', verdict: 'Suspicious' },
    { sourceUrl: 'http://fedex-tracking-update.com', ip: '104.28.15.78', provider: 'AWS', cseIntended: 'Logistics', verdict: 'Phishing' },
    { sourceUrl: 'https://netflix-payment-update.net', ip: '172.67.145.22', provider: 'DigitalOcean', cseIntended: 'Entertainment', verdict: 'Suspicious' },
  ],

  threatLandscapeSegments: [
    { category: 'Telecom', width: 22, color: '#E50914', cseContributors: ['Airtel', 'Vodafone', 'Jio', 'BSNL'] },
    { category: 'Government', width: 19, color: '#FF6A00', cseContributors: ['UIDAI', 'IRCTC', 'Income Tax', 'NIC'] },
    { category: 'Bank & Finance', width: 28, color: '#E50914', cseContributors: ['HDFC', 'SBI', 'ICICI', 'Axis Bank', 'PayPal'] },
    { category: 'E-commerce', width: 15, color: '#FFCC33', cseContributors: ['Amazon', 'Flipkart', 'Myntra'] },
    { category: 'Technology', width: 10, color: '#2FAE6B', cseContributors: ['Microsoft', 'Google', 'Apple'] },
    { category: 'Others', width: 6, color: '#2D9CDB', cseContributors: ['Netflix', 'FedEx', 'DHL'] },
  ],

  topCseByRisk: [
    { sector: 'Power & Energy', critical: 35, high: 25, moderate: 20, elevated: 12, low: 8 },
    { sector: 'Telecom', critical: 28, high: 30, moderate: 22, elevated: 13, low: 7 },
    { sector: 'Bank & Finance', critical: 42, high: 28, moderate: 18, elevated: 8, low: 4 },
    { sector: 'Government', critical: 32, high: 26, moderate: 24, elevated: 12, low: 6 },
    { sector: 'Healthcare', critical: 18, high: 22, moderate: 30, elevated: 20, low: 10 },
    { sector: 'Technology', critical: 15, high: 20, moderate: 28, elevated: 22, low: 15 },
  ],

  parkedInsightsRows: [
    { domain: 'uidai-verify.com', parkedSince: '2024-03-15', recentVerdict: 'Phishing Confirmed' },
    { domain: 'paypal-secure-login.net', parkedSince: '2024-06-22', recentVerdict: 'Suspicious' },
    { domain: 'amazon-customer-care.in', parkedSince: '2024-01-08', recentVerdict: 'Suspicious' },
    { domain: 'microsoft-office365.com', parkedSince: '2024-07-11', recentVerdict: 'Phishing Confirmed' },
    { domain: 'hdfc-netbanking-secure.com', parkedSince: '2024-05-19', recentVerdict: 'Safe Domain' },
    { domain: 'irctc-booking.net', parkedSince: '2024-02-28', recentVerdict: 'Suspicious' },
    { domain: 'sbi-online-banking.in', parkedSince: '2024-04-10', recentVerdict: 'Suspicious' },
    { domain: 'google-drive-storage.com', parkedSince: '2024-08-05', recentVerdict: 'Phishing Confirmed' },
  ],

  monthRange: 'August 2025 – September 2025',
};

// TODO: wire to realtime data source
