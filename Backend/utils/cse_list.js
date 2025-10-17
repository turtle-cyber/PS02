// cse-list.js  (Node/JS - single source of truth for names & categories)

// ===== 1) MASTER DATA (single source of truth) =====
export const CSE_DATA = [
  // Power & Energy
  { category: "Power & Energy", name: "Power Grid Corporation of India Ltd", url: "https://www.powergrid.in" },
  { category: "Power & Energy", name: "Grid Controller of India Ltd", url: "https://gridcontroller.in" },
  { category: "Power & Energy", name: "State Load Dispatch Centres (SLDCs)", url: "https://sldcdelhi.org" },
  { category: "Power & Energy", name: "NTPC Ltd", url: "https://www.ntpc.co.in" },
  { category: "Power & Energy", name: "NHPC Ltd", url: "https://www.nhpcindia.com" },
  { category: "Power & Energy", name: "Nuclear Power Corporation of India Ltd (NPCIL)", url: "https://www.npcil.nic.in" },
  { category: "Power & Energy", name: "Oil & Natural Gas Corporation (ONGC)", url: "https://www.ongcindia.com" },
  { category: "Power & Energy", name: "Indian Oil Corporation Ltd (IOCL)", url: "https://iocl.com" },
  { category: "Power & Energy", name: "Bharat Petroleum Corporation Ltd (BPCL)", url: "https://www.bharatpetroleum.in" },
  { category: "Power & Energy", name: "Hindustan Petroleum Corporation Ltd (HPCL)", url: "https://www.hindustanpetroleum.com" },
  { category: "Power & Energy", name: "GAIL (India) Ltd", url: "https://gailonline.com" },
  { category: "Power & Energy", name: "Rural Electrification Corporation (REC Ltd)", url: "https://recindia.nic.in" },
  { category: "Power & Energy", name: "North Eastern Electric Power Corporation (NEEPCO)", url: "https://neepco.co.in" },
  { category: "Power & Energy", name: "SJVN Ltd", url: "https://sjvn.nic.in" },
  { category: "Power & Energy", name: "THDC India Ltd", url: "https://thdc.co.in" },
  { category: "Power & Energy", name: "Adani Green Energy Ltd", url: "https://www.adanigreenenergy.com" },
  { category: "Power & Energy", name: "State Electricity Boards (SEBs)", url: "https://www.mahadiscom.in" },

  // BFSI
  { category: "BFSI", name: "Reserve Bank of India (RBI)", url: "https://www.rbi.org.in" },
  { category: "BFSI", name: "National Payments Corporation of India (NPCI)", url: "https://www.npci.org.in" },
  { category: "BFSI", name: "Life Insurance Corporation of India (LIC)", url: "https://licindia.in" },
  { category: "BFSI", name: "State Bank of India (SBI)", url: "https://sbi.co.in" },
  { category: "BFSI", name: "Bank of Baroda", url: "https://www.bankofbaroda.in" },
  { category: "BFSI", name: "Punjab National Bank (PNB)", url: "https://www.pnbindia.in" },
  { category: "BFSI", name: "Union Bank of India", url: "https://www.unionbankofindia.co.in" },
  { category: "BFSI", name: "Canara Bank", url: "https://www.canarabank.com" },
  { category: "BFSI", name: "Bank of India", url: "https://www.bankofindia.co.in" },
  { category: "BFSI", name: "Indian Bank", url: "https://www.indianbank.in" },
  { category: "BFSI", name: "Central Bank of India", url: "https://www.centralbankofindia.co.in" },
  { category: "BFSI", name: "Bank of Maharashtra", url: "https://bankofmaharashtra.in" },
  { category: "BFSI", name: "Indian Overseas Bank", url: "https://www.iob.in" },
  { category: "BFSI", name: "UCO Bank", url: "https://www.ucobank.com" },
  { category: "BFSI", name: "IDBI Bank", url: "https://www.idbibank.in" },
  { category: "BFSI", name: "Axis Bank", url: "https://www.axisbank.com" },
  { category: "BFSI", name: "HDFC Bank", url: "https://www.hdfcbank.com" },
  { category: "BFSI", name: "ICICI Bank", url: "https://www.icicibank.com" },
  { category: "BFSI", name: "Kotak Mahindra Bank", url: "https://www.kotak.com" },
  { category: "BFSI", name: "IndusInd Bank", url: "https://www.indusind.com" },
  { category: "BFSI", name: "Federal Bank", url: "https://www.federalbank.co.in" },
  { category: "BFSI", name: "Yes Bank", url: "https://www.yesbank.in" },
  { category: "BFSI", name: "RBL Bank", url: "https://www.rblbank.com" },
  { category: "BFSI", name: "IDFC First Bank", url: "https://www.idfcfirstbank.com" },
  { category: "BFSI", name: "Bandhan Bank", url: "https://www.bandhanbank.com" },
  { category: "BFSI", name: "Karnataka Bank", url: "https://karnatakabank.com" },
  { category: "BFSI", name: "Karur Vysya Bank", url: "https://www.kvb.co.in" },
  { category: "BFSI", name: "City Union Bank", url: "https://www.cityunionbank.com" },
  { category: "BFSI", name: "South Indian Bank", url: "https://www.southindianbank.com" },
  { category: "BFSI", name: "Tamilnad Mercantile Bank", url: "https://www.tmb.in" },
  { category: "BFSI", name: "Jammu & Kashmir Bank", url: "https://www.jkbank.com" },
  { category: "BFSI", name: "Paytm Payments Bank", url: "https://www.paytmbank.com" },

  // Telecommunication
  { category: "Telecommunication", name: "Bharat Sanchar Nigam Ltd (BSNL)", url: "https://www.bsnl.co.in" },
  { category: "Telecommunication", name: "Mahanagar Telephone Nigam Ltd (MTNL)", url: "https://mtnl.in" },
  { category: "Telecommunication", name: "Reliance Jio Infocomm Ltd", url: "https://www.jio.com" },
  { category: "Telecommunication", name: "Bharti Airtel Ltd", url: "https://www.airtel.in" },
  { category: "Telecommunication", name: "Vodafone Idea Ltd", url: "https://www.myvi.in" },
  { category: "Telecommunication", name: "RailTel Corporation of India", url: "https://www.railtelindia.com" },
  { category: "Telecommunication", name: "Tata Communications Ltd", url: "https://www.tatacommunications.com" },
  { category: "Telecommunication", name: "Department of Telecommunications (DoT)", url: "https://dot.gov.in" },
  { category: "Telecommunication", name: "National Informatics Centre (NICNET)", url: "https://www.nic.in" },

  // Transport
  { category: "Transport", name: "Indian Railways", url: "https://indianrailways.gov.in" },
  { category: "Transport", name: "CRIS", url: "https://cris.org.in" },
  { category: "Transport", name: "Airports Authority of India (AAI)", url: "https://www.aai.aero" },
  { category: "Transport", name: "Directorate General of Shipping", url: "https://www.dgshipping.gov.in" },
  { category: "Transport", name: "Ministry of Road Transport & Highways", url: "https://morth.nic.in" },
  { category: "Transport", name: "VAHAN", url: "https://vahan.parivahan.gov.in" },
  { category: "Transport", name: "SARATHI", url: "https://sarathi.parivahan.gov.in" },

  // Government
  { category: "Government", name: "UIDAI", url: "https://uidai.gov.in" },
  { category: "Government", name: "Income Tax Department", url: "https://incometaxindia.gov.in" },
  { category: "Government", name: "National Informatics Centre (NIC)", url: "https://www.nic.in" },
  { category: "Government", name: "Ministry of Electronics & IT (MeitY)", url: "https://www.meity.gov.in" },
  { category: "Government", name: "Election Commission of India", url: "https://eci.gov.in" },
  { category: "Government", name: "National Voter Service Portal (NVSP)", url: "https://www.nvsp.in" },
  { category: "Government", name: "Government of NCT of Delhi", url: "https://delhi.gov.in" },
  { category: "Government", name: "DigiLocker", url: "https://www.digilocker.gov.in" },
  { category: "Government", name: "MyGov", url: "https://www.mygov.in" },

  // Strategic & Public Enterprises
  { category: "Strategic & Public Enterprises", name: "DRDO", url: "https://www.drdo.gov.in" },
  { category: "Strategic & Public Enterprises", name: "ISRO", url: "https://www.isro.gov.in" },
  { category: "Strategic & Public Enterprises", name: "Department of Atomic Energy (DAE)", url: "https://dae.gov.in" },
  { category: "Strategic & Public Enterprises", name: "HAL", url: "https://hal-india.co.in" },
  { category: "Strategic & Public Enterprises", name: "BEL", url: "https://www.bel-india.in" },
  { category: "Strategic & Public Enterprises", name: "BDL", url: "https://bdl-india.in" },
  { category: "Strategic & Public Enterprises", name: "MDL", url: "https://mazagondock.in" },
  { category: "Strategic & Public Enterprises", name: "HSL", url: "https://hslvizag.in" },
  { category: "Strategic & Public Enterprises", name: "BHEL", url: "https://www.bhel.com" },
  { category: "Strategic & Public Enterprises", name: "GRSE", url: "https://grse.in" },
  { category: "Strategic & Public Enterprises", name: "AVNL", url: "https://avnl.co.in" },
  { category: "Strategic & Public Enterprises", name: "SAIL", url: "https://sail.co.in" },
  { category: "Strategic & Public Enterprises", name: "ONGC", url: "https://www.ongcindia.com" },
  { category: "Strategic & Public Enterprises", name: "IOCL", url: "https://iocl.com" },
  { category: "Strategic & Public Enterprises", name: "GAIL", url: "https://gailonline.com" },
  { category: "Strategic & Public Enterprises", name: "BPCL", url: "https://www.bharatpetroleum.in" },
  { category: "Strategic & Public Enterprises", name: "HPCL", url: "https://www.hindustanpetroleum.com" },
];

// ===== 2) DERIVED MAPS =====

// url → name
export const CSE_BY_URL = CSE_DATA.reduce((acc, { url, name }) => {
  acc[url] = name;
  return acc;
}, Object.create(null));

// url → category (last occurrence wins)
export const CSE_CATEGORY_BY_URL = CSE_DATA.reduce((acc, { url, category }) => {
  acc[url] = category;
  return acc;
}, Object.create(null));

// hostname → name (supports base + www)
const HOST_TO_NAME = (() => {
  const acc = Object.create(null);
  for (const [u, name] of Object.entries(CSE_BY_URL)) {
    try {
      const { hostname } = new URL(u);
      const base = hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
      acc[base] = name;
      acc[`www.${base}`] = name;
    } catch {/* ignore bad entries */}
  }
  return acc;
})();

// hostname → category (supports base + www)
const HOST_TO_CATEGORY = (() => {
  const acc = Object.create(null);
  for (const [u, cat] of Object.entries(CSE_CATEGORY_BY_URL)) {
    try {
      const { hostname } = new URL(u);
      const base = hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
      acc[base] = cat;
      acc[`www.${base}`] = cat;
    } catch {/* ignore bad entries */}
  }
  return acc;
})();

// ===== 3) HELPERS & EXPORTS =====

/**
 * Normalize any URL-ish string to a hostname (lowercase, without leading "www.", no trailing dot).
 * Accepts inputs like:
 *   - "https://www.sbi.co.in/retail?x=1"
 *   - "http://sbi.co.in"
 *   - "sbi.co.in"
 *   - "  SBI.CO.IN.  "
 */
export function normalizeHost(input) {
  if (!input || typeof input !== "string") return null;
  const raw = input.trim();
  try {
    const hasProto = /^https?:\/\//i.test(raw);
    const url = new URL(hasProto ? raw : `https://${raw}`);
    return url.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  } catch {
    return raw.toLowerCase().replace(/^www\./, "").replace(/\.$/, "") || null;
  }
}

/**
 * Return official CSE name for a given URL/domain.
 * Keeps original functionality: exact host (and explicit "www.") only; falls back to "Unknown".
 * @param {string} inputUrl
 * @returns {string} name | "Unknown"
 */
export function getCseName(inputUrl) {
  const host = normalizeHost(inputUrl);
  if (!host) return "Unknown";
  return HOST_TO_NAME[host] || HOST_TO_NAME[`www.${host}`] || "Unknown";
}

/**
 * Return category for a given URL/domain.
 * Exact host (and explicit "www.") only; falls back to "Unknown".
 * @param {string} inputUrl
 * @returns {string} category | "Unknown"
 */
export function getCseCategory(inputUrl) {
  const host = normalizeHost(inputUrl);
  if (!host) return "Unknown";
  return HOST_TO_CATEGORY[host] || HOST_TO_CATEGORY[`www.${host}`] || "Unknown";
}
