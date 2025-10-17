export const CSE_BY_URL = {
  "https://www.powergrid.in": "Power Grid Corporation of India Ltd",
  "https://gridcontroller.in": "Grid Controller of India Ltd",
  "https://sldcdelhi.org": "State Load Dispatch Centres (SLDCs)",
  "https://www.ntpc.co.in": "NTPC Ltd",
  "https://www.nhpcindia.com": "NHPC Ltd",
  "https://www.npcil.nic.in": "Nuclear Power Corporation of India Ltd (NPCIL)",
  "https://www.ongcindia.com": "Oil & Natural Gas Corporation (ONGC)",
  "https://iocl.com": "Indian Oil Corporation Ltd (IOCL)",
  "https://www.bharatpetroleum.in": "Bharat Petroleum Corporation Ltd (BPCL)",
  "https://www.hindustanpetroleum.com": "Hindustan Petroleum Corporation Ltd (HPCL)",
  "https://gailonline.com": "GAIL (India) Ltd",
  "https://recindia.nic.in": "Rural Electrification Corporation (REC Ltd)",
  "https://neepco.co.in": "North Eastern Electric Power Corporation (NEEPCO)",
  "https://sjvn.nic.in": "SJVN Ltd",
  "https://thdc.co.in": "THDC India Ltd",
  "https://www.adanigreenenergy.com": "Adani Green Energy Ltd",
  "https://www.mahadiscom.in": "State Electricity Boards (SEBs)",
  "https://www.rbi.org.in": "Reserve Bank of India (RBI)",
  "https://www.npci.org.in": "National Payments Corporation of India (NPCI)",
  "https://licindia.in": "Life Insurance Corporation of India (LIC)",
  "https://sbi.co.in": "State Bank of India (SBI)",
  "https://www.bankofbaroda.in": "Bank of Baroda",
  "https://www.pnbindia.in": "Punjab National Bank (PNB)",
  "https://www.unionbankofindia.co.in": "Union Bank of India",
  "https://www.canarabank.com": "Canara Bank",
  "https://www.bankofindia.co.in": "Bank of India",
  "https://www.indianbank.in": "Indian Bank",
  "https://www.centralbankofindia.co.in": "Central Bank of India",
  "https://bankofmaharashtra.in": "Bank of Maharashtra",
  "https://www.iob.in": "Indian Overseas Bank",
  "https://www.ucobank.com": "UCO Bank",
  "https://www.idbibank.in": "IDBI Bank",
  "https://www.axisbank.com": "Axis Bank",
  "https://www.hdfcbank.com": "HDFC Bank",
  "https://www.icicibank.com": "ICICI Bank",
  "https://www.kotak.com": "Kotak Mahindra Bank",
  "https://www.indusind.com": "IndusInd Bank",
  "https://www.federalbank.co.in": "Federal Bank",
  "https://www.yesbank.in": "Yes Bank",
  "https://www.rblbank.com": "RBL Bank",
  "https://www.idfcfirstbank.com": "IDFC First Bank",
  "https://www.bandhanbank.com": "Bandhan Bank",
  "https://karnatakabank.com": "Karnataka Bank",
  "https://www.kvb.co.in": "Karur Vysya Bank",
  "https://www.cityunionbank.com": "City Union Bank",
  "https://www.southindianbank.com": "South Indian Bank",
  "https://www.tmb.in": "Tamilnad Mercantile Bank",
  "https://www.jkbank.com": "Jammu & Kashmir Bank",
  "https://www.paytmbank.com": "Paytm Payments Bank",
  "https://www.bsnl.co.in": "Bharat Sanchar Nigam Ltd (BSNL)",
  "https://mtnl.in": "Mahanagar Telephone Nigam Ltd (MTNL)",
  "https://www.jio.com": "Reliance Jio Infocomm Ltd",
  "https://www.airtel.in": "Bharti Airtel Ltd",
  "https://www.myvi.in": "Vodafone Idea Ltd",
  "https://www.railtelindia.com": "RailTel Corporation of India",
  "https://www.tatacommunications.com": "Tata Communications Ltd",
  "https://dot.gov.in": "Department of Telecommunications (DoT)",
  "https://www.nic.in": "National Informatics Centre (NIC)",
  "https://indianrailways.gov.in": "Indian Railways",
  "https://cris.org.in": "CRIS",
  "https://www.aai.aero": "Airports Authority of India (AAI)",
  "https://www.dgshipping.gov.in": "Directorate General of Shipping",
  "https://morth.nic.in": "Ministry of Road Transport & Highways",
  "https://vahan.parivahan.gov.in": "VAHAN",
  "https://sarathi.parivahan.gov.in": "SARATHI",
  "https://uidai.gov.in": "UIDAI",
  "https://incometaxindia.gov.in": "Income Tax Department",
  "https://www.meity.gov.in": "Ministry of Electronics & IT (MeitY)",
  "https://eci.gov.in": "Election Commission of India",
  "https://www.nvsp.in": "National Voter Service Portal (NVSP)",
  "https://delhi.gov.in": "Government of NCT of Delhi",
  "https://www.digilocker.gov.in": "DigiLocker",
  "https://www.mygov.in": "MyGov",
  "https://www.drdo.gov.in": "DRDO",
  "https://www.isro.gov.in": "ISRO",
  "https://dae.gov.in": "Department of Atomic Energy (DAE)",
  "https://hal-india.co.in": "HAL",
  "https://www.bel-india.in": "BEL",
  "https://bdl-india.in": "BDL",
  "https://mazagondock.in": "MDL",
  "https://hslvizag.in": "HSL",
  "https://www.bhel.com": "BHEL",
  "https://grse.in": "GRSE",
  "https://avnl.co.in": "AVNL",
  "https://sail.co.in": "SAIL"
};

// Build hostname → name lookup (handles www/non-www)
const HOST_TO_NAME = (() => {
  const acc = Object.create(null);
  for (const [u, name] of Object.entries(CSE_BY_URL)) {
    try {
      const url = new URL(u);
      const base = url.hostname.toLowerCase().replace(/^www\./, "");
      acc[base] = name;
      acc[`www.${base}`] = name; // allow explicit www
    } catch {
      
    }
  }
  return acc;
})();

/**
 * Normalize any URL-ish string to hostname (lowercase, without leading www.)
 * Accepts:
 *   - "https://www.sbi.co.in/retail?x=1"
 *   - "http://sbi.co.in"
 *   - "sbi.co.in"
 */
export function normalizeHost(input) {
  if (!input || typeof input !== "string") return null;
  try {
    const hasProto = /^https?:\/\//i.test(input);
    const url = new URL(hasProto ? input : `https://${input}`);
    return url.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    // fallback: treat plain text as a host
    return input.toLowerCase().replace(/^www\./, "") || null;
  }
}

/**
 * Return official CSE name for a given URL/domain.
 * Handles http/https, www, paths, queries, and casing.
 * @param {string} inputUrl
 * @returns {string|undefined}
 *
 * Example:
 *   getCseName("http://www.sbi.co.in/personal")  // "State Bank of India (SBI)"
 *   getCseName("sbi.co.in")                      // "State Bank of India (SBI)"
 */

export function getCseName(inputUrl) {
  const host = normalizeHost(inputUrl);
  if (!host) return "Unknown"; 
  return HOST_TO_NAME[host] || HOST_TO_NAME[`www.${host}`] || "Unknown";
}
