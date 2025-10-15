import * as React from "react";
import { useLocation } from "react-router-dom";
import { DetailHeader } from "@/components/reports/DetailHeader";
import { DetailCards } from "@/components/reports/DetailCards";
import { getMockLookalikeDetail } from "@/data/mockReportDetails";
import { LiquidCard } from "@/components/ui/liquid-card";

const LookalikeDetailPage = () => {
  const location = useLocation();
  const row = location.state?.row;
  
  // TODO: Fetch real data from API based on row.id or URL
  const data = getMockLookalikeDetail();
  
  // Use row data if available, otherwise use mock
  const displayData = row ? { 
    ...data, 
    sourceUrl: row.sourceUrl || data.sourceUrl,
    ipAddress: row.ipAddress || data.ipAddress,
    risk: row.risk || data.risk,
    verdict: row.verdict || data.verdict
  } : data;

  return (
    <div className="min-h-screen">
      {/* Main content */}
      <main className="mx-auto px-6 py-4">
        <LiquidCard variant="glass">
        <DetailHeader
          url={displayData.sourceUrl}
          backPath="/reports/lookalikes"
          backLabel="Back to Lookalikes"
          verdict={displayData.verdict}
          confidence={displayData.confidence}
          risk={displayData.risk}
          additionalMetrics={[
            { label: "Total Similar Domain Found", value: displayData.totalSimilarDomains, highlight: true },
            { label: "Total Active Domains", value: displayData.totalActiveDomains, highlight: true },
            { label: "Total Parked Domain", value: displayData.totalParkedDomains, highlight: true }
          ]}
          metaLeft={[
            { label: "ISP", value: displayData.isp },
            { label: "ASN", value: displayData.asn },
            { label: "Location", value: displayData.location }
          ]}
          metaRight={[
            { label: "Risk", value: displayData.risk },
            { label: "Verdict", value: displayData.verdict },
            { label: "Domain Age", value: displayData.domainAge }
          ]}
          lastScan={displayData.lastScan}
        />
        </LiquidCard>

        {/* Detail cards */}
        <div className="mt-6 w-full">
          <DetailCards data={displayData} />
        </div>
      </main>
    </div>
  );
};

export default LookalikeDetailPage;
