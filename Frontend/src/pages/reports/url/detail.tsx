import * as React from "react";
import { useLocation, useParams } from "react-router-dom";
import { DetailHeader } from "@/components/reports/DetailHeader";
import { DetailCards } from "@/components/reports/DetailCards";
import { getMockUrlDetail } from "@/data/mockReportDetails";
import { LiquidCard } from "@/components/ui/liquid-card";

const UrlDetailPage = () => {
  const location = useLocation();
  const params = useParams<{ id?: string }>();

  // If you came from the table with navigate(..., { state: { row } })
  const row = location.state?.row;
  const idFromUrl = params.id ? decodeURIComponent(params.id) : undefined;

  // TODO: In the future, fetch real data with `idFromUrl` or row.id
  const data = getMockUrlDetail();

  // Use row data if available, otherwise use mock
  const displayData = row
    ? {
        ...data,
        sourceUrl: row.sourceUrl || data.sourceUrl,
        ipAddress: row.ipAddress || data.ipAddress,
        risk: row.risk || data.risk,
        verdict: row.verdict || data.verdict,
      }
    : data;

  return (
    <div className="min-h-screen">
      <main className="px-6 py-4">
        <LiquidCard variant="glass">
          <DetailHeader
            url={displayData.sourceUrl}
            backPath="/reports/url"
            backLabel="Back to URL Reports"
            verdict={displayData.verdict}
            confidence={displayData.confidence}
            risk={displayData.risk}
            metaLeft={[
              { label: "Source URL", value: displayData.sourceUrl },
              { label: "Destination URL", value: displayData.destinationUrl },
              { label: "IP Address", value: displayData.ipAddress },
            ]}
            metaRight={[
              { label: "A Count", value: displayData.aCount },
              { label: "Country", value: displayData.country },
              { label: "Risk", value: displayData.risk },
              { label: "MX Record", value: displayData.mxRecord },
              { label: "Registrar", value: displayData.registrar },
              { label: "Domain Age", value: displayData.domainAge },
            ]}
            lastScan={displayData.lastScan}
          />
        </LiquidCard>

        <div className="mt-6">
          <DetailCards data={displayData} />
        </div>
      </main>
    </div>
  );
};

export default UrlDetailPage;
