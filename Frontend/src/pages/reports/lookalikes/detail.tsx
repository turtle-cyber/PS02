import { useLocation, useParams } from "react-router-dom";
import { DetailHeader } from "@/components/reports/DetailHeader";
import { DetailCards } from "@/components/reports/DetailCards";
import { getMockLookalikeDetail } from "@/data/mockReportDetails";
import { LiquidCard } from "@/components/ui/liquid-card";
import { useCallback, useEffect, useState } from "react";
import { GET_LOOKALIKE_DETAILS } from "@/endpoints/reports.endpoints";
import { http } from "@/hooks/config";
import { toast } from "sonner";

const useGetLookalikeDetail = (id?: string) => {
  const [lookalikeData, setLookalikeData] = useState<any>(null);
  const [lookalikeLoading, setLookalikeLoading] = useState(false);

  const fetchLookalike = useCallback(async () => {
    if (!id) return;
    setLookalikeLoading(true);
    try {
      const url = `${GET_LOOKALIKE_DETAILS}/${id}`;
      const response = await http.get(url);

      setLookalikeData(response?.data || {});
    } catch (error) {
      toast.error("Error Fetching URL Report Detail");
      console.error("Error Fetching URL Report Detail:", error);
    } finally {
      setLookalikeLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchLookalike();
  }, [fetchLookalike]);

  return {
    lookalikeData,
    lookalikeLoading,
    refetch: fetchLookalike,
  };
};

const LookalikeDetailPage = () => {
  const location = useLocation();
  const params = useParams<{ id?: string }>();
  const row = location.state?.row;

  const idFromUrl = params.id ? decodeURIComponent(params.id) : undefined;

  const { lookalikeData, lookalikeLoading } = useGetLookalikeDetail(idFromUrl);

  const data = getMockLookalikeDetail();

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
      {/* Main content */}
      <main className="mx-auto px-6 py-4">
        <LiquidCard variant="glass">
          <DetailHeader
            url={lookalikeData?.domain}
            backPath="/reports/lookalikes"
            backLabel="Back to Lookalikes"
            verdict={lookalikeData?.data?.metadata?.final_verdict}
            confidence={lookalikeData?.data?.metadata?.confidence}
            risk={lookalikeData?.data?.metadata?.risk_score}
            additionalMetrics={[
              {
                label: "Total Registered Domain Found",
                value:
                  lookalikeData?.data?.metadata?.dnstwist_variants_registered,
                highlight: true,
              },
              {
                label: "Total Active Domains",
                value:
                  lookalikeData?.data?.metadata?.dnstwist_variants_unregistered,
                highlight: true,
              },
            ]}
            metaLeft={[
              {
                label: "ISP",
                value: lookalikeData?.data?.metadata?.asn_org || "N/A",
              },
              {
                label: "ASN",
                value: lookalikeData?.data?.metadata?.asn || "N/A",
              },
              {
                label: "Location",
                value:
                  lookalikeData?.data?.metadata?.city &&
                  lookalikeData?.data?.metadata?.country
                    ? `${lookalikeData.data.metadata.city}, ${lookalikeData.data.metadata.country}`
                    : lookalikeData?.data?.metadata?.country || "N/A",
              },
            ]}
            metaRight={[
              {
                label: "Risk",
                value: lookalikeData?.data?.metadata?.risk_score,
              },
              {
                label: "Verdict",
                value: lookalikeData?.data?.metadata?.final_verdict,
              },
              {
                label: "Domain Age",
                value: lookalikeData?.data?.metadata?.domain_age_days,
              },
            ]}
            lastScan={displayData.lastScan}
          />
        </LiquidCard>

        {/* Detail cards */}
        <div className="mt-6 w-full">
          <DetailCards data={lookalikeData} />
        </div>
      </main>
    </div>
  );
};

export default LookalikeDetailPage;
