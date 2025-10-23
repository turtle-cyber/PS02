import { useLocation, useParams } from "react-router-dom";
import { DetailHeader } from "@/components/reports/DetailHeader";
import { DetailCards } from "@/components/reports/DetailCards";
import { getMockUrlDetail } from "@/data/mockReportDetails";
import { LiquidCard } from "@/components/ui/liquid-card";
import { useCallback, useEffect, useState } from "react";
import { http } from "@/hooks/config";
import { GET_DOMAIN_DETAIL } from "@/endpoints/reports.endpoints";
import { toast } from "sonner";

const useGetUrlReportDetail = (id?: string) => {
  const [reportDetailData, setReportDetailsData] = useState<any>(null);
  const [reportsDetailsLoading, setReportsDetailsLoading] = useState(false);

  const fetchReportDetails = useCallback(async () => {
    if (!id) return; // no id → no call
    setReportsDetailsLoading(true);
    try {
      const url = `${GET_DOMAIN_DETAIL}/${id}`;
      const response = await http.get(url);
      setReportDetailsData(response?.data || {});
    } catch (error) {
      toast.error("Error Fetching URL Report Detail");
      console.error("Error Fetching URL Report Detail:", error);
    } finally {
      setReportsDetailsLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchReportDetails();
  }, [fetchReportDetails]);

  return {
    reportDetailData,
    reportsDetailsLoading,
    refetch: fetchReportDetails,
  };
};

const UrlDetailPage = () => {
  const location = useLocation();
  const params = useParams<{ id?: string }>();

  const row = location.state?.row;
  const idFromUrl = params.id ? decodeURIComponent(params.id) : undefined;

  const { reportDetailData, reportsDetailsLoading } =
    useGetUrlReportDetail(idFromUrl);

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
            url={reportDetailData?.domain}
            backPath="/reports/url"
            backLabel="Back to URL Reports"
            verdict={reportDetailData?.metadata?.final_verdict}
            confidence={reportDetailData?.metadata?.risk_score}
            risk={displayData.risk}
            metaLeft={[
              { label: "Source URL", value: reportDetailData?.domain },
              {
                label: "IP Address",
                value: reportDetailData?.data?.metadata?.ipv4 || "N/A",
              },
              {
                label: "ISP",
                value: reportDetailData?.data?.metadata?.asn_org || "N/A",
              },
            ]}
            metaRight={[
              {
                label: "ASN",
                value: reportDetailData?.data?.metadata?.asn || "N/A",
              },
              {
                label: "Location",
                value: reportDetailData?.data?.metadata?.city && reportDetailData?.data?.metadata?.country
                  ? `${reportDetailData.data.metadata.city}, ${reportDetailData.data.metadata.country}`
                  : reportDetailData?.data?.metadata?.country || "N/A",
              },
              {
                label: "A Count",
                value: reportDetailData?.data?.metadata?.a_count,
              },
              {
                label: "MX Count",
                value: reportDetailData?.data?.metadata?.mx_count,
              },
              {
                label: "Registrar",
                value: reportDetailData?.data?.metadata?.registrar || "N/A",
              },
              {
                label: "Domain Age",
                value: reportDetailData?.data?.metadata?.domain_age_days || "N/A",
              },
            ]}
            lastScan={displayData.lastScan}
          />
        </LiquidCard>

        <div className="mt-6">
          <DetailCards data={reportDetailData} />
        </div>
      </main>
    </div>
  );
};

export default UrlDetailPage;
