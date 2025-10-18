import { ReportsLayout } from "@/components/reports/ReportsLayout";
import { UrlReportsTable } from "@/components/reports/UrlReportsTable";
import { mockUrlReports } from "@/data/mockReports";
import { GET_ORIGINAL_LIST } from "@/endpoints/reports.endpoints";
import { http } from "@/hooks/config";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

const useGetUrlReportsData = () => {
  const [urlReportsData, setUrlReportsData] = useState<any>({});
  const [urlReportsLoading, setUrlReportsLoading] = useState(false);

  const fetchUrlReports = useCallback(async () => {
    setUrlReportsLoading(true);
    try {
      const response = await http.get(GET_ORIGINAL_LIST, {
        params: { limit: 20 },
      });
      setUrlReportsData(response?.data?.domains || []);
    } catch (error) {
      toast.error("Error Fetching URL Reports Data");
      console.error("Error Fetching URL Reports Data with error: ", error);
    } finally {
      setUrlReportsLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchUrlReports();
  }, [fetchUrlReports]);

  return { urlReportsData, urlReportsLoading, refetch: fetchUrlReports };
};

const UrlReportsPage = () => {
  const { urlReportsData, urlReportsLoading } = useGetUrlReportsData();
  return (
    <ReportsLayout title="URL Reports">
      <UrlReportsTable data={urlReportsData} loading={false} />
    </ReportsLayout>
  );
};

export default UrlReportsPage;
