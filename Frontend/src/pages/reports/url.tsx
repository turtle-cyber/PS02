import { ReportsLayout } from "@/components/reports/ReportsLayout";
import { UrlReportsTable } from "@/components/reports/UrlReportsTable";
import { mockUrlReports } from "@/data/mockReports";
import { GET_ORIGINAL_LIST } from "@/endpoints/reports.endpoints";
import { http } from "@/hooks/config";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { exportToCSV, exportToPDF } from "@/utils/exportUtils";

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

const useExportUrlReportsData = () => {
  const [isExporting, setIsExporting] = useState(false);

  const exportCSV = useCallback(async () => {
    setIsExporting(true);
    try {
      // Fetch 1000 rows for export
      const response = await http.get(GET_ORIGINAL_LIST, {
        params: { limit: 1000 },
      });
      const exportData = response?.data?.domains || [];

      if (exportData.length === 0) {
        toast.warning("No data available to export");
        return;
      }

      exportToCSV(exportData, "url-reports", "url-reports");
      toast.success(`Successfully exported ${exportData.length} rows to CSV`);
    } catch (error) {
      toast.error("Failed to export CSV");
      console.error("Error exporting CSV:", error);
    } finally {
      setIsExporting(false);
    }
  }, []);

  const exportPDF = useCallback(async () => {
    setIsExporting(true);
    try {
      // Fetch 1000 rows for export
      const response = await http.get(GET_ORIGINAL_LIST, {
        params: { limit: 1000 },
      });
      const exportData = response?.data?.domains || [];

      if (exportData.length === 0) {
        toast.warning("No data available to export");
        return;
      }

      exportToPDF(exportData, "url-reports", "url-reports");
      toast.success(`Successfully exported ${exportData.length} rows to PDF`);
    } catch (error) {
      toast.error("Failed to export PDF");
      console.error("Error exporting PDF:", error);
    } finally {
      setIsExporting(false);
    }
  }, []);

  return { exportCSV, exportPDF, isExporting };
};

const UrlReportsPage = () => {
  const { urlReportsData, urlReportsLoading } = useGetUrlReportsData();
  const { exportCSV, exportPDF, isExporting } = useExportUrlReportsData();

  return (
    <ReportsLayout
      title="URL Reports"
      onDownloadCSV={exportCSV}
      onDownloadPDF={exportPDF}
      isExporting={isExporting}
    >
      <UrlReportsTable data={urlReportsData} loading={urlReportsLoading} />
    </ReportsLayout>
  );
};

export default UrlReportsPage;
