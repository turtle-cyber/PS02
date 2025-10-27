import { ReportsLayout } from "@/components/reports/ReportsLayout";
import { LookalikesTable } from "@/components/reports/LookalikesTable";
import { mockLookalikes } from "@/data/mockReports";
import { useCallback, useEffect, useState } from "react";
import { http } from "@/hooks/config";
import { GET_LOOKALIKE_TABLE } from "@/endpoints/reports.endpoints";
import { toast } from "sonner";
import { exportToCSV, exportToPDF } from "@/utils/exportUtils";

const useGetLookalikeData = () => {
  const [lookalikeData, setLookalikeData] = useState<any>({});
  const [lookalikeLoading, setLookalikeLoading] = useState(false);

  const fetchLookalike = useCallback(async () => {
    setLookalikeLoading(true);
    try {
      const response = await http.get(GET_LOOKALIKE_TABLE, {
        params: { limit: 20 },
      });
      setLookalikeData(response?.data?.domains || []);
    } catch (error) {
      toast.error("Error Fetching Lookalike Data");
      console.error("Error Fetching Lookalike Data with error: ", error);
    } finally {
      setLookalikeLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchLookalike();
  }, [fetchLookalike]);

  return { lookalikeData, lookalikeLoading, refetch: fetchLookalike };
};

const useExportLookalikeData = () => {
  const [isExporting, setIsExporting] = useState(false);

  const exportCSV = useCallback(async () => {
    setIsExporting(true);
    try {
      // Fetch 1000 rows for export
      const response = await http.get(GET_LOOKALIKE_TABLE, {
        params: { limit: 1000 },
      });
      const exportData = response?.data?.domains || [];

      if (exportData.length === 0) {
        toast.warning("No data available to export");
        return;
      }

      exportToCSV(exportData, "lookalikes", "lookalikes");
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
      const response = await http.get(GET_LOOKALIKE_TABLE, {
        params: { limit: 1000 },
      });
      const exportData = response?.data?.domains || [];

      if (exportData.length === 0) {
        toast.warning("No data available to export");
        return;
      }

      exportToPDF(exportData, "lookalikes", "lookalikes");
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

const LookalikesPage = () => {
  const { lookalikeData, lookalikeLoading } = useGetLookalikeData();
  const { exportCSV, exportPDF, isExporting } = useExportLookalikeData();

  return (
    <ReportsLayout
      title="Lookalikes"
      onDownloadCSV={exportCSV}
      onDownloadPDF={exportPDF}
      isExporting={isExporting}
    >
      <LookalikesTable data={lookalikeData} loading={lookalikeLoading} />
    </ReportsLayout>
  );
};

export default LookalikesPage;
