import { ReportsLayout } from "@/components/reports/ReportsLayout";
import { LookalikesTable } from "@/components/reports/LookalikesTable";
import { mockLookalikes } from "@/data/mockReports";
import { useCallback, useEffect, useState } from "react";
import { http } from "@/hooks/config";
import { GET_LOOKALIKE_TABLE } from "@/endpoints/reports.endpoints";
import { toast } from "sonner";

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

const LookalikesPage = () => {
  const { lookalikeData, lookalikeLoading } = useGetLookalikeData();
  return (
    <ReportsLayout title="Lookalikes">
      <LookalikesTable data={lookalikeData} loading={lookalikeLoading} />
    </ReportsLayout>
  );
};

export default LookalikesPage;
