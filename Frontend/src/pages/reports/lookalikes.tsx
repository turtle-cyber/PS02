import * as React from "react";
import { ReportsLayout } from "@/components/reports/ReportsLayout";
import { LookalikesTable } from "@/components/reports/LookalikesTable";
import { mockLookalikes } from "@/data/mockReports";

const LookalikesPage = () => {
  return (
    <ReportsLayout title="Lookalikes">
      <LookalikesTable data={mockLookalikes} />
    </ReportsLayout>
  );
};

export default LookalikesPage;
