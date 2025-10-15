import * as React from "react";
import { ReportsLayout } from "@/components/reports/ReportsLayout";
import { UrlReportsTable } from "@/components/reports/UrlReportsTable";
import { mockUrlReports } from "@/data/mockReports";

const UrlReportsPage = () => {
  return (
    <ReportsLayout title="URL Reports">
      <UrlReportsTable data={mockUrlReports} />
    </ReportsLayout>
  );
};

export default UrlReportsPage;
