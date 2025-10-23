import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@mui/material";

interface UrlInsightsRow {
  source_url: string;
  ip_address: string;
  hosting_provider: string;
  cse_intended: string;
  verdict: string;
}

interface UrlInsightsTableProps {
  rows?: UrlInsightsRow[]; // ← optional to allow "not passed"
  loading?: boolean;
}

const getVerdictColor = (verdict: string) => {
  switch (verdict) {
    case "phishing":
      return "bg-[#E50914] text-white capitalize";
    case "suspicious":
      return "bg-[#FFB020] text-black capitalize";
    case "benign":
      return "bg-[#1FBF75] text-white capitalize";
    default:
      return "";
  }
};

const headers = [
  "Source URL",
  "IP Address",
  "Hosting Provider",
  "CSE Intended",
  "Verdict",
];

export const UrlInsightsTable: React.FC<UrlInsightsTableProps> = ({
  rows,
  loading,
}) => {
  const data = Array.isArray(rows) ? rows : [];

  const renderSkeletonRows = (count = 5) =>
    Array.from({ length: count }).map((_, i) => (
      <TableRow key={`skeleton-${i}`} className="border-white/5">
        <TableCell>
          <Skeleton variant="rectangular" width={200} height={16} />
        </TableCell>
        <TableCell>
          <Skeleton variant="rectangular" width={140} height={16} />
        </TableCell>
        <TableCell>
          <Skeleton variant="rectangular" width={180} height={16} />
        </TableCell>
        <TableCell>
          <Skeleton variant="rectangular" width={140} height={16} />
        </TableCell>
        <TableCell>
          <Skeleton variant="rectangular" width={80} height={24} />
        </TableCell>
      </TableRow>
    ));

  const renderEmptyState = () => (
    <TableRow className="border-white/5">
      <TableCell colSpan={headers.length}>
        <div className="text-sm text-slate-400 py-4">
          No URL insights to display.
        </div>
      </TableCell>
    </TableRow>
  );

  return (
    <LiquidCard variant="glass" className="p-6 min-h-[460px]">
      <ScrollArea className="h-[400px] pr-4">
        <Table aria-busy={!!loading}>
          <TableHeader>
            <TableRow className="border-white/10 hover:bg-transparent">
              {headers.map((h) => (
                <TableHead key={h} className="text-gray-400 font-medium">
                  {h}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>

          <TableBody>
            {loading
              ? renderSkeletonRows(5)
              : data.length === 0
              ? renderEmptyState()
              : data.map((row, idx) => (
                  <TableRow
                    key={`${row.source_url}-${row.ip_address}-${idx}`}
                    className="border-white/5 hover:bg-white/[0.03] transition-colors"
                  >
                    <TableCell className="text-blue-400 text-sm max-w-[200px] truncate">
                      {row.source_url}
                    </TableCell>
                    <TableCell className="text-slate-300 text-sm">
                      {row.ip_address}
                    </TableCell>
                    <TableCell className="text-slate-300 text-sm">
                      {row.hosting_provider}
                    </TableCell>
                    <TableCell className="text-slate-300 text-sm">
                      {row.cse_intended}
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={`${getVerdictColor(row.verdict)} border-0`}
                      >
                        {row.verdict}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
          </TableBody>
        </Table>
      </ScrollArea>
    </LiquidCard>
  );
};
