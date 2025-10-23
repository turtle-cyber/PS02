import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
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

interface ParkedInsightsRow {
  domain: string;
  parked_since: string;
  verdict: string;
}

interface ParkedInsightsTableProps {
  rows?: ParkedInsightsRow[];
  loading?: boolean;
}

const getVerdictColor = (verdict: string) => {
  switch (verdict) {
    case "Phishing Confirmed":
      return "text-[#D32F2F]";
    case "parked":
      return "text-[#FBC02D]";
    case "Safe Domain":
      return "text-[#72BBDF]";
    default:
      return "bg-slate-700 text-white";
  }
};

const HEADERS = ["Domain Name", "Parked Since", "Recent Verdict"];
const STAGGER_MS = 80;

export const ParkedInsightsTable: React.FC<ParkedInsightsTableProps> = ({
  rows,
  loading = false,
}) => {
  const data = Array.isArray(rows) ? rows : [];

  const renderSkeletonRows = (count = 5) =>
    Array.from({ length: count }).map((_, i) => (
      <TableRow key={`skeleton-${i}`} className="border-white/5">
        <TableCell colSpan={HEADERS.length} style={{ padding: 0 }}>
          <div className="py-2">
            <Skeleton
              variant="rectangular"
              height={38}
              sx={{ borderRadius: 1.5, bgcolor: "rgba(255,255,255,0.08)" }}
            />
          </div>
        </TableCell>
      </TableRow>
    ));

  const renderEmptyState = () => (
    <TableRow className="border-white/5">
      <TableCell colSpan={HEADERS.length}>
        <div className="text-sm text-slate-400 py-4 text-center">
          No Data Found
        </div>
      </TableCell>
    </TableRow>
  );

  return (
    <LiquidCard variant="glass" className="p-6 min-h-[450px]">
      {/* Row fade-in animation CSS (scoped) */}
      {/* <style>{`
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(-6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .tr-fade {
          opacity: 0;
          animation: fadeInUp 360ms ease-out forwards;
          will-change: transform, opacity;
        }
        @media (prefers-reduced-motion: reduce) {
          .tr-fade { animation: none; opacity: 1; transform: none; }
        }
      `}</style> */}

      <ScrollArea className="h-[400px] pr-4">
        <Table aria-busy={!!loading}>
          <TableHeader>
            <TableRow className="border-white/10 hover:bg-transparent">
              {HEADERS.map((h) => (
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
                    key={`${row.domain}-${row.parked_since}-${idx}`}
                    className="border-white/5 hover:bg-white/[0.03] transition-colors tr-fade"
                    style={{ animationDelay: `${idx * STAGGER_MS}ms` }}
                  >
                    <TableCell className="text-slate-300 text-sm">
                      {row.domain}
                    </TableCell>
                    <TableCell className="text-slate-300 text-sm">
                      {row.parked_since}
                    </TableCell>
                    <TableCell>
                      <span className={`${getVerdictColor(row.verdict)}`}>
                        {row.verdict}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
          </TableBody>
        </Table>
      </ScrollArea>
    </LiquidCard>
  );
};
