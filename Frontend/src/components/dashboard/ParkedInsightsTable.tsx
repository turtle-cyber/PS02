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

interface ParkedInsightsRow {
  domain: string;
  parkedSince: string;
  recentVerdict: string;
}

interface ParkedInsightsTableProps {
  rows: ParkedInsightsRow[];
}

const getVerdictColor = (verdict: string) => {
  switch (verdict) {
    case 'Phishing Confirmed':
      return 'text-[#D32F2F]';
    case 'Suspicious':
      return 'text-[#FBC02D]';
    case 'Safe Domain':
      return 'text-[#72BBDF]';
    default:
      return 'bg-slate-700 text-white';
  }
};

export const ParkedInsightsTable: React.FC<ParkedInsightsTableProps> = ({ rows }) => {
  return (
    <LiquidCard variant="glass" className="p-6 min-h-[450px]">
      <ScrollArea className="h-[400px] pr-4">
        <Table>
          <TableHeader>
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="text-gray-400 font-medium">Domain Name</TableHead>
              <TableHead className="text-gray-400 font-medium">Parked Since</TableHead>
              <TableHead className="text-gray-400 font-medium">Recent Verdict</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row, idx) => (
              <TableRow 
                key={idx} 
                className="border-white/5 hover:bg-white/[0.03] transition-colors"
              >
                <TableCell className="text-slate-300 text-sm">{row.domain}</TableCell>
                <TableCell className="text-slate-300 text-sm">{row.parkedSince}</TableCell>
                <TableCell>
                  {/* <Badge className={`${getVerdictColor(row.recentVerdict)} border-0`}>
                    {row.recentVerdict}
                  </Badge> */}
                  {/* {getVerdictColor(row.recentVerdict)} */}
                  <span className={`${getVerdictColor(row?.recentVerdict)}`}>{row?.recentVerdict}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </ScrollArea>
    </LiquidCard>
  );
};
