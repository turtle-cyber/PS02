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

interface UrlInsightsRow {
  sourceUrl: string;
  ip: string;
  provider: string;
  cseIntended: string;
  verdict: string;
}

interface UrlInsightsTableProps {
  rows: UrlInsightsRow[];
}

const getVerdictVariant = (verdict: string) => {
  switch (verdict) {
    case 'Phishing':
      return 'destructive';
    case 'Suspicious':
      return 'secondary';
    case 'Clean':
      return 'default';
    default:
      return 'outline';
  }
};

const getVerdictColor = (verdict: string) => {
  switch (verdict) {
    case 'Phishing':
      return 'bg-[#E50914] text-white';
    case 'Suspicious':
      return 'bg-[#FFB020] text-black';
    case 'Clean':
      return 'bg-[#1FBF75] text-white';
    default:
      return '';
  }
};

export const UrlInsightsTable: React.FC<UrlInsightsTableProps> = ({ rows }) => {
  return (
    <LiquidCard variant="glass" className="p-6 min-h-[360px]">
      <ScrollArea className="h-[300px] pr-4">
        <Table>
          <TableHeader>
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="text-gray-400 font-medium">Source URL</TableHead>
              <TableHead className="text-gray-400 font-medium">IP Address</TableHead>
              <TableHead className="text-gray-400 font-medium">Hosting Provider</TableHead>
              <TableHead className="text-gray-400 font-medium">CSE Intended</TableHead>
              <TableHead className="text-gray-400 font-medium">Verdict</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row, idx) => (
              <TableRow 
                key={idx} 
                className="border-white/5 hover:bg-white/[0.03] transition-colors"
              >
                <TableCell className="text-blue-400 text-sm max-w-[200px] truncate">
                  {row.sourceUrl}
                </TableCell>
                <TableCell className="text-slate-300 text-sm">{row.ip}</TableCell>
                <TableCell className="text-slate-300 text-sm">{row.provider}</TableCell>
                <TableCell className="text-slate-300 text-sm">{row.cseIntended}</TableCell>
                <TableCell>
                  <Badge className={`${getVerdictColor(row.verdict)} border-0`}>
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
