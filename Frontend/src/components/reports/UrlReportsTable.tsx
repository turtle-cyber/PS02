import * as React from "react";
import { useNavigate } from "react-router-dom";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { UrlReportRow } from "@/data/mockReports";

interface UrlReportsTableProps {
  data: UrlReportRow[];
}

const getVerdictColor = (verdict: string) => {
  switch (verdict) {
    case "Phishing":
      return "bg-[#8B373A]/20 text-[#E1E1E1] border-[#E50914]/40";
    case "Suspicious":
      return "bg-[#FDD835]/20 text-[#E1E1E1] border-[#FFB020]/40";
    case "Clean":
      return "bg-[#43A047]/20 text-[#E1E1E1] border-[#1FBF75]/40";
    default:
      return "bg-slate-500/20 text-slate-400 border-slate-500/40";
  }
};

const getRiskColor = (risk: number) => {
  if (risk >= 80) return "text-[#E7535C]";
  if (risk >= 60) return "text-[#F57F17]";
  if (risk >= 40) return "text-[#FDD835]";
  if (risk >= 20) return "text-[#43A047]";
  return "text-[#2D9CDB]";
};

export const UrlReportsTable: React.FC<UrlReportsTableProps> = ({ data }) => {
  const [selectedRows, setSelectedRows] = React.useState<Set<string>>(new Set());
  const navigate = useNavigate();

  const toggleAll = () => {
    if (selectedRows.size === data.length) {
      setSelectedRows(new Set());
    } else {
      setSelectedRows(new Set(data.map((row) => row.id)));
    }
  };

  const toggleRow = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const newSelected = new Set(selectedRows);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedRows(newSelected);
  };

  const handleRowClick = (row: UrlReportRow) => {
    navigate('/reports/url/detail', { state: { source: 'url', row } });
  };

  return (
    <div className="relative">
      <ScrollArea className="h-full">
        <Table role="table" aria-label="URL Reports">
          <TableHeader className="sticky top-0 z-10 bg-black/40 backdrop-blur-sm">
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="w-12">
                <Checkbox
                  checked={selectedRows.size === data.length}
                  onCheckedChange={toggleAll}
                  aria-label="Select all"
                />
              </TableHead>
              <TableHead className="text-slate-400">Source URL</TableHead>
              <TableHead className="text-slate-400">IP Address</TableHead>
              <TableHead className="text-slate-400">Risk</TableHead>
              <TableHead className="text-slate-400">Verdict</TableHead>
              <TableHead className="text-slate-400">Name Server</TableHead>
              <TableHead className="text-slate-400">MX Records</TableHead>
              <TableHead className="text-slate-400">Registration Date</TableHead>
              <TableHead className="text-slate-400">Registrar</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((row) => (
              <TableRow
                key={row.id}
                className="border-white/5 hover:bg-white/[0.03] transition-colors cursor-pointer"
                onClick={() => handleRowClick(row)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    handleRowClick(row);
                  }
                }}
                tabIndex={0}
              >
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <Checkbox
                    checked={selectedRows.has(row.id)}
                    onCheckedChange={(e) => toggleRow(row.id, e as any)}
                    aria-label={`Select ${row.sourceUrl}`}
                  />
                </TableCell>
                <TableCell>
                  <a
                    href={`https://${row.sourceUrl}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#2D9CDB] hover:underline hover:text-[#5DB9E8] transition-colors"
                  >
                    {row.sourceUrl}
                  </a>
                </TableCell>
                <TableCell className="text-slate-300">{row.ipAddress}</TableCell>
                <TableCell className={`font-semibold ${getRiskColor(row.risk)}`}>
                  {row.risk}
                </TableCell>
                <TableCell>
                  <Badge className={getVerdictColor(row.verdict)}>
                    {row.verdict}
                  </Badge>
                </TableCell>
                <TableCell className="text-slate-300">{row.nameServer}</TableCell>
                <TableCell className="text-slate-300">{row.mxRecords}</TableCell>
                <TableCell className="text-slate-300">{row.registrationDate}</TableCell>
                <TableCell className="text-slate-300">{row.registrar}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  );
};
