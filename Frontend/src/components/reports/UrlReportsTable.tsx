import * as React from "react";
import { useNavigate } from "react-router-dom";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

interface DomainItem {
  id: string;
  metadata: {
    registrable?: string;
    ipv4?: string | null;
    risk_score?: number;
    final_verdict?: string;
    verdict?: string;
    nameserver?: string | null;
    mx_count?: number;
    first_seen?: string;
    registrar?: string;
  };
}

interface UrlReportsTableProps {
  data: DomainItem[]; // pass response.domains
  loading?: boolean;
}

const getVerdictColor = (verdict: string | undefined) => {
  const v = String(verdict ?? "").toLowerCase();
  if (v === "phishing")
    return "bg-[#8B373A]/20 text-[#E1E1E1] border-[#E50914]/40 capitalize";
  if (v === "suspicious")
    return "bg-[#FDD835]/20 text-[#E1E1E1] border-[#FFB020]/40 capitalize";
  if (v === "benign" || v === "clean")
    return "bg-[#43A047]/20 text-[#E1E1E1] border-[#1FBF75]/40 capitalize";
  return "bg-slate-500/20 text-slate-400 border-slate-500/40 capitalize";
};

const getRiskColor = (risk: number | undefined) => {
  const r = Number(risk ?? 0);
  if (r >= 80) return "text-[#E7535C]";
  if (r >= 60) return "text-[#F57F17]";
  if (r >= 40) return "text-[#FDD835]";
  if (r >= 20) return "text-[#43A047]";
  return "text-[#2D9CDB]";
};

const safe = (v: unknown) =>
  v === null || v === undefined || String(v).trim() === "" ? "—" : String(v);

const hrefFromDomain = (d?: string) =>
  d && /^https?:\/\//i.test(d) ? d : d ? `https://${d}` : undefined;

export const UrlReportsTable: React.FC<UrlReportsTableProps> = ({
  data,
  loading,
}) => {
  const navigate = useNavigate();
  const rows = Array.isArray(data) ? data : [];
  const [selectedRows, setSelectedRows] = React.useState<Set<string>>(
    new Set()
  );

  const toggleAll = () => {
    if (selectedRows.size === rows.length) setSelectedRows(new Set());
    else setSelectedRows(new Set(rows.map((r) => r.id)));
  };

  const toggleRow = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = new Set(selectedRows);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelectedRows(next);
  };

  // NEW: navigate to /reports/url/detail/<row.metadata.registrable>
  const handleRowClick = (row: DomainItem) => {
    const raw = row?.id ?? "";
    const idOnly = raw.includes(":") ? raw.split(":")[0] : raw;
    navigate(`/reports/url/detail/${encodeURIComponent(idOnly)}`);
  };

  const isEmpty = !loading && rows.length === 0;

  const SkeletonRow = ({ i }: { i: number }) => (
    <TableRow key={`sk-${i}`} className="border-white/5">
      {Array.from({ length: 9 }).map((_, c) => (
        <TableCell key={c}>
          <div className="h-4 w-[70%] bg-white/10 rounded animate-pulse" />
        </TableCell>
      ))}
    </TableRow>
  );

  return (
    <div className="relative">
      <ScrollArea className="h-[85vh]">
        <Table role="table" aria-label="URL Reports">
          <TableHeader className="sticky top-0 z-10 bg-black/40 backdrop-blur-sm">
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="w-12">
              </TableHead>
              <TableHead className="text-slate-400">Source URL</TableHead>
              <TableHead className="text-slate-400">IP Address</TableHead>
              <TableHead className="text-slate-400">Risk</TableHead>
              <TableHead className="text-slate-400">Verdict</TableHead>
              <TableHead className="text-slate-400">Name Server</TableHead>
              <TableHead className="text-slate-400">MX Records</TableHead>
              <TableHead className="text-slate-400">
                Registration Date
              </TableHead>
              <TableHead className="text-slate-400">Registrar</TableHead>
            </TableRow>
          </TableHeader>

          <TableBody>
            {loading ? (
              <>
                {Array.from({ length: 10 }).map((_, i) => (
                  <SkeletonRow i={i} key={i} />
                ))}
              </>
            ) : isEmpty ? (
              <TableRow className="border-white/5">
                <TableCell
                  colSpan={9}
                  className="text-center text-gray-400 py-8"
                >
                  No data found
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => {
                const m = row.metadata || {};
                const sourceUrl = m.registrable;
                const href = hrefFromDomain(sourceUrl);
                const ip = m.ipv4;
                const risk = m.risk_score ?? 0;
                const verdict = (m.final_verdict ?? m.verdict) as
                  | string
                  | undefined;
                const ns = m.nameserver;
                const mx = m.mx_count;
                const firstSeen = m.first_seen;
                const registrar = m.registrar;

                return (
                  <TableRow
                    key={row.id}
                    className="border-white/5 hover:bg-white/[0.03] transition-colors cursor-pointer"
                    onClick={() => handleRowClick(row)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        handleRowClick(row);
                      }
                    }}
                    tabIndex={0}
                  >
                    <TableCell onClick={(e) => e.stopPropagation()}>
                    </TableCell>

                    <TableCell>
                      {href ? (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#2D9CDB] hover:underline hover:text-[#5DB9E8] transition-colors"
                          onClick={(e) => e.stopPropagation()} // prevent row navigation when opening link
                        >
                          {sourceUrl}
                        </a>
                      ) : (
                        <span className="text-slate-300">
                          {safe(sourceUrl)}
                        </span>
                      )}
                    </TableCell>

                    <TableCell className="text-slate-300">{safe(ip)}</TableCell>

                    <TableCell
                      className={`font-semibold ${getRiskColor(risk)}`}
                    >
                      {Number.isFinite(risk) ? risk : 0}
                    </TableCell>

                    <TableCell>
                      <Badge className={getVerdictColor(verdict)}>
                        {safe(verdict)}
                      </Badge>
                    </TableCell>

                    <TableCell className="text-slate-300">{safe(ns)}</TableCell>
                    <TableCell className="text-slate-300">
                      {mx === null || mx === undefined ? "—" : String(mx)}
                    </TableCell>
                    <TableCell className="text-slate-300">
                      {safe(firstSeen)}
                    </TableCell>
                    <TableCell className="text-slate-300">
                      {safe(registrar)}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  );
};
