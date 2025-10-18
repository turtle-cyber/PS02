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
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

/* ====== Only the fields used by the table ====== */
interface DomainItem {
  id: string;
  metadata: {
    registrable?: string; // Source URL/domain
    ipv4?: string | null; // IP Address
    risk_score?: number; // Risk
    final_verdict?: string; // Verdict (preferred)
    verdict?: string; // Verdict (fallback)
    nameserver?: string | null; // Name Server
    mx_count?: number | null; // MX Records
    first_seen?: string; // Registration Date (or first seen)
    registrar?: string; // Registrar
  };
}

interface LookalikesTableProps {
  data: DomainItem[]; // pass response.domains
  loading?: boolean;
}

/* ====== UI helpers ====== */
const getVerdictColor = (verdict?: string) => {
  const v = String(verdict ?? "").toLowerCase();
  if (v === "phishing")
    return "bg-[#8B373A]/20 text-[#E1E1E1] border-[#E50914]/40";
  if (v === "suspicious")
    return "bg-[#FDD835]/20 text-[#E1E1E1] border-[#FFB020]/40";
  if (v === "benign" || v === "clean")
    return "bg-[#43A047]/20 text-[#E1E1E1] border-[#1FBF75]/40";
  return "bg-slate-500/20 text-slate-400 border-slate-500/40";
};

const getRiskColor = (risk?: number) => {
  const r = Number.isFinite(risk) ? Number(risk) : NaN;
  if (!Number.isFinite(r)) return "text-slate-400";
  if (r >= 80) return "text-[#E7535C]";
  if (r >= 60) return "text-[#F57F17]";
  if (r >= 40) return "text-[#FDD835]";
  if (r >= 20) return "text-[#43A047]";
  return "text-[#2D9CDB]";
};

const safe = (v: unknown) =>
  v === null || v === undefined || String(v).trim() === "" ? "N/A" : String(v);

const hrefFromDomain = (d?: string) =>
  d && /^https?:\/\//i.test(d) ? d : d ? `https://${d}` : undefined;

const SkeletonBar: React.FC<{ className?: string }> = ({ className }) => (
  <div
    className={`h-4 w-[70%] bg-white/10 rounded animate-pulse ${
      className || ""
    }`}
  />
);

/* ====== Component ====== */
export const LookalikesTable: React.FC<LookalikesTableProps> = ({
  data,
  loading = false,
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

  // Navigate to detail by domain extracted from id (before the colon)
  const handleRowClick = (row: DomainItem) => {
    const raw = row?.id ?? "";
    const idOnly = raw.includes(":") ? raw.split(":")[0] : raw;
    navigate(`/reports/lookalikes/detail/${encodeURIComponent(idOnly)}`);
  };

  const isEmpty = !loading && rows.length === 0;

  const SkeletonRow = ({ i }: { i: number }) => (
    <TableRow key={`sk-${i}`} className="border-white/5">
      {/* checkbox cell */}
      <TableCell>
        <div className="h-4 w-4 rounded bg-white/10 animate-pulse" />
      </TableCell>
      {/* remaining 9 cells */}
      {Array.from({ length: 9 }).map((_, c) => (
        <TableCell key={c}>
          <SkeletonBar />
        </TableCell>
      ))}
    </TableRow>
  );

  return (
    <div className="relative">
      <ScrollArea className="h-[85vh]">
        <Table role="table" aria-label="Lookalike Domains">
          <TableHeader className="sticky top-0 z-10 bg-black/40 backdrop-blur-sm">
            <TableRow className="border-white/10 hover:bg-transparent">
              <TableHead className="w-12">
                <Checkbox
                  checked={rows.length > 0 && selectedRows.size === rows.length}
                  onCheckedChange={toggleAll}
                  aria-label="Select all"
                />
              </TableHead>
              <TableHead className="text-slate-400">Source URL</TableHead>
              <TableHead className="text-slate-400">IP Address</TableHead>
              <TableHead className="text-slate-400">URL Construction</TableHead>
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
                  colSpan={10}
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
                const risk = m.risk_score;
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
                      <Checkbox
                        checked={selectedRows.has(row.id)}
                        onCheckedChange={(e) => toggleRow(row.id, e as any)}
                        aria-label={`Select ${sourceUrl ?? row.id}`}
                      />
                    </TableCell>

                    <TableCell>
                      {href ? (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#2D9CDB] hover:underline hover:text-[#5DB9E8] transition-colors"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {safe(sourceUrl)}
                        </a>
                      ) : (
                        <span className="text-slate-300">
                          {safe(sourceUrl)}
                        </span>
                      )}
                    </TableCell>

                    <TableCell className="text-slate-300">{safe(ip)}</TableCell>

                    {/* URL Construction is not provided by API → show N/A */}
                    <TableCell className="text-slate-300">N/A</TableCell>

                    <TableCell
                      className={`font-semibold ${getRiskColor(risk)}`}
                    >
                      {Number.isFinite(risk) ? risk : "N/A"}
                    </TableCell>

                    <TableCell>
                      <Badge className={getVerdictColor(verdict)}>
                        {safe(verdict)}
                      </Badge>
                    </TableCell>

                    <TableCell className="text-slate-300">{safe(ns)}</TableCell>
                    <TableCell className="text-slate-300">
                      {mx === null || mx === undefined ? "N/A" : String(mx)}
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
