import * as React from "react";
import {
  Box,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  TableContainer,
  Chip,
  Skeleton,
} from "@mui/material";

interface URLProcess {
  org_urls: string;
  risk_score: number;
  country: string;
  first_seen: string;
  cse: string;
  verdict: string; // 'phishing' | 'suspicious' | 'parked' | 'inactive' | 'benign' | ...
}

interface UrlProcessTableProps {
  data?: URLProcess[];
  loading?: boolean;
  /** Optional: cap the table height (default 400) */
  maxHeight?: number | string;
}

export const URLProcessTable: React.FC<UrlProcessTableProps> = ({
  data,
  loading,
  maxHeight = 400,
}) => {
  const rows = Array.isArray(data) ? data : [];
  const empty = !loading && rows.length === 0;

  const verdictChipSX = (v: string) => {
    const key = (v || "").toLowerCase();
    if (key === "phishing") return { bgcolor: "#E50914", color: "#fff" };
    if (key === "suspicious") return { bgcolor: "#EA580C", color: "#fff" };
    if (key === "parked") return { bgcolor: "#EAB308", color: "#111" };
    if (key === "inactive") return { bgcolor: "#22C55E", color: "#111" };
    if (key === "benign") return { bgcolor: "#3B82F6", color: "#fff" };
    return { bgcolor: "#6B7280", color: "#fff" };
  };

  const isHttpUrl = (s: string) => /^https?:\/\//i.test(s);
  const clean = (s?: string) => {
    const t = (s || "").trim();
    if (!t || t.toLowerCase() === "unknown" || t.toLowerCase() === "n/a")
      return "—";
    return t;
  };

  return (
    <Box sx={{ width: "100%" }}>
      <TableContainer
        sx={{
          maxHeight,
          overflow: "auto",
          borderRadius: 2,
          border: "1px solid rgba(255,255,255,0.08)",

          "& .MuiTableCell-stickyHeader": {
            top: 0,
            zIndex: 2,
            backgroundColor: "rgba(53, 53, 53, 0.5)",
            backdropFilter: "saturate(150%) blur(10px)",
            WebkitBackdropFilter: "saturate(150%) blur(10px)",
            borderBottom: "1px solid rgba(255,255,255,0.08)",
          },
          "& thead th:first-of-type": { borderTopLeftRadius: 12 },
          "& thead th:last-of-type": { borderTopRightRadius: 12 },
          scrollbarColor: "rgba(255,255,255,0.28) transparent",
          "&::-webkit-scrollbar": { width: 6, height: 6 },
          "&::-webkit-scrollbar-thumb": {
            background: "rgba(255,255,255,0.28)",
            borderRadius: 8,
          },
          "&::-webkit-scrollbar-thumb:hover": {
            background: "rgba(255,255,255,0.38)",
          },
          "&::-webkit-scrollbar-corner": { background: "transparent" },
        }}
      >
        <Table
          stickyHeader
          sx={{
            minWidth: 760, // a bit wider so horizontal scroll can appear when needed
            backgroundColor: "transparent",
            "& td, & th": { borderBottomColor: "rgba(255,255,255,0.08)" },

            // ✅ Taller header + rows
            "& thead .MuiTableCell-root": {
              py: 1.8, // ~58–60px header (depends on font size)
              fontWeight: 700,
              color: "rgba(241,245,249,0.92)",
              fontSize: 13.5,
              letterSpacing: 0.2,
            },
            "& tbody .MuiTableCell-root": {
              py: 1.6, // ~50–54px rows
              fontSize: 13,
            },
          }}
        >
          <TableHead>
            <TableRow>
              <TableCell>Org URL</TableCell>
              <TableCell>Score</TableCell>
              <TableCell>Country</TableCell>
              <TableCell>First Seen</TableCell>
              <TableCell>Verdict</TableCell>
            </TableRow>
          </TableHead>

          <TableBody>
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={`sk-${i}`} hover>
                  <TableCell>
                    <Skeleton variant="text" width="80%" height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="text" width={48} height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="text" width={66} height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="text" width="70%" height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="rounded" width={80} height={28} />
                  </TableCell>
                </TableRow>
              ))
            ) : empty ? (
              <TableRow>
                <TableCell
                  colSpan={5}
                  align="center"
                  sx={{ py: 6, color: "rgba(255,255,255,0.6)" }}
                >
                  No Data Found
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row, index) => {
                const url = clean(row.org_urls);
                const country = clean(row.country);
                const firstSeen = clean(row.first_seen);
                const verdict = (row.verdict || "").toLowerCase();

                return (
                  <TableRow
                    key={index}
                    hover
                    sx={{
                      "&:hover": { backgroundColor: "rgba(255,255,255,0.05)" },
                    }}
                  >
                    <TableCell
                      sx={{
                        maxWidth: 380,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        fontFamily:
                          'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                      }}
                      title={url}
                    >
                      {isHttpUrl(url) ? (
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          style={{ color: "#60A5FA", textDecoration: "none" }}
                          onMouseOver={(e) =>
                            (e.currentTarget.style.textDecoration = "underline")
                          }
                          onMouseOut={(e) =>
                            (e.currentTarget.style.textDecoration = "none")
                          }
                        >
                          {url}
                        </a>
                      ) : (
                        <span style={{ color: "#D1D5DB" }}>{url}</span>
                      )}
                    </TableCell>

                    <TableCell sx={{ color: "#fff", fontWeight: 700 }}>
                      {row.risk_score}
                    </TableCell>

                    <TableCell sx={{ color: "#D1D5DB" }}>{country}</TableCell>

                    <TableCell sx={{ color: "rgba(156,163,175,0.95)" }}>
                      {firstSeen}
                    </TableCell>

                    <TableCell>
                      <Chip
                        label={verdict || "—"}
                        size="small"
                        sx={verdictChipSX(verdict)}
                      />
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};
