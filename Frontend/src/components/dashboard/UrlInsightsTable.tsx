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

interface UrlInsightsRow {
  source_url: string;
  ip_address: string;
  hosting_provider: string;
  cse_intended: string;
  verdict: string;
}

interface UrlInsightsTableProps {
  rows?: UrlInsightsRow[];
  loading?: boolean;
  /** Optional: cap the table height (default 400) */
  maxHeight?: number | string;
}

export const UrlInsightsTable: React.FC<UrlInsightsTableProps> = ({
  rows,
  loading,
  maxHeight = 460,
}) => {
  const data = Array.isArray(rows) ? rows : [];
  const empty = !loading && data.length === 0;

  const verdictChipSX = (v: string) => {
  const key = (v || "").toLowerCase();
  if (key === "phishing") 
    return { 
      bgcolor: "rgba(139, 55, 58, 0.2)", 
      color: "#E1E1E1",
      border: "1px solid rgba(229, 9, 20, 0.4)"
    };
  if (key === "suspicious") 
    return { 
      bgcolor: "rgba(253, 216, 53, 0.2)", 
      color: "#E1E1E1",
      border: "1px solid rgba(255, 176, 32, 0.4)"
    };
  if (key === "parked") 
    return { 
      bgcolor: "rgba(234, 179, 8, 0.2)", 
      color: "#E1E1E1",
      border: "1px solid rgba(234, 179, 8, 0.4)"
    };
  if (key === "inactive") 
    return { 
      bgcolor: "rgba(34, 197, 94, 0.2)", 
      color: "#E1E1E1",
      border: "1px solid rgba(34, 197, 94, 0.4)"
    };
  if (key === "benign" || key === "clean") 
    return { 
      bgcolor: "rgba(67, 160, 71, 0.2)", 
      color: "#E1E1E1",
      border: "1px solid rgba(31, 191, 117, 0.4)"
    };
  return { 
    bgcolor: "rgba(100, 116, 139, 0.2)", 
    color: "#94A3B8",
    border: "1px solid rgba(100, 116, 139, 0.4)"
  };
};


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
            backdropFilter: "saturate(150%) blur(2px)",
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
            minWidth: 760,
            backgroundColor: "transparent",
            "& td, & th": { borderBottomColor: "rgba(255,255,255,0.08)" },

            "& thead .MuiTableCell-root": {
              py: 1.8,
              fontWeight: 700,
              color: "rgba(241,245,249,0.92)",
              fontSize: 13.5,
              letterSpacing: 0.2,
            },
            "& tbody .MuiTableCell-root": {
              py: 1.6,
              fontSize: 13,
            },
          }}
        >
          <TableHead>
            <TableRow>
              <TableCell>Source URL</TableCell>
              <TableCell>IP Address</TableCell>
              <TableCell>Hosting Provider</TableCell>
              <TableCell>CSE Intended</TableCell>
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
                    <Skeleton variant="text" width={140} height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="text" width="70%" height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="text" width={140} height={24} />
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
                  No URL insights to display.
                </TableCell>
              </TableRow>
            ) : (
              data.map((row, idx) => {
                const sourceUrl = clean(row.source_url);
                const ipAddress = clean(row.ip_address);
                const hostingProvider = clean(row.hosting_provider);
                const cseIntended = clean(row.cse_intended);
                const verdict = (row.verdict || "").toLowerCase();

                return (
                  <TableRow
                    key={`${row.source_url}-${row.ip_address}-${idx}`}
                    hover
                    sx={{
                      "&:hover": { backgroundColor: "rgba(255,255,255,0.05)" },
                    }}
                  >
                    <TableCell
                      sx={{
                        maxWidth: 280,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        color: "#60A5FA",
                      }}
                      title={sourceUrl}
                    >
                      {sourceUrl}
                    </TableCell>

                    <TableCell sx={{ color: "#D1D5DB" }}>
                      {ipAddress}
                    </TableCell>

                    <TableCell sx={{ color: "#D1D5DB" }}>
                      {hostingProvider}
                    </TableCell>

                    <TableCell sx={{ color: "#D1D5DB" }}>
                      {cseIntended}
                    </TableCell>

                    <TableCell>
                      <Chip
                        label={verdict.charAt(0).toUpperCase() + verdict.slice(1).toLowerCase()}
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