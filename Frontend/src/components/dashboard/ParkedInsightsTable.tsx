import * as React from "react";
import {
  Box,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  TableContainer,
  Skeleton,
} from "@mui/material";

interface ParkedInsightsRow {
  domain: string;
  parked_since: string;
  verdict: string;
}

interface ParkedInsightsTableProps {
  rows?: ParkedInsightsRow[];
  loading?: boolean;
  /** Optional: cap the table height (default 400) */
  maxHeight?: number | string;
}

export const ParkedInsightsTable: React.FC<ParkedInsightsTableProps> = ({
  rows,
  loading = false,
  maxHeight = 450,
}) => {
  const data = Array.isArray(rows) ? rows : [];
  const empty = !loading && data.length === 0;

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case "Phishing Confirmed":
        return "#D32F2F";
      case "parked":
        return "#FBC02D";
      case "Safe Domain":
        return "#72BBDF";
      default:
        return "#6B7280";
    }
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
            minWidth: 600,
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
              <TableCell>Domain Name</TableCell>
              <TableCell>Parked Since</TableCell>
              <TableCell>Recent Verdict</TableCell>
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
                    <Skeleton variant="text" width="70%" height={24} />
                  </TableCell>
                  <TableCell>
                    <Skeleton variant="text" width={120} height={24} />
                  </TableCell>
                </TableRow>
              ))
            ) : empty ? (
              <TableRow>
                <TableCell
                  colSpan={3}
                  align="center"
                  sx={{ py: 6, color: "rgba(255,255,255,0.6)" }}
                >
                  No Data Found
                </TableCell>
              </TableRow>
            ) : (
              data.map((row, idx) => {
                const domain = clean(row.domain);
                const parkedSince = clean(row.parked_since);
                const verdict = row.verdict || "—";
                const verdictColor = getVerdictColor(verdict);

                return (
                  <TableRow
                    key={`${row.domain}-${row.parked_since}-${idx}`}
                    hover
                    sx={{
                      "&:hover": { backgroundColor: "rgba(255,255,255,0.05)" },
                    }}
                  >
                    <TableCell sx={{ color: "#D1D5DB" }}>
                      {domain}
                    </TableCell>

                    <TableCell sx={{ color: "#D1D5DB" }}>
                      {parkedSince}
                    </TableCell>

                    <TableCell sx={{ color: verdictColor, fontWeight: 500 }}>
                      {verdict}
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