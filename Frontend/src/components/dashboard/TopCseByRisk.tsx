import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { EChartBase } from "@/components/echarts/echart-base";
import { Box, CircularProgress, Typography } from "@mui/material";
import type { BarSeriesOption, EChartsOption } from "echarts";

type Hit = { name?: string; category?: string };
type Bucket = { count: number; hits: Hit[] };

interface ThreatApiData {
  phishing?: Bucket;
  suspicious?: Bucket;
  benign?: Bucket;
  inactive?: Bucket;
  parked?: Bucket;
}

interface TopCseByRiskProps {
  apiData?: ThreatApiData | null;
  loading?: boolean;
  /** Optional: limit how many sectors to display (sorted by total desc). Default 8 */
  maxSectors?: number;
}

const STATUS_ORDER: Array<keyof ThreatApiData> = [
  "phishing",
  "suspicious",
  "parked",
  "inactive",
  "benign",
];

const STATUS_CONFIG: Record<
  keyof ThreatApiData,
  { label: string; color: string }
> = {
  phishing: { label: "Phishing", color: "#DC2626" }, // red
  suspicious: { label: "Suspicious", color: "#EA580C" }, // orange
  parked: { label: "Parked", color: "#EAB308" }, // yellow
  inactive: { label: "Inactive", color: "#22C55E" }, // green
  benign: { label: "Benign", color: "#3B82F6" }, // blue
};

function cleanName(n?: string) {
  const s = (n || "").trim();
  if (!s) return "";
  const lower = s.toLowerCase();
  if (lower === "unknown" || lower === "url from user") return "";
  return s;
}

function cleanCategory(c?: string) {
  const s = (c || "").trim();
  if (!s || s.toLowerCase() === "unknown") return "Uncategorized";
  return s;
}

type SectorRow = {
  sector: string;
  totals: Record<keyof ThreatApiData, number>; // raw counts (deduped names)
  totalAll: number;
};

function buildSectorRows(
  apiData?: ThreatApiData | null,
  maxSectors = 8
): SectorRow[] {
  if (!apiData) return [];

  // sector -> status -> Set of unique names
  const map: Record<string, Record<string, Set<string>>> = {};

  for (const statusKey of STATUS_ORDER) {
    const bucket = apiData[statusKey];
    if (!bucket || !bucket.hits) continue;

    for (const h of bucket.hits) {
      const name = cleanName(h?.name);
      if (!name) continue;
      const sector = cleanCategory(h?.category);

      if (!map[sector]) map[sector] = {};
      if (!map[sector][statusKey]) map[sector][statusKey] = new Set<string>();
      map[sector][statusKey].add(name);
    }
  }

  // Convert to rows with counts
  const rows: SectorRow[] = Object.entries(map).map(([sector, statusSets]) => {
    const totals = {
      phishing: statusSets["phishing"]?.size ?? 0,
      suspicious: statusSets["suspicious"]?.size ?? 0,
      parked: statusSets["parked"]?.size ?? 0,
      inactive: statusSets["inactive"]?.size ?? 0,
      benign: statusSets["benign"]?.size ?? 0,
    } as Record<keyof ThreatApiData, number>;

    const totalAll = STATUS_ORDER.reduce((acc, k) => acc + (totals[k] || 0), 0);
    return { sector, totals, totalAll };
  });

  // Filter sectors with zero total
  const nonZero = rows.filter((r) => r.totalAll > 0);

  // Sort by total desc, then alpha
  nonZero.sort(
    (a, b) => b.totalAll - a.totalAll || a.sector.localeCompare(b.sector)
  );

  // Limit to top N
  return nonZero.slice(0, maxSectors);
}

export const TopCseByRisk: React.FC<TopCseByRiskProps> = React.memo(({
  apiData,
  loading,
  maxSectors = 8,
}) => {
  // Build sector rows and convert to percentages
  const rows = React.useMemo(
    () => buildSectorRows(apiData, maxSectors),
    [apiData, maxSectors]
  );
  const hasData = rows.length > 0;

  // Y-axis labels
  const sectors = React.useMemo(() => rows.map((r) => r.sector), [rows]);

  // For stacked percentage bars (0..100), compute percentages per sector
  const toPct = (num: number, denom: number) =>
    denom ? (num / denom) * 100 : 0;

  const series = React.useMemo(
    () =>
      STATUS_ORDER.map((statusKey, idx) => ({
        name: STATUS_CONFIG[statusKey].label,
        type: "bar",
        stack: "total",
        barWidth: "60%",
        barMaxWidth: 24,
        itemStyle: { color: STATUS_CONFIG[statusKey].color },
        data: rows.map((r) => toPct(r.totals[statusKey], r.totalAll)),
      })) satisfies BarSeriesOption[],
    [rows]
  );

  const legendLabels = React.useMemo(
    () => STATUS_ORDER.map((k) => STATUS_CONFIG[k].label),
    []
  );

  const option: EChartsOption = React.useMemo(
    () => ({
      backgroundColor: "transparent",
      grid: {
        left: "5%",
        right: "25%",
        top: "15%",
        bottom: "5%",
        containLabel: false,
      },
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: "rgba(0, 0, 0, 0.9)",
        borderColor: "rgba(255, 255, 255, 0.1)",
        textStyle: { color: "#ffffff" },
        // Show both % and raw counts in tooltip
        formatter: (params: any) => {
          if (!params || !params.length) return "";
          const sectorIdx = params[0].dataIndex;
          const row = rows[sectorIdx];
          if (!row) return "";

          const lines = [
            `<div style="margin-bottom:6px;"><b>${row.sector}</b></div>`,
          ];
          for (const p of params) {
            const statusKey = STATUS_ORDER.find(
              (k) => STATUS_CONFIG[k].label === p.seriesName
            );
            if (!statusKey) continue;
            const raw = row.totals[statusKey] ?? 0;
            const pct = row.totalAll
              ? ((raw / row.totalAll) * 100).toFixed(1)
              : "0.0";
            const color = STATUS_CONFIG[statusKey].color;
            lines.push(
              `<div style="display:flex;align-items:center;gap:8px;">
              <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${color}"></span>
              <span>${STATUS_CONFIG[statusKey].label}: ${pct}% <span style="opacity:.7">(${raw})</span></span>
            </div>`
            );
          }
          return lines.join("");
        },
      } as any,
      legend: {
        data: legendLabels,
        top: 10,
        left: 680,
        textStyle: { color: "#a1a1aa", fontSize: 11 },
        itemWidth: 12,
        itemHeight: 12,
      },
      xAxis: {
        type: "value",
        max: 100,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { show: false },
        splitLine: { lineStyle: { color: "rgba(255, 255, 255, 0.05)" } },
      },
      yAxis: {
        type: "category",
        data: sectors,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: "#a1a1aa", fontSize: 12 },
      },
      series,
    }),
    [rows, sectors, series, legendLabels]
  );

  return (
    <LiquidCard variant="glass" className="p-6 min-h-[400px]">
      {loading ? (
        <Box
          display="flex"
          alignItems="center"
          justifyContent="center"
          height={400}
        >
          <CircularProgress size={24} />
        </Box>
      ) : !hasData ? (
        <Box
          display="flex"
          alignItems="center"
          justifyContent="space-between"
          gap={4}
          height={400}
        >
          <Box
            flex={1}
            display="flex"
            flexDirection="column"
            justifyContent="center"
          >
            {/* Empty chart placeholder box */}
            <div className="h-[240px] rounded-lg border border-white/10 bg-white/5" />
            {/* Legend */}
            <div className="flex items-center gap-5 mt-4">
              {STATUS_ORDER.map((k) => (
                <div key={k} className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full shadow-sm"
                    style={{ backgroundColor: STATUS_CONFIG[k].color }}
                  />
                  <span className="text-slate-300 text-xs font-medium">
                    {STATUS_CONFIG[k].label}
                  </span>
                </div>
              ))}
            </div>
          </Box>
          <div className="text-right flex-shrink-0 max-w-md">
            <Typography variant="body1" sx={{ color: "rgba(226,232,240,0.9)" }}>
              No data found for the selected range.
            </Typography>
          </div>
        </Box>
      ) : (
        <div className="h-[400px]">
          <EChartBase option={option} />
        </div>
      )}
    </LiquidCard>
  );
});
