import { Link, useLocation } from "react-router-dom";
import {
  AppBar,
  Toolbar,
  Container,
  Button,
  Box,
  Menu,
  MenuItem,
  LinearProgress,
  styled,
  CircularProgress,
  Skeleton,
} from "@mui/material";
import { KeyboardArrowDown } from "@mui/icons-material";
import { LiquidCard } from "@/components/ui/liquid-card";
import { LiveDot } from "@/components/ui/live-dot";
import { EChartBase } from "@/components/echarts/echart-base";
import { URLProcessTable } from "@/components/monitoring/url-process-table";
import { TimeRangeTabs } from "@/components/monitoring/time-range-tabs";
import { Progress } from "@/components/ui/progress";
import { Button as ShadcnButton } from "@/components/ui/button";
import { FileText, FileDown } from "lucide-react";
import type { EChartsOption } from "echarts";
import { useCallback, useEffect, useMemo, useState } from "react";
import { http } from "@/hooks/config";
import {
  GET_LIVE_URL,
  GET_TAGGING_DISTRIBUTION,
  GET_UNIQUE_DOMAINS_COUNT,
  GET_URL_PROCESSES,
} from "@/endpoints/liveMonitoring.endpoints";
import { toast } from "sonner";

/* ---------- TYPES ---------- */
type TimeRange = "5m" | "30m" | "1h" | "24h";
type LivePoint = { timestamp: string; count: number; cumulative: number };

/* ---------- HELPERS ---------- */
const toBackendTimeframe = (t: TimeRange) =>
  t === "5m"
    ? "5min"
    : t === "30m"
    ? "30min"
    : t === "1h"
    ? "1hour" // ⬅️ fix
    : t === "24h"
    ? "24hours" // ⬅️ fix
    : t;

const CustomProgress = styled(LinearProgress)({
  height: 8,
  borderRadius: 4,
  backgroundColor: "#474747",
  "& .MuiLinearProgress-bar": {
    borderRadius: 4,
    backgroundColor:
      "linear-gradient(90deg, #E50914 0%, #FF1744 50%, #FF5252 100%)",
  },
});

/* ---------- API HOOKS ---------- */

const useGetLiveUrlScanData = (timeRange: TimeRange) => {
  const [liveUrlScanData, setLiveUrlScanData] = useState<LivePoint[]>([]);
  const [liveUrlScanLoading, setLiveUrlScanLoading] = useState(false);

  const fetchLiveUrlData = useCallback(async () => {
    setLiveUrlScanLoading(true);
    setLiveUrlScanData([]);
    try {
      const response = await http.get(GET_LIVE_URL, {
        params: { timeframe: toBackendTimeframe(timeRange) },
      });
      const arr = response?.data?.data;
      setLiveUrlScanData(Array.isArray(arr) ? arr : []);
    } catch (error) {
      toast.error("Error Fetching Live URL Data");
      console.error("Error Fetching Live URL Scan Data with error: ", error);
    } finally {
      setLiveUrlScanLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    fetchLiveUrlData();
  }, [fetchLiveUrlData]);

  return { liveUrlScanData, liveUrlScanLoading, refetch: fetchLiveUrlData };
};

const useGetUniqueDomainCount = () => {
  const [uniqueDomainCountData, setUniqueDomainCountData] = useState<any>({});
  const [uniqueDomainCountLoading, setUniqueDomainCountLoading] =
    useState(false);

  const fetchUniqueDomainCount = useCallback(async () => {
    setUniqueDomainCountLoading(true);
    try {
      const response = await http.get(GET_UNIQUE_DOMAINS_COUNT);

      setUniqueDomainCountData(response?.data);
    } catch (error) {
      console.error(
        "Error Fetching Unique Domain Count Data with error: ",
        error
      );
    } finally {
      setUniqueDomainCountLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUniqueDomainCount();
  }, [fetchUniqueDomainCount]);

  return {
    uniqueDomainCountData,
    uniqueDomainCountLoading,
    refetch: fetchUniqueDomainCount,
  };
};

const useGetUrlTagging = () => {
  const [urlTaggingData, setUrlTaggingData] = useState<any>({});
  const [urlTaggingLoading, setUrlTaggingLoading] = useState(false);

  const fetchUrlTaggingData = useCallback(async () => {
    setUrlTaggingLoading(true);
    try {
      const response = await http.get(GET_TAGGING_DISTRIBUTION);

      setUrlTaggingData(response?.data);
    } catch (error) {
      console.error(
        "Error Fetching Unique Domain Count Data with error: ",
        error
      );
    } finally {
      setUrlTaggingLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUrlTaggingData();
  }, [fetchUrlTaggingData]);

  return {
    urlTaggingData,
    urlTaggingLoading,
    refetch: fetchUrlTaggingData,
  };
};

const useGetUrlProcess = () => {
  const [urlProcessData, setUrlProcessData] = useState<any>({});
  const [urlProcessLoading, setUrlProcessLoading] = useState(false);

  const fetchUrlProcessData = useCallback(async () => {
    setUrlProcessLoading(true);
    try {
      const response = await http.get(GET_URL_PROCESSES);
      console.log(response?.data);
      setUrlProcessData(response?.data?.data);
    } catch (error) {
      console.error("Error Fetching URL Process Data with error: ", error);
    } finally {
      setUrlProcessLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUrlProcessData();
  }, [fetchUrlProcessData]);

  return {
    urlProcessData,
    urlProcessLoading,
    refetch: fetchUrlProcessData,
  };
};

/* ---------- PAGE ---------- */

const LiveMonitoring: React.FC = () => {
  const [timeRange, setTimeRange] = useState<TimeRange>("5m");
  const [reportsAnchorEl, setReportsAnchorEl] = useState<null | HTMLElement>(
    null
  );
  const reportsOpen = Boolean(reportsAnchorEl);

  /* ------- API Data Unpacking ----------*/
  const { liveUrlScanData, liveUrlScanLoading } =
    useGetLiveUrlScanData(timeRange);

  const { uniqueDomainCountData, uniqueDomainCountLoading } =
    useGetUniqueDomainCount();

  const { urlTaggingData, urlTaggingLoading } = useGetUrlTagging();

  const { urlProcessData, urlProcessLoading } = useGetUrlProcess();

  /* ------- Helpers For Graph ------- */
  const seriesCount = useMemo<[number, number][]>(() => {
    return (liveUrlScanData ?? []).map((p: LivePoint) => [
      new Date(p.timestamp).getTime(),
      p.count,
    ]);
  }, [liveUrlScanData]);

  // Line chart option
  const lineChartOption: EChartsOption = useMemo(
    () => ({
      grid: { top: 40, right: 40, bottom: 40, left: 60, containLabel: false },
      xAxis: {
        type: "time",
        axisLine: { lineStyle: { color: "#333" } },
        axisLabel: {
          color: "#666",
          fontSize: 11,
          formatter: (value: number) =>
            new Intl.DateTimeFormat("en-IN", {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
            }).format(value),
        },
        splitLine: { show: false },
      },
      yAxis: {
        type: "value",
        min: 0,
        axisLine: { show: false },
        axisLabel: { color: "#666", fontSize: 11 },
        splitLine: { lineStyle: { color: "#222", type: "dashed" } },
      },
      legend: { show: false },
      tooltip: {
        trigger: "axis",
        backgroundColor: "rgba(0,0,0,0.8)",
        borderColor: "#E50914",
        textStyle: { color: "#fff" },
        valueFormatter: (v: number) => (v ?? 0).toLocaleString(),
      },
      series: [
        {
          name: "Scanned URLs",
          type: "line",
          smooth: true,
          showSymbol: false,
          connectNulls: true,
          data: seriesCount, // ← only count
          lineStyle: { color: "#E50914", width: 2 },
          itemStyle: { color: "#E50914" },
          areaStyle: { opacity: 0.08 },
        },
      ],
    }),
    [seriesCount]
  );

  // Stacked bar chart option
  const dist = urlTaggingData?.distribution ?? {};
  const phishing = Number(dist.phishing ?? 0);
  const parked = Number(dist.parked ?? 0);
  const suspicious = Number(dist.suspicious ?? 0);
  const benign = Number(dist.benign ?? 0);

  // sum used for full-width scaling
  const sum = phishing + parked + suspicious + benign;
  const xMax = Math.max(sum || 1, 1);

  // gradient helper
  const grad = (c1: string, c2: string) => ({
    type: "linear" as const,
    x: 0,
    y: 0,
    x2: 1,
    y2: 0,
    colorStops: [
      { offset: 0, color: c1 },
      { offset: 1, color: c2 },
    ],
  });

  // compute which segments are first/last non-zero
  const segments = [
    {
      name: "Phishing",
      key: "phishing",
      value: phishing,
      color: grad("#EF4444", "#F87171"),
    },
    {
      name: "Parked",
      key: "parked",
      value: parked,
      color: grad("#F59E0B", "#FBBF24"),
    },
    {
      name: "Suspicious",
      key: "suspicious",
      value: suspicious,
      color: grad("#60A5FA", "#93C5FD"),
    },
    {
      name: "Benign",
      key: "benign",
      value: benign,
      color: grad("#4CAF50", "#81C784"),
    },
  ];

  const firstIdx = segments.findIndex((s) => s.value > 0);
  const lastIdx = (() => {
    for (let i = segments.length - 1; i >= 0; i--)
      if (segments[i].value > 0) return i;
    return -1;
  })();

  const getRadius = (idx: number): [number, number, number, number] => {
    if (firstIdx === -1) return [8, 8, 8, 8]; // all zero (won't render anyway)
    if (firstIdx === lastIdx && idx === firstIdx) return [8, 8, 8, 8]; // only one non-zero segment
    if (idx === firstIdx) return [8, 0, 0, 8]; // leftmost non-zero
    if (idx === lastIdx) return [0, 8, 8, 0]; // rightmost non-zero
    return [0, 0, 0, 0];
  };

  // ---- bar option built dynamically ----
  const barChartOption: EChartsOption = useMemo(
    () => ({
      grid: { top: 0, right: 0, bottom: 0, left: 0, containLabel: false },
      xAxis: { type: "value", show: false, max: xMax },
      yAxis: { type: "category", show: false, data: [""] },
      series: segments.map((s, idx) => ({
        name: s.name,
        type: "bar",
        stack: "total",
        data: [s.value],
        barWidth: 24,
        itemStyle: { color: s.color, borderRadius: getRadius(idx) },
        label: {
          show: true,
          position: "top",
          color: "#fff",
          fontSize: 14,
          offset: [0, -8],
          formatter: (p: any) => (p.value > 0 ? String(p.value) : ""), // hide zero labels
        },
      })),
      tooltip: {
        trigger: "item",
        backgroundColor: "rgba(0,0,0,0.8)",
        borderColor: "#333",
        textStyle: { color: "#fff" },
        formatter: (p: any) => `${p.seriesName}: ${p.value}`,
      },
    }),
    [phishing, parked, suspicious, benign, xMax]
  );

  return (
    <Box
      sx={{
        minHeight: "100vh",
        position: "relative",
        overflowX: "hidden", // FIX: contain pseudo-elements + any wide child
        boxSizing: "border-box", // FIX: guard sizing math
        "&::before": {
          content: '""',
          position: "absolute",
          top: 0,
          left: "-10%",
          width: "600px",
          height: "600px",
          background:
            "radial-gradient(circle, rgba(215,24,24,0.15) 0%, transparent 70%)",
          pointerEvents: "none",
        },
        "&::after": {
          content: '""',
          position: "absolute",
          top: 0,
          right: "-10%",
          width: "600px",
          height: "600px",
          background:
            "radial-gradient(circle, rgba(215,24,24,0.15) 0%, transparent 70%)",
          pointerEvents: "none",
        },
      }}
    >
      {/* Main Content */}
      <Container
        maxWidth={false}
        disableGutters
        sx={{
          py: 6,
          position: "relative",
          zIndex: 1,
          px: { xs: 2, sm: 3 }, // FIX: small padding so content never touches viewport edges
          "& *": { minWidth: 0 }, // FIX: allow flex/grid children to shrink without overflowing
          maxWidth: "100%", // FIX: never exceed viewport width
        }}
      >
        {/* Top Row: URL Processes + Live URL Scan */}
        <Box
          sx={{
            display: "grid",
            gap: 4,
            gridTemplateColumns: { xs: "1fr", lg: "1fr 1fr" }, // FIX: responsive to avoid overflow
            mb: 4,
          }}
        >
          {/* URL Processes - with pulse animation */}
          <LiquidCard
            variant="glass"
            className="p-6 animate-pulse-glow"
            style={{ animation: "pulseGlow 4.5s ease-in-out infinite" }}
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">
                URL Processes
              </h2>
            </div>
            <URLProcessTable
              data={urlProcessData}
              loading={urlProcessLoading}
            />
          </LiquidCard>

          {/* Live URL Scan - plain dark card */}
          <LiquidCard variant="glass" className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">
                Live URL Scan
              </h2>
              <TimeRangeTabs value={timeRange} onChange={setTimeRange} />
            </div>
            <div className="flex items-center gap-2 mb-4">
              <span className="inline-flex h-2 w-2 rounded-full bg-[#E50914]" />
              <span className="text-sm text-gray-400">Total URLs</span>
            </div>
            <Box
              sx={{
                position: "relative",
                height: 320,
                width: "100%",
                maxWidth: "100%",
              }}
            >
              <EChartBase option={lineChartOption} />

              {liveUrlScanLoading && (
                <Box
                  sx={{
                    position: "absolute",
                    inset: 0,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    bgcolor: "rgba(0,0,0,0.35)",
                    backdropFilter: "blur(2px)",
                    zIndex: 2,
                    borderRadius: 1,
                  }}
                >
                  <CircularProgress size={28} />
                </Box>
              )}
            </Box>
          </LiquidCard>
        </Box>

        {/* Bottom Row: 3 Cards */}
        <Box
          sx={{
            display: "grid",
            gap: 4,
            gridTemplateColumns: {
              xs: "1fr",
              md: "1fr 1fr",
              lg: "1fr 1fr 1fr",
            },
          }}
        >
          {/* Currently Scanning */}
          <LiquidCard variant="glass" className="p-6">
            <h3 className="text-base font-medium text-gray-400 mb-4">
              Currently Scanning
            </h3>
            <div className="mb-6">
              <span className="text-5xl font-bold text-white">567</span>
              <sup className="text-xl text-gray-400 ml-1">th</sup>
              <span className="text-xl text-gray-400 ml-2">URL</span>
            </div>

            <LinearProgress
              variant="determinate"
              value={50}
              className="mb-2"
              sx={{
                height: 8,
                borderRadius: 1,
                backgroundColor: "#474747",
                "& .MuiLinearProgress-bar": {
                  borderRadius: 1,
                  background:
                    "linear-gradient(90deg, #BF8D8E 0%, #A93237 100%)",
                },
              }}
            />
            <div className="flex justify-between items-center mt-2">
              <p className="text-sm text-gray-400">
                567 out of 1134 Files have been processed.
              </p>
              <span className="text-sm text-gray-400 font-semibold">50%</span>
            </div>
          </LiquidCard>

          {/* URL Tagging */}
          <LiquidCard variant="glass" className="p-6">
            <h3 className="text-base font-medium text-gray-400 mb-4">
              URL Tagging
            </h3>

            <Box
              sx={{
                position: "relative",
                height: 120,
                width: "100%",
                maxWidth: "100%",
              }}
            >
              <EChartBase option={barChartOption} />
              {urlTaggingLoading && (
                <Box
                  sx={{
                    position: "absolute",
                    inset: 0,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    bgcolor: "rgba(0,0,0,0.35)",
                    backdropFilter: "blur(2px)",
                    zIndex: 2,
                    borderRadius: 1,
                  }}
                >
                  <CircularProgress size={24} />
                </Box>
              )}
            </Box>

            <div className="flex justify-between mt-4">
              <div className="flex items-center gap-2">
                <span
                  className="inline-flex h-3 w-3 rounded-sm"
                  style={{
                    background: "linear-gradient(90deg, #EF4444, #F87171)",
                  }}
                />
                <span className="text-sm text-gray-400">Phishing</span>
                <span className="text-sm font-semibold text-white ml-2">
                  {phishing}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span
                  className="inline-flex h-3 w-3 rounded-sm"
                  style={{
                    background: "linear-gradient(90deg, #F59E0B, #FBBF24)",
                  }}
                />
                <span className="text-sm text-gray-400">Parked</span>
                <span className="text-sm font-semibold text-white ml-2">
                  {parked}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span
                  className="inline-flex h-3 w-3 rounded-sm"
                  style={{
                    background: "linear-gradient(90deg, #60A5FA, #93C5FD)",
                  }}
                />
                <span className="text-sm text-gray-400">Suspicious</span>
                <span className="text-sm font-semibold text-white ml-2">
                  {suspicious}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span
                  className="inline-flex h-3 w-3 rounded-sm"
                  style={{
                    background: "linear-gradient(90deg, #4CAF50, #81C784)",
                  }}
                />
                <span className="text-sm text-gray-400">Benign</span>
                <span className="text-sm font-semibold text-white ml-2">
                  {benign}
                </span>
              </div>
            </div>
          </LiquidCard>

          {/* Scan Snippet */}
          <LiquidCard variant="glass" className="p-6">
            <div className="flex items-start justify-between mb-4">
              <h3 className="text-base font-medium text-gray-400">
                Scan Snippet
              </h3>
              <div className="flex gap-2">
                <ShadcnButton variant="ghost" size="icon" className="h-8 w-8">
                  <FileText className="h-4 w-4 text-gray-400" />
                </ShadcnButton>
                <ShadcnButton variant="ghost" size="icon" className="h-8 w-8">
                  <FileDown className="h-4 w-4 text-gray-400" />
                </ShadcnButton>
              </div>
            </div>
            <div className="mb-4 flex items-center">
              {uniqueDomainCountLoading ? (
                <Skeleton width={100} height={45} />
              ) : (
                <span className="text-5xl font-bold text-[#E50914]">
                  {uniqueDomainCountData?.unique_domains}
                </span>
              )}
              <span className="text-xl text-gray-400 ml-2">
                Unique Domains Found
              </span>
            </div>
            <p className="text-sm text-gray-400 mb-6">
              Cross-hosted & categorized
            </p>
            <ShadcnButton
              variant="outline"
              className="w-full border-[#E50914] text-[#E50914] bg-transparent hover:bg-[#E50914]/10"
            >
              View Report
            </ShadcnButton>
          </LiquidCard>
        </Box>
      </Container>

      {/* Pulse Glow Animation */}
      <style>{`
        @keyframes pulseGlow {
          0%, 100% {
            box-shadow: inset 0 0 0 rgba(229, 9, 20, 0), 0 0 24px rgba(229, 9, 20, 0.10);
          }
          50% {
            box-shadow: inset 0 0 24px rgba(229, 9, 20, 0.15), 0 0 32px rgba(229, 9, 20, 0.18);
          }
        }
      `}</style>
    </Box>
  );
};

export default LiveMonitoring;
