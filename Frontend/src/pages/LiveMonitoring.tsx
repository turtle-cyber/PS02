import * as React from "react";
import { Link, useLocation } from "react-router-dom";
import { AppBar, Toolbar, Container, Button, Box, Menu, MenuItem, LinearProgress, styled } from "@mui/material";
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

type TimeRange = "5m" | "30m" | "1h" | "24h";

const CustomProgress = styled(LinearProgress)({
  height: 8,
  borderRadius: 4,
  backgroundColor: '#474747',
  '& .MuiLinearProgress-bar': {
    borderRadius: 4,
    backgroundColor: 'linear-gradient(90deg, #E50914 0%, #FF1744 50%, #FF5252 100%)',
  },
});

const LiveMonitoring: React.FC = () => {
  const location = useLocation();
  const [timeRange, setTimeRange] = React.useState<TimeRange>("5m");
  const [reportsAnchorEl, setReportsAnchorEl] = React.useState<null | HTMLElement>(null);
  const reportsOpen = Boolean(reportsAnchorEl);

  const navItems = [
    { label: "Home", path: "/" },
    { label: "URL Detection", path: "/url-detection" },
    { label: "Live Monitoring", path: "/live-monitoring" },
    { label: "Dashboard", path: "/dashboard" },
  ];

  // Line chart option
  const lineChartOption: EChartsOption = {
    grid: {
      top: 40,
      right: 40,
      bottom: 40,
      left: 60,
      containLabel: false,
    },
    xAxis: {
      type: "category",
      data: ["3:00", "3:05", "3:10", "3:15", "3:20", "3:25", "3:30", "3:35"],
      axisLine: { lineStyle: { color: "#333" } },
      axisLabel: { color: "#666", fontSize: 11 },
      splitLine: { show: false },
    },
    yAxis: {
      type: "value",
      axisLine: { show: false },
      axisLabel: { color: "#666", fontSize: 11 },
      splitLine: { lineStyle: { color: "#222", type: "dashed" } },
    },
    series: [
      {
        name: "Total URLs",
        type: "line",
        smooth: true,
        data: [11000, 10500, 10200, 9800, 9400, 8800, 8200, 7600],
        lineStyle: { color: "#E50914", width: 2 },
        itemStyle: { color: "#E50914" },
        showSymbol: false,
        areaStyle: undefined,
      },
    ],
    tooltip: {
      trigger: "axis",
      backgroundColor: "rgba(0,0,0,0.8)",
      borderColor: "#E50914",
      textStyle: { color: "#fff" },
    },
  };

  // Stacked bar chart option
 const barChartOption: EChartsOption = {
  grid: {
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    containLabel: false,
  },
  xAxis: {
    type: "value",
    show: false,
    max: 567,
  },
  yAxis: {
    type: "category",
    show: false,
    data: [""],
  },
  series: [
    {
      name: "Phishing",
      type: "bar",
      stack: "total",
      data: [324],
      itemStyle: { 
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 1,
          y2: 0,
          colorStops: [
            { offset: 0, color: '#A93237' },
            { offset: 1, color: '#BF8D8E' }
          ],
        },
        borderRadius: [8, 0, 0, 8],
      },
      barWidth: 24,
      label: {
        show: true,
        position: 'top',
        color: '#fff',
        fontSize: 16,
        fontWeight: 'normal',
        offset: [0, -10],
      },
    },
    {
      name: "Suspicious",
      type: "bar",
      stack: "total",
      data: [243],
      itemStyle: { 
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 1,
          y2: 0,
          colorStops: [
            { offset: 0, color: '#95BCE2' },
            { offset: 1, color: '#60A5FA' }
          ],
        },
        borderRadius: [0, 8, 8, 0],
      },
      barWidth: 24,
      label: {
        show: true,
        position: 'top',
        color: '#fff',
        fontSize: 16,
        fontWeight: 'normal',
        offset: [0, -10],
      },
    },
  ],
  tooltip: {
    show: false,
  },
};
  return (
    <Box
      sx={{
        minHeight: "100vh",
        position: "relative",
        overflowX: "hidden",            // FIX: contain pseudo-elements + any wide child
        boxSizing: "border-box",        // FIX: guard sizing math
        "&::before": {
          content: '""',
          position: "absolute",
          top: 0,
          left: "-10%",
          width: "600px",
          height: "600px",
          background: "radial-gradient(circle, rgba(215,24,24,0.15) 0%, transparent 70%)",
          pointerEvents: "none",
        },
        "&::after": {
          content: '""',
          position: "absolute",
          top: 0,
          right: "-10%",
          width: "600px",
          height: "600px",
          background: "radial-gradient(circle, rgba(215,24,24,0.15) 0%, transparent 70%)",
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
          px: { xs: 2, sm: 3 },        // FIX: small padding so content never touches viewport edges
          "& *": { minWidth: 0 },       // FIX: allow flex/grid children to shrink without overflowing
          maxWidth: "100%",             // FIX: never exceed viewport width
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
              <h2 className="text-xl font-semibold text-white">URL Processes</h2>
              <LiveDot />
            </div>
            <URLProcessTable />
          </LiquidCard>

          {/* Live URL Scan - plain dark card */}
          <LiquidCard variant="glass" className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">Live URL Scan</h2>
              <TimeRangeTabs value={timeRange} onChange={setTimeRange} />
            </div>
            <div className="flex items-center gap-2 mb-4">
              <span className="inline-flex h-2 w-2 rounded-full bg-[#E50914]" />
              <span className="text-sm text-gray-400">Total URLs</span>
            </div>
            <div style={{ height: 320, width: "100%", maxWidth: "100%" }}>{/* FIX */}
              <EChartBase option={lineChartOption} />
            </div>
          </LiquidCard>
        </Box>

        {/* Bottom Row: 3 Cards */}
        <Box
          sx={{
            display: "grid",
            gap: 4,
            gridTemplateColumns: { xs: "1fr", md: "1fr 1fr", lg: "1fr 1fr 1fr" }, // FIX: responsive
          }}
        >
          {/* Currently Scanning */}
          <LiquidCard variant="glass" className="p-6">
  <h3 className="text-base font-medium text-gray-400 mb-4">Currently Scanning</h3>
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
    backgroundColor: '#474747',
    '& .MuiLinearProgress-bar': {
      borderRadius: 1,
      background: 'linear-gradient(90deg, #BF8D8E 0%, #A93237 100%)',
    },
  }}
/>
  <div className="flex justify-between items-center mt-2">
    <p className="text-sm text-gray-400">567 out of 1134 Files have been processed.</p>
    <span className="text-sm text-gray-400 font-semibold">50%</span>
  </div>
</LiquidCard>

          {/* URL Tagging */}
          <LiquidCard variant="glass" className="p-6">
            <h3 className="text-base font-medium text-gray-400 mb-4">URL Tagging</h3>
            <div style={{ height: 120, width: "100%", maxWidth: "100%" }}>{/* FIX */}
              <EChartBase option={barChartOption} />
            </div>
            <div className="flex justify-between mt-4">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-3 w-3 rounded-sm bg-[#E50914]" />
                <span className="text-sm text-gray-400">Phishing</span>
                <span className="text-sm font-semibold text-white ml-2">324</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-flex h-3 w-3 rounded-sm bg-[#3B82F6]" />
                <span className="text-sm text-gray-400">Suspicious</span>
                <span className="text-sm font-semibold text-white ml-2">243</span>
              </div>
            </div>
          </LiquidCard>

          {/* Scan Snippet */}
          <LiquidCard variant="glass" className="p-6">
            <div className="flex items-start justify-between mb-4">
              <h3 className="text-base font-medium text-gray-400">Scan Snippet</h3>
              <div className="flex gap-2">
                <ShadcnButton variant="ghost" size="icon" className="h-8 w-8">
                  <FileText className="h-4 w-4 text-gray-400" />
                </ShadcnButton>
                <ShadcnButton variant="ghost" size="icon" className="h-8 w-8">
                  <FileDown className="h-4 w-4 text-gray-400" />
                </ShadcnButton>
              </div>
            </div>
            <div className="mb-4">
              <span className="text-5xl font-bold text-[#E50914]">68</span>
              <span className="text-xl text-gray-400 ml-2">Unique Domains Found</span>
            </div>
            <p className="text-sm text-gray-400 mb-6">Cross-hosted & categorized</p>
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
