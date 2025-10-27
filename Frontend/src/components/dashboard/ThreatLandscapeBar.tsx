import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Box, CircularProgress, Typography } from "@mui/material";

type Hit = { name: string; category?: string };
type Bucket = { count: number; hits: Hit[] };

interface ThreatApiData {
  phishing?: Bucket;
  suspicious?: Bucket;
  benign?: Bucket;
  parked?: Bucket;
}

interface ThreatLandscapeBarProps {
  apiData?: ThreatApiData | null;
  loading?: boolean;
}

/** Order & colors for stacked segments (legend still shows statuses) */
const STATUS_ORDER: Array<keyof ThreatApiData> = [
  "phishing",
  "suspicious",
  "parked",
  "benign",
];

const STATUS_CONFIG: Record<
  keyof ThreatApiData,
  { display: string; color: string }
> = {
  phishing: { display: "Phishing", color: "#DC2626" },
  suspicious: { display: "Suspicious", color: "#EA580C" },
  parked: { display: "Parked", color: "#EAB308" },
  benign: { display: "Benign", color: "#22C55E" },
};

type GroupBreakdown = {
  group: string;
  items: string[];
  count: number;
};

type Segment = {
  statusKey: keyof ThreatApiData;
  width: number; // percentage
  color: string;
  breakdown: GroupBreakdown[];
};

function cleanName(n?: string) {
  const s = (n || "").trim();
  if (!s) return "";
  const lower = s.toLowerCase();

  return s;
}

function groupByCategory(hits: Hit[], maxNamesPerGroup = 6): GroupBreakdown[] {
  const map = new Map<string, Set<string>>();

  for (const h of hits || []) {
    const name = cleanName(h?.name);
    const catRaw = (h?.category || "").trim();
    const group =
      catRaw && catRaw.toLowerCase() !== "unknown" ? catRaw : "Uncategorized";
    if (!name) continue;

    if (!map.has(group)) map.set(group, new Set<string>());
    map.get(group)!.add(name);
  }

  // Convert to array, sort by count desc, then alpha by group
  const arr: GroupBreakdown[] = Array.from(map.entries()).map(
    ([group, set]) => ({
      group,
      items: Array.from(set).slice(0, maxNamesPerGroup),
      count: set.size,
    })
  );

  arr.sort((a, b) => b.count - a.count || a.group.localeCompare(b.group));
  return arr;
}

function buildSegmentsFromApi(apiData?: ThreatApiData | null): {
  segments: Segment[];
  total: number;
} {
  if (!apiData) return { segments: [], total: 0 };

  const totals = STATUS_ORDER.map((k) => apiData[k]?.count ?? 0);
  const total = totals.reduce((a, b) => a + b, 0);
  if (!total) return { segments: [], total: 0 };

  const segments: Segment[] = STATUS_ORDER.map((statusKey) => {
    const bucket = apiData[statusKey] ?? { count: 0, hits: [] };
    if (!bucket.count) return null;

    return {
      statusKey,
      width: (bucket.count / total) * 100,
      color: STATUS_CONFIG[statusKey].color,
      breakdown: groupByCategory(bucket.hits || []),
    } as Segment;
  }).filter(Boolean) as Segment[];

  return { segments, total };
}

export const ThreatLandscapeBar: React.FC<ThreatLandscapeBarProps> = ({
  apiData,
  loading,
}) => {
  const { segments, total } = React.useMemo(
    () => buildSegmentsFromApi(apiData),
    [apiData]
  );

  const legendItems = STATUS_ORDER.map((k) => ({
    label: STATUS_CONFIG[k].display,
    color: STATUS_CONFIG[k].color,
  }));

  return (
    <LiquidCard className="p-6">
      {loading ? (
        <Box display="flex" alignItems="center" justifyContent="center" py={6}>
          <CircularProgress size={24} />
        </Box>
      ) : total === 0 ? (
        <Box
          display="flex"
          alignItems="center"
          justifyContent="space-between"
          gap={4}
        >
          <Box flex={1}>
            <div className="flex h-6 rounded-lg overflow-hidden border border-white/10 bg-white/5" />
            <div className="flex items-center gap-5 mt-4">
              {legendItems.map((item, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full shadow-sm"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-slate-300 text-xs font-medium">
                    {item.label}
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
        <div className="flex items-center justify-between gap-8">
          <div className="flex-1">
            <TooltipProvider>
              <div className="flex h-6 rounded-lg overflow-hidden shadow-lg">
                {segments.map((segment, idx) => (
                  <Tooltip key={idx} delayDuration={0}>
                    <TooltipTrigger asChild>
                      <div
                        className="cursor-pointer transition-all hover:opacity-80 hover:shadow-xl"
                        style={{
                          width: `${segment.width}%`,
                          backgroundColor: segment.color,
                        }}
                        aria-label={`${
                          STATUS_CONFIG[segment.statusKey].display
                        }: ${segment.width.toFixed(1)}%`}
                        title={STATUS_CONFIG[segment.statusKey].display}
                      />
                    </TooltipTrigger>

                    {/* TOOLTIP: show CSEs grouped by their own categories */}
                    <TooltipContent
                      side="top"
                      className="bg-slate-900/95 border-white/20 backdrop-blur-sm"
                    >
                      <div className="space-y-2 min-w-[260px] max-w-[360px]">
                        <p className="font-semibold text-white text-sm">
                          CSE categories • {segment.width.toFixed(1)}%
                        </p>

                        {segment.breakdown.length === 0 ? (
                          <p className="text-xs text-slate-400">
                            No contributors
                          </p>
                        ) : (
                          <div className="space-y-2">
                            {segment.breakdown.slice(0, 6).map((g, i) => {
                              const extra = Math.max(
                                0,
                                g.count - g.items.length
                              );
                              return (
                                <div key={i} className="text-xs">
                                  <p className="text-slate-400 mb-1">
                                    {g.group}
                                  </p>
                                  <ul className="text-slate-300 space-y-0.5">
                                    {g.items.map((n, j) => (
                                      <li key={j}>• {n}</li>
                                    ))}
                                    {extra > 0 && (
                                      <li className="text-slate-500">
                                        … +{extra} more
                                      </li>
                                    )}
                                  </ul>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </TooltipContent>
                  </Tooltip>
                ))}
              </div>
            </TooltipProvider>

            {/* Legend (statuses) */}
            <div className="flex items-center gap-5 mt-4">
              {legendItems.map((item, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <div
                    className="w-2.5 h-2.5 rounded-full shadow-sm"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-slate-300 text-xs font-medium">
                    {item.label}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="text-right flex-shrink-0 max-w-md">
            <p className="text-slate-300 text-base leading-relaxed">
              Represents the potential threat level of a typosquatted domain to
              CSEs or Government bodies.
            </p>
          </div>
        </div>
      )}
    </LiquidCard>
  );
};
