import * as React from "react";
import { CircularProgress } from "@mui/material";
import { LiquidCard } from "@/components/ui/liquid-card";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from "react-simple-maps";
import { scaleSqrt } from "d3-scale";

/** TopoJSON for world map (lightweight). You can self-host later if needed. */
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

/** ISO2 → [lng, lat] centroids (add more as your API returns new countries) */
const ISO2_TO_COORD: Record<string, [number, number]> = {
  US: [-98.35, 39.5],
  DE: [10.45, 51.17],
  AU: [134.49, -25.73],
  NL: [5.29, 52.13],
  IN: [78.96, 22.59],
  VG: [-64.62, 18.49],
  KR: [127.98, 36.5],
  GB: [-1.47, 52.36],
  HK: [114.17, 22.32],
  CA: [-106.35, 56.13],
  CH: [8.23, 46.82],
  IE: [-8.24, 53.41],
  SG: [103.82, 1.35],
  LT: [23.88, 55.17],
  RU: [105.32, 61.52],
  ES: [-3.75, 40.46],
  FR: [2.21, 46.23],
  DK: [9.5, 56.26],
};

const ISO2_TO_NAME: Record<string, string> = {
  US: "United States",
  DE: "Germany",
  AU: "Australia",
  NL: "Netherlands",
  IN: "India",
  VG: "British Virgin Islands",
  KR: "South Korea",
  GB: "United Kingdom",
  HK: "Hong Kong",
  CA: "Canada",
  CH: "Switzerland",
  IE: "Ireland",
  SG: "Singapore",
  LT: "Lithuania",
  RU: "Russia",
  ES: "Spain",
  FR: "France",
  DK: "Denmark",
};

type CountryPoint = { country: string; count: number; percentage?: number };

interface OriginCountriesMapProps {
  data?: CountryPoint[]; // API: [{ country: "US", count: 217, percentage: 59.94 }, ...]
  loading?: boolean;
  topN?: number; // right-side list count (default 5)
}

export const OriginCountriesMap: React.FC<OriginCountriesMapProps> = ({
  data,
  loading = false,
  topN = 5,
}) => {
  const hasData = Array.isArray(data) && data.length > 0;

  // Filter to countries we have coordinates for, and map to display shape
  const points = React.useMemo(() => {
    if (!hasData) return [];
    return data!
      .filter((d) => ISO2_TO_COORD[d.country] && d.count > 0)
      .map((d) => {
        const [lng, lat] = ISO2_TO_COORD[d.country];
        return {
          code: d.country,
          name: ISO2_TO_NAME[d.country] || d.country,
          coords: [lng, lat] as [number, number],
          count: d.count,
          percentage: d.percentage,
        };
      });
  }, [data, hasData]);

  // Radius scale (sqrt so big counts don't dominate)
  const radius = React.useMemo(() => {
    const max = points.reduce((m, p) => Math.max(m, p.count), 0);
    const min = points.reduce((m, p) => Math.min(m, p.count), Infinity);
    const domainMin = isFinite(min) ? Math.min(min, 1) : 0;
    const domainMax = Math.max(max, 1);
    return scaleSqrt<number, number>()
      .domain([domainMin, domainMax])
      .range([6, 26]);
  }, [points]);

  // Top-N list for right side
  const top = React.useMemo(() => {
    if (!hasData) return [];
    return [...data!].sort((a, b) => b.count - a.count).slice(0, topN);
  }, [data, hasData, topN]);

  const maxCount = top[0]?.count ?? 1;

  const formatK = (n: number) =>
    n >= 1000 ? `${Math.round(n / 100) / 10}K` : `${n}`;

  return (
    <LiquidCard variant="glass" className="p-4">
      <div className="gap-6 h-[450px] overflow-auto">
        <div className="w-full h-[300px] flex items-center justify-center">
          {loading ? (
            <CircularProgress size={28} />
          ) : !hasData ? (
            <div className="text-slate-400 text-sm">No Data Found</div>
          ) : (
            <ComposableMap
              projectionConfig={{ scale: 200 }}
              style={{ width: "100%", height: "100%" }}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      style={{
                        default: {
                          fill: "rgba(255,255,255,0.03)",
                          stroke: "rgba(255,255,255,0.08)",
                          outline: "none",
                        },
                        hover: {
                          fill: "rgba(229,9,20,0.12)",
                          stroke: "rgba(255,255,255,0.12)",
                          outline: "none",
                        },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Bubbles */}
              {points.map((p) => (
                <Marker key={p.code} coordinates={p.coords}>
                  {/* Outer translucent circle */}
                  <circle
                    r={radius(p.count)}
                    fill="rgba(229,9,20,0.28)"
                    stroke="rgba(229,9,20,0.55)"
                    strokeWidth={1}
                    style={{
                      filter: "drop-shadow(0 0 8px rgba(229,9,20,0.35))",
                    }}
                  />
                  {/* Small core */}
                  <circle r={3} fill="#E50914" />
                  {/* Optional simple tooltip on title */}
                  <title>
                    {p.name}
                    {"\n"}
                    Count: {p.count}
                    {typeof p.percentage === "number"
                      ? ` (${p.percentage.toFixed(2)}%)`
                      : ""}
                  </title>
                </Marker>
              ))}
            </ComposableMap>
          )}
        </div>

        {/* Right-side Top-N bars */}
        <div className="mt-5 grid grid-cols-2 gap-4">
          {(hasData ? top : []).map((row, idx) => (
            <div key={`${row.country}-${idx}`}>
              <div className="flex justify-between items-center mb-1">
                <span className="text-slate-300 text-sm">
                  {ISO2_TO_NAME[row.country] || row.country}{" "}
                  {formatK(row.count)}
                </span>
                {typeof row.percentage === "number" && (
                  <span className="text-white text-sm font-semibold">
                    {row.percentage.toFixed(0)}%
                  </span>
                )}
              </div>
              <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#E50914] rounded-full transition-all"
                  style={{ width: `${(row.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          ))}
          {!loading && !hasData && (
            <div className="text-slate-400 text-sm col-span-2">
              No Data Found
            </div>
          )}
        </div>
      </div>
    </LiquidCard>
  );
};
