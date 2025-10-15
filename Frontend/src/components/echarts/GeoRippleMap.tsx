import * as React from "react";
import { EChartBase, type EChartBaseRef } from "./echart-base";
import type { EChartsOption } from "echarts";
import * as echarts from "echarts/core";
import { MapChart, EffectScatterChart } from "echarts/charts";
import { GeoComponent } from "echarts/components";

// Register additional charts for map
echarts.use([MapChart, EffectScatterChart, GeoComponent]);

// Inline simplified world GeoJSON (only major countries for performance)
const worldGeoJSON = {
  type: "FeatureCollection" as const,
  features: [
    // Simplified world map - in production, use full geoJSON
    { type: "Feature" as const, id: "USA", properties: { name: "United States" }, geometry: { type: "Polygon" as const, coordinates: [[[-125, 50], [-125, 25], [-65, 25], [-65, 50], [-125, 50]]] }},
    { type: "Feature" as const, id: "IND", properties: { name: "India" }, geometry: { type: "Polygon" as const, coordinates: [[[68, 35], [68, 8], [97, 8], [97, 35], [68, 35]]] }},
    { type: "Feature" as const, id: "CHN", properties: { name: "China" }, geometry: { type: "Polygon" as const, coordinates: [[[75, 53], [75, 18], [135, 18], [135, 53], [75, 53]]] }},
    { type: "Feature" as const, id: "BRA", properties: { name: "Brazil" }, geometry: { type: "Polygon" as const, coordinates: [[[-75, 5], [-75, -35], [-35, -35], [-35, 5], [-75, 5]]] }},
    { type: "Feature" as const, id: "RUS", properties: { name: "Russia" }, geometry: { type: "Polygon" as const, coordinates: [[[20, 80], [20, 40], [180, 40], [180, 80], [20, 80]]] }},
    { type: "Feature" as const, id: "GBR", properties: { name: "United Kingdom" }, geometry: { type: "Polygon" as const, coordinates: [[[-8, 60], [-8, 50], [2, 50], [2, 60], [-8, 60]]] }},
    { type: "Feature" as const, id: "DEU", properties: { name: "Germany" }, geometry: { type: "Polygon" as const, coordinates: [[[5, 55], [5, 47], [15, 47], [15, 55], [5, 55]]] }},
    { type: "Feature" as const, id: "AUS", properties: { name: "Australia" }, geometry: { type: "Polygon" as const, coordinates: [[[113, -10], [113, -44], [154, -44], [154, -10], [113, -10]]] }},
  ]
};

interface GeoRippleMapProps {
  data: Array<{ name: string; value: [number, number, number] }>;
  height?: string;
}

// Register map once when module loads (before any component renders)
let mapRegistered = false;
if (!mapRegistered) {
  echarts.registerMap("world", worldGeoJSON as any);
  mapRegistered = true;
}

export const GeoRippleMap: React.FC<GeoRippleMapProps> = ({ data, height = "400px" }) => {
  const chartRef = React.useRef<EChartBaseRef>(null);
  const [isReady, setIsReady] = React.useState(false);

  React.useEffect(() => {
    // Ensure map is registered (redundant check but safe)
    if (!echarts.getMap("world")) {
      echarts.registerMap("world", worldGeoJSON as any);
    }
    setIsReady(true);
  }, []);

  const option: EChartsOption = {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(0, 0, 0, 0.8)",
      borderColor: "rgba(229, 9, 20, 0.3)",
      textStyle: { color: "#fff" },
      formatter: (params: any) => {
        if (params.seriesType === "effectScatter") {
          return `${params.data.name}<br/>Count: ${params.data.value[2]}`;
        }
        return params.name;
      }
    },
    geo: {
      map: "world",
      roam: false,
      itemStyle: {
        areaColor: "rgba(255, 255, 255, 0.03)",
        borderColor: "rgba(255, 255, 255, 0.08)",
        borderWidth: 0.5
      },
      emphasis: {
        itemStyle: {
          areaColor: "rgba(229, 9, 20, 0.12)"
        }
      },
      label: {
        show: false
      }
    },
    series: [
      {
        type: "map",
        map: "world",
        roam: false,
        itemStyle: {
          areaColor: "rgba(255, 255, 255, 0.03)",
          borderColor: "rgba(255, 255, 255, 0.08)"
        },
        emphasis: {
          itemStyle: {
            areaColor: "rgba(229, 9, 20, 0.12)"
          }
        },
        label: {
          show: false
        }
      },
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        data: data,
        symbolSize: (val: number[]) => {
          return Math.max(6, Math.sqrt(val[2]) * 3);
        },
        showEffectOn: "render",
        rippleEffect: {
          period: 4,
          scale: 3,
          brushType: "stroke"
        },
        label: {
          show: false
        },
        itemStyle: {
          color: "#E50914",
          shadowBlur: 10,
          shadowColor: "rgba(229, 9, 20, 0.5)"
        },
        zlevel: 1
      }
    ]
  };

  // Only render chart after map is registered
  if (!isReady) {
    return (
      <div style={{ height }} className="flex items-center justify-center">
        <span className="text-slate-400 text-sm">Loading map...</span>
      </div>
    );
  }

  return (
    <div style={{ height }}>
      <EChartBase ref={chartRef} option={option} />
    </div>
  );
};
