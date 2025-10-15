import * as React from "react";
import * as echarts from "echarts/core";
import { LiquidCard } from "@/components/ui/liquid-card";
import { EChartBase } from "@/components/echarts/echart-base";
import type { EChartsOption } from "echarts";

// Simplified world geoJSON (inline)
const worldGeoJSON = {
  type: "FeatureCollection" as const,
  features: [
    // Minimal world map - in production, use complete geoJSON
    { type: "Feature" as const, properties: { name: "India" }, geometry: { type: "Polygon" as const, coordinates: [[[68, 8], [97, 8], [97, 35], [68, 35], [68, 8]]] } },
    { type: "Feature" as const, properties: { name: "United States" }, geometry: { type: "Polygon" as const, coordinates: [[[-125, 25], [-66, 25], [-66, 49], [-125, 49], [-125, 25]]] } },
    { type: "Feature" as const, properties: { name: "China" }, geometry: { type: "Polygon" as const, coordinates: [[[73, 18], [135, 18], [135, 53], [73, 53], [73, 18]]] } },
    { type: "Feature" as const, properties: { name: "Russia" }, geometry: { type: "Polygon" as const, coordinates: [[[19, 41], [180, 41], [180, 81], [19, 81], [19, 41]]] } },
    { type: "Feature" as const, properties: { name: "Brazil" }, geometry: { type: "Polygon" as const, coordinates: [[[-74, -34], [-34, -34], [-34, 5], [-74, 5], [-74, -34]]] } },
    { type: "Feature" as const, properties: { name: "United Kingdom" }, geometry: { type: "Polygon" as const, coordinates: [[[-8, 50], [2, 50], [2, 61], [-8, 61], [-8, 50]]] } },
  ],
};

interface OriginCountriesMapProps {
  data: {
    heat: { name: string; value: number }[];
    cities: { name: string; lat: number; lng: number; value: number }[];
  };
}

export const OriginCountriesMap: React.FC<OriginCountriesMapProps> = ({ data }) => {
  React.useEffect(() => {
    echarts.registerMap('world', worldGeoJSON);
  }, []);

  const option: EChartsOption = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(0, 0, 0, 0.9)',
      borderColor: 'rgba(255, 255, 255, 0.1)',
      textStyle: {
        color: '#ffffff',
      },
    },
    geo: {
      map: 'world',
      roam: false,
      itemStyle: {
        areaColor: 'rgba(255, 255, 255, 0.03)',
        borderColor: 'rgba(255, 255, 255, 0.08)',
      },
      emphasis: {
        itemStyle: {
          areaColor: 'rgba(229, 9, 20, 0.12)',
        },
      },
      silent: false,
    },
    visualMap: {
      min: 0,
      max: 1500,
      calculable: false,
      show: false,
      inRange: {
        color: ['rgba(229, 9, 20, 0.2)', 'rgba(229, 9, 20, 0.8)'],
      },
    },
    series: [
      {
        name: 'Country Heat',
        type: 'map',
        map: 'world',
        roam: false,
        itemStyle: {
          borderColor: 'rgba(255, 255, 255, 0.08)',
        },
        emphasis: {
          itemStyle: {
            areaColor: 'rgba(229, 9, 20, 0.2)',
          },
        },
        data: data.heat,
      },
      {
        name: 'Cities',
        type: 'effectScatter',
        coordinateSystem: 'geo',
        showEffectOn: 'render',
        rippleEffect: {
          period: 4,
          scale: 3,
          brushType: 'stroke',
        },
        itemStyle: {
          color: '#E50914',
          shadowBlur: 10,
          shadowColor: 'rgba(229, 9, 20, 0.5)',
        },
        emphasis: {
          scale: true,
        },
        symbolSize: (val: any) => Math.max(6, Math.sqrt(val[2]) * 2),
        data: data.cities.map(city => ({
          name: city.name,
          value: [city.lng, city.lat, city.value],
        })),
      },
    ],
  };

return (
  <LiquidCard variant="glass" className="p-6 h-[500">
    <div className="gap-6 h-[310px]">
      <div className="">
        <EChartBase option={option} />
      </div>
      <div className="mt-10 grid grid-cols-2 gap-4">
        {data.cities.slice(0, 5).map((city, idx) => (
          <div key={idx}>
            <div className="flex justify-between items-center mb-1">
              <span className="text-slate-300 text-sm">{city.name}</span>
              <span className="text-white text-sm font-semibold">{city.value}</span>
            </div>
            <div className="h-1 bg-white/5 rounded-full overflow-hidden">
              <div
                className="h-full bg-[#E50914] rounded-full transition-all"
                style={{ width: `${(city.value / data.cities[0].value) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  </LiquidCard>
);
};
