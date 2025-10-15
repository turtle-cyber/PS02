import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { EChartBase } from "@/components/echarts/echart-base";
import type { EChartsOption } from "echarts";

interface UrlWatchAreaProps {
  series: {
    dates: string[];
    phishing: number[];
    suspicious: number[];
    clean: number[];
  };
}

export const UrlWatchArea: React.FC<UrlWatchAreaProps> = ({ series }) => {
  const option: EChartsOption = {
    backgroundColor: 'transparent',
    grid: {
      left: '3%',
      right: '4%',
      bottom: '10%',
      top: '15%',
      containLabel: true,
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'cross',
        label: {
          backgroundColor: '#1a1a1a',
        },
      },
      backgroundColor: 'rgba(0, 0, 0, 0.9)',
      borderColor: 'rgba(255, 255, 255, 0.1)',
      textStyle: {
        color: '#ffffff',
      },
    },
    legend: {
      data: ['Phishing', 'Suspicious', 'Clean'],
      top: 10,
      right: 10,
      textStyle: {
        color: '#a1a1aa',
      },
      itemWidth: 12,
      itemHeight: 12,
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: series.dates,
      axisLine: {
        lineStyle: {
          color: 'rgba(255, 255, 255, 0.1)',
        },
      },
      axisLabel: {
        color: '#a1a1aa',
        fontSize: 11,
        formatter: (value: string) => {
          const date = new Date(value);
          return `${date.getMonth() + 1}/${date.getDate()}`;
        },
      },
      splitLine: {
        show: false,
      },
    },
    yAxis: {
      type: 'value',
      axisLine: {
        show: false,
      },
      axisLabel: {
        color: '#a1a1aa',
        fontSize: 11,
      },
      splitLine: {
        lineStyle: {
          color: 'rgba(255, 255, 255, 0.05)',
        },
      },
    },
    series: [
      {
        name: 'Phishing',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 0,
        },
        showSymbol: false,
        areaStyle: {
          opacity: 0.8,
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              {
                offset: 0,
                color: 'rgba(229, 9, 20, 0.6)',
              },
              {
                offset: 1,
                color: 'rgba(229, 9, 20, 0.1)',
              },
            ],
          },
        },
        emphasis: {
          focus: 'series',
        },
        data: series.phishing,
      },
      {
        name: 'Suspicious',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 0,
        },
        showSymbol: false,
        areaStyle: {
          opacity: 0.8,
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              {
                offset: 0,
                color: 'rgba(255, 176, 32, 0.6)',
              },
              {
                offset: 1,
                color: 'rgba(255, 176, 32, 0.1)',
              },
            ],
          },
        },
        emphasis: {
          focus: 'series',
        },
        data: series.suspicious,
      },
      {
        name: 'Clean',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 0,
        },
        showSymbol: false,
        areaStyle: {
          opacity: 0.8,
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              {
                offset: 0,
                color: 'rgba(31, 191, 117, 0.6)',
              },
              {
                offset: 1,
                color: 'rgba(31, 191, 117, 0.1)',
              },
            ],
          },
        },
        emphasis: {
          focus: 'series',
        },
        data: series.clean,
      },
    ],
  };

  return (
    <LiquidCard variant="glass" className="p-2 min-h-[280px]">
      {/* <h3 className="text-white text-lg font-semibold mb-4">URL Watch</h3> */}
      <div className="h-[265px]">
        <EChartBase option={option} />
      </div>
    </LiquidCard>
  );
};
