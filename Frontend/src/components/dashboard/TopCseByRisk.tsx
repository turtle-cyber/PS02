import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { EChartBase } from "@/components/echarts/echart-base";
import type { EChartsOption } from "echarts";

interface CseRiskData {
  sector: string;
  critical: number;
  high: number;
  moderate: number;
  elevated: number;
  low: number;
}

interface TopCseByRiskProps {
  data: CseRiskData[];
}

export const TopCseByRisk: React.FC<TopCseByRiskProps> = ({ data }) => {
  const option: EChartsOption = {
    backgroundColor: 'transparent',
    grid: {
      left: '5%',
      right: '25%',
      top: '15%',
      bottom: '5%',
      containLabel: false,
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'shadow',
      },
      backgroundColor: 'rgba(0, 0, 0, 0.9)',
      borderColor: 'rgba(255, 255, 255, 0.1)',
      textStyle: {
        color: '#ffffff',
      },
    },
    legend: {
      data: ['Critical', 'High', 'Moderate', 'Elevated', 'Low'],
      top: 10,
      left: 680,
      textStyle: {
        color: '#a1a1aa',
        fontSize: 11,
      },
      itemWidth: 12,
      itemHeight: 12,
    },
    xAxis: {
      type: 'value',
      max: 100,
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        show: false,
      },
      splitLine: {
        lineStyle: {
          color: 'rgba(255, 255, 255, 0.05)',
        },
      },
    },
    yAxis: {
      type: 'category',
      data: data.map(d => d.sector),
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        color: '#a1a1aa',
        fontSize: 12,
      },
    },
    series: [
      {
        name: 'Critical',
        type: 'bar',
        stack: 'total',
        barWidth: '60%',
        itemStyle: {
          color: '#E50914',
        },
        barMaxWidth: 24,
        data: data.map(d => d.critical),
      },
      {
        name: 'High',
        type: 'bar',
        stack: 'total',
        itemStyle: {
          color: '#FF6A00',
        },
        data: data.map(d => d.high),
      },
      {
        name: 'Moderate',
        type: 'bar',
        stack: 'total',
        itemStyle: {
          color: '#FFCC33',
        },
        data: data.map(d => d.moderate),
      },
      {
        name: 'Elevated',
        type: 'bar',
        stack: 'total',
        itemStyle: {
          color: '#2FAE6B',
        },
        data: data.map(d => d.elevated),
      },
      {
        name: 'Low',
        type: 'bar',
        stack: 'total',
        itemStyle: {
          color: '#2D9CDB',
        },
        data: data.map(d => d.low),
      },
    ],
  };

  return (
    <LiquidCard variant="glass" className="p-6 min-h-[400px]">
      <div className="h-[400px]">
        <EChartBase option={option} />
      </div>
    </LiquidCard>
  );
};
