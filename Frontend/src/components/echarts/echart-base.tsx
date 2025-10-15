import * as React from "react";
import * as echarts from "echarts/core";
import { LineChart, BarChart } from "echarts/charts";
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsOption } from "echarts";

echarts.use([
  LineChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  CanvasRenderer,
]);

interface EChartBaseProps {
  option: EChartsOption;
  className?: string;
  style?: React.CSSProperties;
}

export interface EChartBaseRef {
  getEchartsInstance: () => echarts.ECharts | null;
}

export const EChartBase = React.forwardRef<EChartBaseRef, EChartBaseProps>(
  ({ option, className, style }, ref) => {
    const chartRef = React.useRef<HTMLDivElement>(null);
    const chartInstanceRef = React.useRef<echarts.ECharts | null>(null);

    React.useImperativeHandle(ref, () => ({
      getEchartsInstance: () => chartInstanceRef.current,
    }));

  React.useEffect(() => {
    if (!chartRef.current) return;

    // Initialize chart
    chartInstanceRef.current = echarts.init(chartRef.current, null, {
      renderer: "canvas",
    });

    // Set option
    chartInstanceRef.current.setOption(option, { notMerge: true });

    // Setup ResizeObserver
    const resizeObserver = new ResizeObserver(() => {
      chartInstanceRef.current?.resize();
    });

    resizeObserver.observe(chartRef.current);

    // Cleanup
    return () => {
      resizeObserver.disconnect();
      chartInstanceRef.current?.dispose();
      chartInstanceRef.current = null;
    };
  }, []);

  // Update option when it changes
  React.useEffect(() => {
    if (chartInstanceRef.current) {
      chartInstanceRef.current.setOption(option, { notMerge: true });
    }
  }, [option]);

    return (
      <div
        ref={chartRef}
        className={className}
        style={{ width: "100%", height: "100%", ...style }}
      />
    );
  }
);

EChartBase.displayName = "EChartBase";
