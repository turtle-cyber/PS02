import * as React from "react";
import { cn } from "@/lib/utils";

type TimeRange = "5m" | "30m" | "1h" | "24h";

interface TimeRangeTabsProps {
  value: TimeRange;
  onChange: (value: TimeRange) => void;
}

const tabs: { label: string; value: TimeRange }[] = [
  { label: "5 mins", value: "5m" },
  { label: "30 mins", value: "30m" },
  { label: "1 hour", value: "1h" },
  { label: "24 hours", value: "24h" },
];

export const TimeRangeTabs: React.FC<TimeRangeTabsProps> = ({
  value,
  onChange,
}) => {
  return (
    <div className="inline-flex items-center rounded-lg border border-white/10 bg-black/20 p-1">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          onClick={() => onChange(tab.value)}
          className={cn(
            "px-4 py-1.5 text-sm font-medium rounded-md transition-all",
            value === tab.value
              ? "bg-white/10 text-white"
              : "text-gray-400 hover:text-white hover:bg-white/5"
          )}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
};
