import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface ThreatSegment {
  category: string;
  width: number;
  color: string;
  cseContributors: string[];
}

interface ThreatLandscapeBarProps {
  segments: ThreatSegment[];
}

const riskLevels = [
  { label: "Critical", color: "#DC2626" },
  { label: "High", color: "#EA580C" },
  { label: "Moderate", color: "#EAB308" },
  { label: "Elevated", color: "#22C55E" },
  { label: "Low", color: "#3B82F6" },
];

export const ThreatLandscapeBar: React.FC<ThreatLandscapeBarProps> = ({ segments }) => {
  return (
    <LiquidCard className="p-6">
      <div className="flex items-center justify-between gap-8">
  <div className="flex-1">
    <h3 className="text-white text-lg font-semibold mb-4">Threat Landscape</h3>
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
              />
            </TooltipTrigger>
            <TooltipContent side="top" className="bg-slate-900/95 border-white/20 backdrop-blur-sm">
              <div className="space-y-2 min-w-[200px]">
                <p className="font-semibold text-white text-sm">{segment.category}</p>
                <div>
                  <p className="text-xs text-slate-400 mb-1">Contributing CSEs:</p>
                  <ul className="text-xs text-slate-300 space-y-1">
                    {segment.cseContributors.map((cse, i) => (
                      <li key={i}>• {cse}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </TooltipContent>
          </Tooltip>
        ))}
      </div>
    </TooltipProvider>
    
    <div className="flex items-center gap-5 mt-4">
      {riskLevels.map((level, idx) => (
        <div key={idx} className="flex items-center gap-2">
          <div 
            className="w-2.5 h-2.5 rounded-full shadow-sm" 
            style={{ backgroundColor: level.color }}
          />
          <span className="text-slate-300 text-xs font-medium">{level.label}</span>
        </div>
      ))}
    </div>
  </div>
  
  <div className="text-right flex-shrink-0 max-w-md">
    <p className="text-slate-400 text-sm font-medium mb-2">Breakdown</p>
    <p className="text-slate-300 text-base leading-relaxed">
      Represents the potential threat level of a typosquatted domain to CSEs or Government bodies.
    </p>
  </div>
</div>
    </LiquidCard>
  );
};