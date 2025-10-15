import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";

interface OverviewCardsProps {
  totals: {
    scans: number;
    confidence: number;
    cses: number;
    phishingUrls: number;
  };
}

export const OverviewCards: React.FC<OverviewCardsProps> = ({ totals }) => {
  return (
    <div className="flex flex-col gap-9 w-full">
      <div className="flex gap-6">
        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">Total Scans</p>
            <p className="text-white text-3xl font-semibold">
              {totals.scans.toLocaleString()}
            </p>
          </div>
        </LiquidCard>
        
        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">Confidence Score</p>
            <p className="text-white text-3xl font-semibold">
              {totals.confidence}%
            </p>
          </div>
        </LiquidCard>
      </div>

      <div className="flex gap-6">
        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">CSEs</p>
            <p className="text-white text-3xl font-semibold">{totals.cses}</p>
          </div>
        </LiquidCard>
        
        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">Phishing URLs</p>
            <p className="text-white text-3xl font-semibold">
              {totals.phishingUrls.toLocaleString()}
            </p>
          </div>
        </LiquidCard>
      </div>
    </div>
  );
};