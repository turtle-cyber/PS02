import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";

interface DomainsCardProps {
  domainsSummary: {
    lookAlike: number;
    mxRecords: number;
    activeDetected: number;
    parked: number;
  };
}

export const DomainsCard: React.FC<DomainsCardProps> = ({ domainsSummary }) => {
  return (
    <LiquidCard variant="glass" className="p-6 min-h-[360px]">
      <div className="grid grid-cols-2 gap-20">
        <div>
          <p className="text-slate-400 text-sm mb-1">Look-Alike Domains</p>
          <p className="text-white text-2xl font-semibold">{domainsSummary.lookAlike.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-1">MX Records</p>
          <p className="text-white text-2xl font-semibold">{domainsSummary.mxRecords.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-1">Total Active Domains Detected</p>
          <p className="text-white text-2xl font-semibold">{domainsSummary.activeDetected.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-1">Total Parked Domains</p>
          <p className="text-white text-2xl font-semibold">{domainsSummary.parked.toLocaleString()}</p>
        </div>
      </div>
    </LiquidCard>
  );
};
