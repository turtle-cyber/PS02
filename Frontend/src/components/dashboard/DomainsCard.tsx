import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { Skeleton } from "@mui/material";

export const DomainsCard: React.FC<any> = ({ data, loading }) => {
  return (
    <LiquidCard variant="glass" className="p-6 min-h-[360px]">
      <div className="grid grid-cols-2 gap-20">
        <div>
          <p className="text-slate-400 text-sm mb-1">Look-Alike Domains</p>
          <p className="text-white text-2xl font-semibold">
            {loading ? (
              <Skeleton sx={{ width: 100, borderRadius: 2 }} />
            ) : data ? (
              data.lookalike_domains
            ) : (
              "N/A"
            )}
          </p>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-1">MX Records</p>
          <p className="text-white text-2xl font-semibold">
            {loading ? (
              <Skeleton sx={{ width: 100, borderRadius: 2 }} />
            ) : data ? (
              data.domains_with_mx
            ) : (
              "N/A"
            )}
          </p>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-1">
            Total Active Domains Detected
          </p>
          <p className="text-white text-2xl font-semibold">
            {loading ? (
              <Skeleton sx={{ width: 100, borderRadius: 2 }} />
            ) : data ? (
              data.total_active_domains
            ) : (
              "N/A"
            )}
          </p>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-1">Total Parked Domains</p>
          <p className="text-white text-2xl font-semibold">
            {loading ? (
              <Skeleton sx={{ width: 100, borderRadius: 2 }} />
            ) : data ? (
              data.total_parked_domains
            ) : (
              "N/A"
            )}
          </p>
        </div>
      </div>
    </LiquidCard>
  );
};
