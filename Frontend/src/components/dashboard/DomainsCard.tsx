import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { Skeleton } from "@mui/material";

export const DomainsCard: React.FC<any> = ({ data, loading }) => {
  const formatNumber = (num: number | null | undefined) => {
    if (num == null) return "N/A";
    return num.toLocaleString();
  };

  const formatK = (num: number | null | undefined) => {
    if (num == null) return "N/A";
    if (num >= 1000) return `${Math.round(num / 100) / 10}K`;
    return num.toString();
  };

  return (
    <LiquidCard variant="glass" className="p-6 min-h-[460px]">
      <div className="flex flex-col h-full gap-6">
        {/* Top Section: Look-Alike Domains + MX Records */}
        <div className="grid grid-cols-2 gap-0 border-b border-white/10 pb-6">
          {/* Look-Alike Domains */}
          <div className="flex flex-col justify-center border-r border-white/10 pr-6">
            <div className="text-[2.5rem] leading-none font-bold text-white mb-2">
              {loading ? (
                <Skeleton sx={{ width: 120, height: 50, borderRadius: 2 }} />
              ) : (
                formatNumber(data?.lookalike_domains)
              )}
            </div>
            <div className="text-slate-400 text-sm font-normal">
              Look-Alike Domains
            </div>
            {data?.tlds && !loading && (
              <div className="text-slate-500 text-xs mt-1">
                TLDs: {formatK(data.tlds)}
              </div>
            )}
          </div>

          {/* MX Records */}
          <div className="flex flex-col justify-center pl-6">
            <div className="text-[2.5rem] leading-none font-bold text-white mb-2">
              {loading ? (
                <Skeleton sx={{ width: 120, height: 50, borderRadius: 2 }} />
              ) : (
                formatNumber(data?.domains_with_mx)
              )}
            </div>
            <div className="text-slate-400 text-sm font-normal">MX Records</div>
          </div>
        </div>

        {/* Total Active Domains Detected */}
        <div className="flex flex-col justify-center border-b border-white/10 py-6">
          <div className="text-slate-400 text-sm font-normal mb-2">
            Total Active Domains Detected
          </div>
          <div className="text-[2.5rem] leading-none font-bold text-white">
            {loading ? (
              <Skeleton sx={{ width: 120, height: 50, borderRadius: 2 }} />
            ) : (
              formatNumber(data?.total_active_domains)
            )}
          </div>
        </div>

        {/* Total Parked Domains */}
        <div className="flex flex-col justify-center pt-6">
          <div className="text-slate-400 text-sm font-normal mb-2">
            Total Parked Domains
          </div>
          <div className="text-[2.5rem] leading-none font-bold text-white">
            {loading ? (
              <Skeleton sx={{ width: 120, height: 50, borderRadius: 2 }} />
            ) : (
              formatNumber(data?.total_parked_domains)
            )}
          </div>
        </div>
      </div>
    </LiquidCard>
  );
};