import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { Skeleton } from "@mui/material";

export const OverviewCards: React.FC<any> = ({ data, loading }) => {
  return (
    <div className="flex flex-col gap-5 w-full">
      <div className="flex gap-6">
        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">Total Scans</p>
            <p className="text-white text-3xl font-semibold">
              {loading ? (
                <Skeleton sx={{ width: 100, borderRadius: 2 }} />
              ) : data ? (
                data.total_scans
              ) : (
                "N/A"
              )}
            </p>
          </div>
        </LiquidCard>

        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">Confidence Score</p>
            <p className="text-white text-3xl font-semibold">
              {loading ? (
                <Skeleton sx={{ width: 100, borderRadius: 2 }} />
              ) : data ? (
                53
              ) : (
                "N/A"
              )}
              %
            </p>
          </div>
        </LiquidCard>
      </div>

      <div className="flex gap-6">
        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">CSEs</p>
            <p className="text-white text-3xl font-semibold">
              {loading ? (
                <Skeleton sx={{ width: 100, borderRadius: 2 }} />
              ) : data ? (
                data.brands_tracked
              ) : (
                "N/A"
              )}
            </p>
          </div>
        </LiquidCard>

        <LiquidCard variant="glass" className="p-6 flex-1">
          <div className="space-y-4">
            <p className="text-slate-400 text-sm mb-1">Phishing URLs</p>
            <p className="text-white text-3xl font-semibold">
              {loading ? (
                <Skeleton sx={{ width: 100, borderRadius: 2 }} />
              ) : data ? (
                data.total_phishing
              ) : (
                "N/A"
              )}
            </p>
          </div>
        </LiquidCard>
      </div>
    </div>
  );
};
