import * as React from "react";
import { useNavigate } from "react-router-dom";
import { ChevronLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface DetailHeaderProps {
  url: string;
  backPath: string;
  backLabel: string;
  verdict?: string;
  darkWebPresence?: boolean;
  confidence?: number;
  risk?: number;
  metaLeft: Array<{ label: string; value: string | number }>;
  metaRight: Array<{ label: string; value: string | number }>;
  lastScan: string;
  additionalMetrics?: Array<{
    label: string;
    value: string | number;
    highlight?: boolean;
  }>;
}

const getVerdictColor = (verdict: string) => {
  switch (verdict) {
    case "phishing":
      return "bg-[#8B373A]/20 text-[#e1e1e1] border-[#E50914]/40 capitalize";
    case "parked":
      return "bg-[#FDD835]/20 text-[#FFB020] border-[#FFB020]/40 capitalize";
    case "benign":
      return "bg-[#43A047]/20 text-[#1FBF75] border-[#1FBF75]/40 capitalize";
    default:
      return "bg-slate-500/20 text-slate-400 border-slate-500/40 capitalize";
  }
};

export const DetailHeader: React.FC<DetailHeaderProps> = ({
  url,
  backPath,
  backLabel,
  verdict,
  darkWebPresence,
  confidence,
  risk,
  metaLeft,
  metaRight,
  lastScan,
  additionalMetrics = [],
}) => {
  const navigate = useNavigate();

  return (
    <div className="rounded-2xl border border-white/6 backdrop-blur-md bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02))] shadow-[0_0_24px_rgba(229,9,20,0.10)] ring-1 ring-white/5 p-6">
      {/* Back button and URL */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-4 flex-1">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate(backPath)}
            className="text-slate-400 hover:text-white"
            aria-label={backLabel}
          >
            <ChevronLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-2xl font-semibold text-white">{url}</h1>
        </div>

        {/* Status chips */}
        <div className="flex items-center gap-2">
          {verdict && (
            <Badge className={getVerdictColor(verdict)}>{verdict}</Badge>
          )}
          {darkWebPresence && (
            <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/40">
              Dark-web presence
            </Badge>
          )}
          {typeof confidence === "number" && typeof risk === "number" && (
            <Badge className="bg-slate-700/40 text-slate-300 border-slate-600/40">
              Confidence: {confidence}% | Risk: {risk}
            </Badge>
          )}
        </div>
      </div>

      {/* Additional metrics (for lookalikes) */}
      {additionalMetrics.length > 0 && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          {additionalMetrics.map((metric, idx) => (
            <div key={idx} className="space-y-1">
              <p className="text-xs text-slate-400">{metric.label}:</p>
              <p
                className={`text-lg font-semibold ${
                  metric.highlight ? "text-[#B71C1C]" : "text-slate-200"
                }`}
              >
                {metric.value}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Meta grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
        {/* Left block */}
        <div className="space-y-3">
          {metaLeft.map((item, idx) => (
            <div key={idx} className="flex justify-between items-center">
              <span className="text-sm text-slate-400">{item.label}:</span>
              <span className="text-sm text-slate-200 font-medium">
                {item.value}
              </span>
            </div>
          ))}
        </div>

        {/* Right block */}
        <div className="space-y-3">
          {metaRight.map((item, idx) => (
            <div key={idx} className="flex justify-between items-center">
              <span className="text-sm text-slate-400">{item.label}:</span>
              <span className="text-sm text-slate-200 font-medium">
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Last scan */}
      <div className="flex justify-end">
        <span className="text-xs text-slate-500">
          Last Scan:{" "}
          {new Date(lastScan).toLocaleString("en-GB", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          })}
        </span>
      </div>
    </div>
  );
};
