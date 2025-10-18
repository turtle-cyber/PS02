import * as React from "react";
import { GeoRippleMap } from "@/components/echarts/GeoRippleMap";
import { ScreenshotGrid } from "./ScreenshotGrid";
import type { UrlDetailData } from "@/data/mockReportDetails";
import { LiquidCard } from "../ui/liquid-card";

const cardStyles =
  "rounded-2xl border border-white/6 backdrop-blur-md bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02))] shadow-[0_0_24px_rgba(229,9,20,0.10)] ring-1 ring-white/5 p-5";

const MetricRow: React.FC<{
  label: string;
  value: string | number | boolean;
}> = ({ label, value }) => (
  <div className="flex justify-between items-center py-1.5">
    <span className="text-sm text-slate-400">{label}:</span>
    <span className="text-sm text-slate-200 font-medium">
      {typeof value === "boolean" ? (value ? "Yes" : "No") : value}
    </span>
  </div>
);

export const DetailCards: React.FC<any> = ({ data }) => {
  return (
    <>
      {/* Row 1: Domain Analysis + Screenshots */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="grid grid-row-1 lg:grid-row-2 gap-8">
          <LiquidCard variant="glass">
            <h1 className="text-base font-semibold text-slate-300 mb-0 ml-4 mt-4">
              Domain Analysis
            </h1>
            <div className="ml-4 mb-4 mr-4">
              <MetricRow
                label="A Count"
                value={data?.data?.metadata?.a_count}
              />
              <MetricRow
                label="NS Count"
                value={data?.data?.metadata?.ns_count}
              />
              <MetricRow
                label="MX Count"
                value={data?.data?.metadata?.mx_count}
              />
            </div>
          </LiquidCard>
          <LiquidCard variant="glass">
            <h3 className="text-base font-semibold text-slate-300 mt-4 mb-0 ml-4 ">
              Domain Age WHOIS
            </h3>
            <div className="ml-4 mb-4 mr-4">
              <MetricRow
                label="Is Newly Registered"
                value={data?.data?.metadata?.is_newly_registered ?? "N/A"}
              />
              <MetricRow
                label="Is Very New"
                value={data?.data?.metadata?.is_very_new}
              />
              <MetricRow
                label="Days Until Expiry"
                value={data?.data?.metadata?.days_until_expiry}
              />
            </div>
          </LiquidCard>
        </div>
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mt-4 mb-4 ml-4">
            Geo Location
          </h3>
          <GeoRippleMap data={data?.geoPoints} height="280px" />
        </LiquidCard>
      </div>

      {/* Row 3: Feature Metrics (full width) */}
      <div className="mb-6">
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mt-4 mb-4 ml-4">
            Feature Metrics
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-x-8 gap-y-2 ml-4 mb-4 mr-4">
            <MetricRow label="URL" value={data?.urlLength} />
            <MetricRow label="Has Features" value="Yes" />
            <MetricRow label="URL Length" value={data?.urlLength} />
            <MetricRow
              label="URL Entropy"
              value={data?.urlEntropy?.toFixed(2)}
            />
            <MetricRow
              label="Number of Subdomains"
              value={data?.numSubdomains}
            />
            <MetricRow label="Has Repeated Digits" value="No" />
            <MetricRow label="Mixed Script" value={data?.hasMixedScript} />
            <MetricRow label="Form Count" value={data?.formCount} />
            <MetricRow label="Password Fields" value={data?.passwordFields} />
            <MetricRow label="Email Fields" value={data?.emailFields} />
            <MetricRow
              label="Phishing Keywords"
              value={data?.phishingKeywords}
            />
            <MetricRow label="Keywords Count" value={data?.phishingKeywords} />
            <MetricRow label="HTML Size" value={data?.htmlSize} />
            <MetricRow label="External Links" value={data?.externalLinks} />
            <MetricRow label="Iframe Count" value={data?.iframeCount} />
          </div>
        </LiquidCard>
      </div>

      {/* Row 4: Favicon + Redirect Tracking */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            Favicon Analysis
          </h3>
          <div className="ml-4 mb-4 mr-4">
            <MetricRow label="Favicon MD5" value={data?.faviconMd5} />
            <MetricRow label="Favicon SHA256" value={data?.faviconSha256} />
          </div>
        </LiquidCard>

        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            Redirect Tracking
          </h3>

          <div className="ml-4 mb-4 mr-4">
            <MetricRow label="Redirect Count" value={data?.redirectCount} />
            <MetricRow label="Has Redirects" value={data?.hasRedirects} />
          </div>
        </LiquidCard>
      </div>

      {/* Row 5: JS Analysis + SSL Certificate */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            JS Analysis
          </h3>
          <div className="ml-4 mb-4 mr-4">
            <MetricRow label="Obfuscated" value={data?.isObfuscated} />
            <MetricRow label="Eval Count" value={data?.evalCount} />
            <MetricRow label="Encoding Count" value={data?.encodingCount} />
            <MetricRow label="Keylogger" value={data?.hasKeylogger} />
            <MetricRow
              label="Form Manipulation"
              value={data?.hasFormManipulation}
            />
            <MetricRow
              label="Redirect Detection"
              value={data?.hasRedirectDetection}
            />
            <MetricRow label="JS Risk Score" value={data?.jsRiskScore} />
          </div>
        </LiquidCard>

        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            SSL Certificate Analysis
          </h3>
          <div className="ml-4 mb-4 mr-4 ">
            <MetricRow
              label="Suspicious Form Count"
              value={data?.hasSuspiciousForms}
            />
            <MetricRow label="Has Suspicious Form Name" value={"N/A"} />
            <MetricRow label="Forms to IP" value={data?.formsToIp} />
            <MetricRow
              label="Form to Private IP"
              value={data?.formsToPrivateIp}
            />
          </div>
        </LiquidCard>
      </div>

      {/* Row 6: Scan Settings */}
      <div>
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            Scan Settings
          </h3>
          <div className="ml-4 mb-4 mr-4">
            <div className="flex items-center gap-3">
              <label className="text-sm text-slate-400">
                Select Monitoring Duration:
              </label>
              <select className=" ml-10 bg-gray-800/50 border border-white/10 rounded-md px-3 py-1.5 text-sm text-slate-200">
                <option value="30">30 days</option>
                <option value="60">60 days</option>
                <option value="90" selected>
                  90 days
                </option>
              </select>
            </div>
            <p className="text-xs text-slate-500">
              {/* TODO: Wire up monitoring duration change handler */}
              Adjust monitoring duration for this URL
            </p>
          </div>
        </LiquidCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-1 gap-6 mt-6 mb-6">
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            Screenshots
          </h3>
          <div className="ml-4 mb-4 mr-4">
            <ScreenshotGrid screenshots={data?.screenshots} />
          </div>
        </LiquidCard>
      </div>
    </>
  );
};
