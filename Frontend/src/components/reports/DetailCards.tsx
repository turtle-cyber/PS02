import * as React from "react";
import { GeoRippleMap } from "@/components/echarts/GeoRippleMap";
import { ScreenshotGrid } from "./ScreenshotGrid";
import type { UrlDetailData } from "@/data/mockReportDetails";
import { LiquidCard } from "../ui/liquid-card";
import { transformScreenshotPath } from "@/utils/screenshotHelpers";
import { Accordion, AccordionDetails, AccordionSummary } from "@mui/material";
import { ArrowDownward } from "@mui/icons-material";

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
  const [showScreenshot, setShowScreenshot] = React.useState(true);
  const [imageError, setImageError] = React.useState(false);

  const handleDownload = async (imageUrl: string) => {
    if (!imageUrl) return;
    try {
      const response = await fetch(imageUrl);
      if (!response.ok) throw new Error("Failed to fetch image");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = imageUrl.split("/").pop() || "screenshot.png";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download failed:", err);
      alert("Unable to download screenshot.");
    }
  };

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
          <GeoRippleMap
            data={
              data?.data?.metadata?.latitude && data?.data?.metadata?.longitude
                ? [
                    {
                      name:
                        data?.data?.metadata?.city ||
                        data?.data?.metadata?.country ||
                        "Unknown Location",
                      value: [
                        data.data.metadata.longitude,
                        data.data.metadata.latitude,
                        1,
                      ],
                    },
                  ]
                : []
            }
            height="280px"
          />
        </LiquidCard>
      </div>

      {/* Row 3: Feature Metrics (full width) */}
      <div className="mb-6">
        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mt-4 mb-4 ml-4">
            Feature Metrics
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-x-8 gap-y-2 ml-4 mb-4 mr-4">
            <MetricRow
              label="URL"
              value={
                data?.data?.metadata?.url
                  ? data.data.metadata.url.length > 100
                    ? data.data.metadata.url.slice(0, 100) + "..."
                    : data.data.metadata.url
                  : "N/A"
              }
            />
            <MetricRow
              label="Has Features"
              value={data?.data?.metadata?.has_features}
            />
            <MetricRow
              label="URL Length"
              value={data?.data?.metadata?.url_length}
            />
            <MetricRow
              label="URL Entropy"
              value={data?.data?.metadata?.url_entropy}
            />
            <MetricRow
              label="Subdomains Entropy"
              value={data?.data?.metadata?.subdomain_entropy}
            />
            <MetricRow
              label="Has Repeated Digits"
              value={data?.data?.metadata?.has_repeated_digits}
            />
            <MetricRow
              label="Mixed Script"
              value={data?.data?.metadata?.mixed_script}
            />
            <MetricRow
              label="Form Count"
              value={data?.data?.metadata?.formCount}
            />
            <MetricRow
              label="Password Fields"
              value={data?.data?.metadata?.password_fields}
            />
            <MetricRow
              label="Email Fields"
              value={data?.data?.metadata?.email_fields}
            />
            <MetricRow
              label="Phishing Keywords"
              value={data?.data?.metadata?.phishing_keywords}
            />
            <MetricRow
              label="Keywords Count"
              value={data?.data?.metadata?.keyword_count}
            />
            <MetricRow
              label="HTML Size"
              value={data?.data?.metadata?.html_size}
            />
            <MetricRow
              label="External Links"
              value={data?.data?.metadata?.external_links}
            />
            <MetricRow
              label="Iframe Count"
              value={data?.data?.metadata?.iframe_count}
            />
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
            <MetricRow
              label="Favicon MD5"
              value={data?.data?.metadata?.favicon_md5}
            />
            <MetricRow
              label="Favicon SHA256"
              value={data?.data?.metadata?.favicon_sha256}
            />
          </div>
        </LiquidCard>

        <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            SSL Certificate Analysis
          </h3>
          <div className="ml-4 mb-4 mr-4 ">
            <MetricRow
              label="Suspicious Form Count"
              value={data?.data?.metadata?.suspicious_form_count}
            />
            <MetricRow label="Has Suspicious Form Name" value={"N/A"} />
            <MetricRow
              label="Forms to IP"
              value={data?.data?.metadata?.forms_to_ip}
            />
            <MetricRow
              label="Form to Private IP"
              value={data?.data?.metadata?.forms_to_private_ip}
            />
          </div>
        </LiquidCard>

        {/* <LiquidCard variant="glass">
          <h3 className="text-base font-semibold text-slate-300 mb-4 ml-4 mt-4">
            Redirect Tracking
          </h3>

          <div className="ml-4 mb-4 mr-4">
            <MetricRow label="Redirect Count" value={data?.redirectCount} />
            <MetricRow label="Has Redirects" value={data?.hasRedirects} />
          </div>
        </LiquidCard> */}
      </div>

      {/* Row 5: JS Analysis + SSL Certificate */}
      {/* <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
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
      </div> */}

      {/* Row 6: Scan Settings */}
      {/* <div>
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
              Adjust monitoring duration for this URL
            </p>
          </div>
        </LiquidCard>
      </div> */}

      <div className="grid grid-cols-1 lg:grid-cols-1 gap-6 mt-6 mb-6">
        <LiquidCard variant="glass">
          <Accordion
            disableGutters
            elevation={0}
            expanded={showScreenshot}
            onChange={() => setShowScreenshot((prev) => !prev)}
            className="!bg-transparent !shadow-none"
          >
            <AccordionSummary
              expandIcon={<ArrowDownward className="text-slate-300" />}
              className="!min-h-0 !py-0 hover:bg-white/5 rounded-lg transition"
            >
              <h3 className="text-base font-semibold text-slate-300 select-none">
                Screenshots
              </h3>
            </AccordionSummary>

            <AccordionDetails className="!pt-5">
              <div className="flex justify-center mb-4">
                {data?.data?.metadata?.screenshot_path && !imageError ? (
                  <div className="relative group w-full max-w-md rounded-lg overflow-hidden">
                    <img
                      src={
                        transformScreenshotPath(
                          data?.data?.metadata?.screenshot_path
                        ) || ""
                      }
                      alt="Domain Screenshot"
                      className="w-full h-auto rounded-md object-contain transition-transform duration-300 group-hover:scale-[1.02]"
                      onError={() => setImageError(true)}
                    />

                    {/* Hover Download button */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation(); // prevent accordion toggle
                        handleDownload(
                          transformScreenshotPath(
                            data?.data?.metadata?.screenshot_path
                          )
                        );
                      }}
                      className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <span className="px-3 py-1.5 bg-slate-800/80 text-slate-100 text-sm rounded-md border border-white/10 hover:bg-slate-700/90">
                        Download
                      </span>
                    </button>
                  </div>
                ) : (
                  <p className="text-sm text-slate-400 italic mb-4">
                    No Screenshot available
                  </p>
                )}
              </div>
            </AccordionDetails>
          </Accordion>
        </LiquidCard>
      </div>
    </>
  );
};
