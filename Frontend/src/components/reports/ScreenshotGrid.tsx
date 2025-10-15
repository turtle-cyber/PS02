import * as React from "react";

interface ScreenshotGridProps {
  screenshots: string[];
}

export const ScreenshotGrid: React.FC<ScreenshotGridProps> = ({ screenshots }) => {
  return (
    <div className="grid grid-cols-2 gap-3">
      {screenshots.map((src, idx) => (
        <div
          key={idx}
          className="aspect-video rounded-lg overflow-hidden border border-white/10 bg-slate-900/50 hover:border-white/20 transition-colors cursor-pointer"
        >
          <img
            src={src}
            alt={`Screenshot ${idx + 1}`}
            className="w-full h-full object-cover"
          />
        </div>
      ))}
    </div>
  );
};
