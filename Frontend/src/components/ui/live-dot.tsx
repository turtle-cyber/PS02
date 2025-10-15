import * as React from "react";
import { cn } from "@/lib/utils";

interface LiveDotProps extends React.HTMLAttributes<HTMLDivElement> {}

export const LiveDot = React.forwardRef<HTMLDivElement, LiveDotProps>(
  ({ className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn("flex items-center gap-2", className)}
        role="status"
        aria-live="polite"
        {...props}
      >
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#E50914] opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#E50914]"></span>
        </span>
        <span className="text-[#E50914] text-sm font-medium">Live</span>
      </div>
    );
  }
);

LiveDot.displayName = "LiveDot";
