import * as React from "react";
import { cn } from "@/lib/utils";

interface LiquidCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  variant?: 'default' | 'glass';
  allowOverflow?: boolean;
}

export const LiquidCard = React.forwardRef<HTMLDivElement, LiquidCardProps>(
  ({ className, children, variant = 'default', allowOverflow = false, ...props }, ref) => {

    const glassStyles = 'rounded-2xl border border-white/10 backdrop-blur-[20px]' +
      ' bg-[rgba(255,255,255,0.05)] shadow-[0_0_24px_rgba(229,9,20,0.10)]' +
      ' ring-1 ring-white/5 transition-all duration-300' +
      ' hover:bg-[rgba(255,255,255,0.08)] hover:border-white/15' +
      ' hover:shadow-[0_0_32px_rgba(229,9,20,0.15)]' +
      ` relative ${allowOverflow ? 'overflow-visible' : 'overflow-hidden'}`;

    const defaultStyles = "rounded-2xl border border-white/6 backdrop-blur-md" +
      " bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02))]" +
      " shadow-[0_0_24px_rgba(229,9,20,0.10)]" +
      " ring-1 ring-white/5";

    const baseStyles = variant === 'glass' ? glassStyles : defaultStyles;

    return (
      <div
        ref={ref}
        className={cn(baseStyles, className)}
        {...props}
      >
        {/* Optional glow effect for glass variant */}
        {variant === 'glass' && (
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background: 'radial-gradient(circle at 30% 30%, rgba(215, 24, 24, 0.1) 0%, transparent 50%)',
            }}
          />
        )}
        <div className="relative z-10">{children}</div>
      </div>
    );
  }
);

LiquidCard.displayName = "LiquidCard";