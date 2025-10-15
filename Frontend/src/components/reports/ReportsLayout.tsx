import * as React from "react";
import { LiquidCard } from "@/components/ui/liquid-card";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { FileText, Download, Filter } from "lucide-react";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";

interface ReportsLayoutProps {
  title: string;
  children: React.ReactNode;
}

export const ReportsLayout: React.FC<ReportsLayoutProps> = ({ title, children }) => {
  return (
    <div className="min-h-screen">
      {/* Header */}
      {/* <header className="border-b border-white/5 bg-transparent backdrop-blur-sm"> */}
        <div className="w-full max-w-none px-6 py-6">
          <div className="flex items-center justify-between">
            <h1 className="text-3xl font-bold text-white">{title}</h1>
            <div className="flex items-center gap-3">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" className="text-slate-400 hover:text-white hover:bg-white/5">
                    <FileText className="h-5 w-5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Export PDF</TooltipContent>
              </Tooltip>
              
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" className="text-slate-400 hover:text-white hover:bg-white/5">
                    <Download className="h-5 w-5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Export CSV</TooltipContent>
              </Tooltip>

              <Sheet>
                <SheetTrigger asChild>
                  <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white hover:bg-white/5">
                    <Filter className="h-4 w-4" />
                    Filters
                  </Button>
                </SheetTrigger>
                <SheetContent className="bg-slate-950 border-white/10">
                  <SheetHeader>
                    <SheetTitle className="text-white">Filter Reports</SheetTitle>
                    <SheetDescription className="text-slate-400">
                      Apply filters to refine your report data
                    </SheetDescription>
                  </SheetHeader>
                  <div className="mt-6 space-y-4">
                    <p className="text-sm text-slate-400">Filter controls coming soon...</p>
                  </div>
                </SheetContent>
              </Sheet>
            </div>
          </div>
        </div>
      {/* </header> */}

      {/* Main content */}
      <main className="ml-4 mr-4">
        <LiquidCard className="p-0 overflow-hidden border border-white/5">
          {children}
        </LiquidCard>   
      </main>
    </div>
  );
};