import * as React from "react";
import { Button } from "@/components/ui/button";
import { Calendar } from "lucide-react";

interface MonthRangePickerProps {
  range: string;
}

export const MonthRangePicker: React.FC<MonthRangePickerProps> = ({ range }) => {
  return (
    <Button 
      variant="ghost" 
      className="text-slate-300 hover:text-white hover:bg-white/5 transition-colors"
      onClick={() => console.log("Month range picker clicked")}
    >
      <Calendar className="mr-2 h-4 w-4" />
      {range}
    </Button>
  );
};
