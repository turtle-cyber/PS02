import React, { useState } from "react";
import { addDays } from "date-fns";
import { Calendar } from "@/components/ui/calendar";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { DateRange as DateRangeIcon } from "@mui/icons-material";
import type { DateRange } from "react-day-picker";

interface DateTimeRangeValue {
  startDate: Date;
  endDate: Date;
}

interface DateTimeRangeFilterProps {
  value: DateTimeRangeValue;
  onChange: (value: DateTimeRangeValue) => void;
}

const DateTimeRangeFilter: React.FC<DateTimeRangeFilterProps> = ({
  value,
  onChange,
}) => {
  const [open, setOpen] = useState(false);

  // Internal state for calendar date range
  const [dateRange, setDateRange] = useState<DateRange | undefined>({
    from: value.startDate,
    to: value.endDate,
  });

  // Internal state for time inputs
  const [startTime, setStartTime] = useState(() => {
    const hours = value.startDate.getUTCHours().toString().padStart(2, "0");
    const minutes = value.startDate.getUTCMinutes().toString().padStart(2, "0");
    return `${hours}:${minutes}`;
  });

  const [endTime, setEndTime] = useState(() => {
    const hours = value.endDate.getUTCHours().toString().padStart(2, "0");
    const minutes = value.endDate.getUTCMinutes().toString().padStart(2, "0");
    return `${hours}:${minutes}`;
  });

  const handleDateRangeSelect = (range: DateRange | undefined) => {
    setDateRange(range);
  };

  const handleDone = () => {
    if (!dateRange?.from || !dateRange?.to) {
      return;
    }

    // Parse start time
    const [startHours, startMinutes] = startTime
      .split(":")
      .map((str) => parseInt(str, 10));
    let startDateTime = new Date(dateRange.from);
    startDateTime.setUTCHours(startHours);
    startDateTime.setUTCMinutes(startMinutes);
    startDateTime.setUTCSeconds(0, 0);

    // Parse end time
    const [endHours, endMinutes] = endTime
      .split(":")
      .map((str) => parseInt(str, 10));
    let endDateTime = new Date(dateRange.to);
    endDateTime.setUTCHours(endHours);
    endDateTime.setUTCMinutes(endMinutes);
    endDateTime.setUTCSeconds(59, 999);

    onChange({
      startDate: startDateTime,
      endDate: endDateTime,
    });

    setOpen(false);
  };

  const handleReset = () => {
    // Reset to last 24 hours
    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const startDateTime = new Date(last24Hours);
    startDateTime.setUTCHours(0, 0, 0, 0);

    const endDateTime = new Date(now);
    endDateTime.setUTCHours(23, 59, 59, 999);

    setDateRange({
      from: startDateTime,
      to: endDateTime,
    });
    setStartTime("00:00");
    setEndTime("23:59");

    onChange({
      startDate: startDateTime,
      endDate: endDateTime,
    });

    setOpen(false);
  };

  // Format datetime for display: "Jan 15 2025 14:30 - Jan 22 2025 18:45"
  const formatDateTimeRange = (start: Date, end: Date) => {
    const options: Intl.DateTimeFormatOptions = {
      month: "short",
      day: "numeric",
      year: "numeric",
      timeZone: "UTC",
    };

    const startDate = start.toLocaleDateString("en-US", options);
    const endDate = end.toLocaleDateString("en-US", options);

    const startHours = start.getUTCHours().toString().padStart(2, "0");
    const startMinutes = start.getUTCMinutes().toString().padStart(2, "0");
    const endHours = end.getUTCHours().toString().padStart(2, "0");
    const endMinutes = end.getUTCMinutes().toString().padStart(2, "0");

    return `${startDate} ${startHours}:${startMinutes} - ${endDate} ${endHours}:${endMinutes}`;
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className="justify-start text-left font-normal bg-[rgba(255,255,255,0.05)] hover:bg-[rgba(255,255,255,0.08)] backdrop-blur-[15px] border-white/10"
        >
          <DateRangeIcon className="mr-2 h-4 w-4" />
          {formatDateTimeRange(value.startDate, value.endDate)}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-auto p-0 bg-[rgba(255,255,255,0.08)] backdrop-blur-[15px] border-white/10"
        align="start"
      >
        <div className="p-4 space-y-4">
          {/* Calendar for date range selection */}
          <Calendar
            mode="range"
            selected={dateRange}
            onSelect={handleDateRangeSelect}
            numberOfMonths={1}
            disabled={(date) =>
              date > new Date() || date < addDays(new Date(), -90)
            }
          />

          {/* Time inputs */}
          <div className="border-t pt-4 space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium mb-1.5 block">
                  Start Time
                </label>
                <input
                  type="time"
                  value={startTime}
                  onChange={(e) => setStartTime(e.target.value)}
                  className="w-full px-3 py-2 text-sm border rounded-md bg-[rgba(255,255,255,0.05)] hover:bg-[rgba(255,255,255,0.08)] border-white/5"
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-1.5 block">
                  End Time
                </label>
                <input
                  type="time"
                  value={endTime}
                  onChange={(e) => setEndTime(e.target.value)}
                  className="w-full px-3 py-2 text-sm border rounded-md bg-[rgba(255,255,255,0.05)] hover:bg-[rgba(255,255,255,0.08)] border-white/5"
                />
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex justify-end gap-2 border-t pt-4">
            <Button
              variant="outline"
              size="sm"
              onClick={handleReset}
              className=""
            >
              Reset
            </Button>
            <Button size="sm" onClick={handleDone}>
              Done
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
};

export default DateTimeRangeFilter;
