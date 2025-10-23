import React, { useState } from "react";
import { DateRangePicker } from "react-date-range";

import "react-date-range/dist/styles.css";
import "react-date-range/dist/theme/default.css";
import { Button, Popover, Typography } from "@mui/material";
import { addDays } from "date-fns";
import { DateRange as DateRangeIcon } from "@mui/icons-material";

interface DateRangeValue {
  startDate: Date;
  endDate: Date;
}

interface DateRangeFilterProps {
  value: DateRangeValue;
  onChange: (value: DateRangeValue) => void;
}

const DateRangeFilter: React.FC<DateRangeFilterProps> = ({
  value,
  onChange,
}) => {
  const [anchorElCalendar, setAnchorElCalendar] =
    useState<HTMLButtonElement | null>(null);
  const openCalendar = Boolean(anchorElCalendar);
  const id = openCalendar ? "date-range-popover" : undefined;

  const [selectedDateRange, setSelectedDateRange] = useState({
    startDate: value.startDate,
    endDate: value.endDate,
    key: "selection",
  });

  const handleDateRangeSelection = (ranges: any) => {
    setSelectedDateRange(ranges.selection);
  };

  const handleDateRangeDone = () => {
    // Set time to start of day (00:00:00) for start date
    const startDate = new Date(selectedDateRange.startDate);
    startDate.setHours(0, 0, 0, 0);

    // Set time to end of day (23:59:59) for end date
    const endDate = new Date(selectedDateRange.endDate);
    endDate.setHours(23, 59, 59, 999);

    onChange({ startDate, endDate });
    handleCloseCalendar();
  };

  const handleClickCalendar = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorElCalendar(event.currentTarget);
  };

  const handleCloseCalendar = () => {
    setAnchorElCalendar(null);
  };

  const onClickClearDateRange = () => {
    // Reset to last 24 hours
    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const startDate = new Date(last24Hours);
    startDate.setHours(0, 0, 0, 0);

    const endDate = new Date(now);
    endDate.setHours(23, 59, 59, 999);

    setSelectedDateRange({
      startDate,
      endDate,
      key: "selection",
    });

    onChange({ startDate, endDate });
    handleCloseCalendar();
  };

  // Format date range for display: "Jan 15 2025 - Jan 22, 2025"
  const formatDateRange = (start: Date, end: Date) => {
    const options: Intl.DateTimeFormatOptions = {
      month: "short",
      day: "numeric",
      year: "numeric",
    };

    const startStr = start.toLocaleDateString("en-US", options);
    const endStr = end.toLocaleDateString("en-US", options);

    return `${startStr} - ${endStr}`;
  };

  return (
    <>
      <Button
        sx={{ paddingX: 3, paddingY: 1 }}
        aria-describedby={id}
        variant="outlined"
        onClick={handleClickCalendar}
        startIcon={<DateRangeIcon />}
      >
        {formatDateRange(value.startDate, value.endDate)}
      </Button>
      <Popover
        id={id}
        open={openCalendar}
        anchorEl={anchorElCalendar}
        onClose={handleCloseCalendar}
        anchorOrigin={{
          vertical: "bottom",
          horizontal: "left",
        }}
      >
        <div className="calender-date-range-container">
          <Typography sx={{ p: 2 }}>
            <DateRangePicker
              onChange={handleDateRangeSelection}
              showSelectionPreview={true}
              moveRangeOnFirstSelection={false}
              months={1}
              minDate={addDays(new Date(), -90)}
              maxDate={addDays(new Date(), 0)}
              ranges={[selectedDateRange]}
              inputRanges={[]}
              direction="horizontal"
            />
            <div className="calender-action-buttons">
              <button className="btn-done p-2" onClick={handleDateRangeDone}>
                Done
              </button>
              <button className="btn-clear p-2" onClick={onClickClearDateRange}>
                Reset
              </button>
            </div>
          </Typography>
        </div>
      </Popover>
    </>
  );
};

export default DateRangeFilter;
