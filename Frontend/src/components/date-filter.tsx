import React, { useState } from "react";
import { DateRangePicker } from "react-date-range";

import "react-date-range/dist/styles.css";
import "react-date-range/dist/theme/default.css";
import { Button, Popover, Tooltip, Typography } from "@mui/material";
import { addDays } from "date-fns";
import { DateRange } from "@mui/icons-material";

const DateRangeFilter = () => {
  const [anchorElCalendar, setAnchorElCalendar] = useState(null);
  const openCalendar = Boolean(anchorElCalendar);
  const id = openCalendar ? "simple-popover" : undefined;

  const sevenDaysAgoDate = new Date();
  sevenDaysAgoDate.setDate(new Date().getDate() - 7);
  const [selectedDateRange, setSelectedDateRange] = useState({
    startDate: sevenDaysAgoDate,
    endDate: new Date(),
    key: "selection",
  });

  const handleDateRangeSelection = (ranges) => {
    setSelectedDateRange(ranges.selection);
  };

  const handleDateRangeDone = () => {
    setDateRange(selectedDateRange);
    handleCloseCalendar();
  };

  const handleClickCalendar = (event) => {
    setAnchorElCalendar(event.currentTarget);
  };

  const handleCloseCalendar = () => {
    setAnchorElCalendar(null);
  };

  const onClickClearDateRange = () => {
    setSelectedDateRange({
      startDate: new Date(),
      endDate: new Date(),
      key: "selection",
    });
    setDateRange();
    handleCloseCalendar();
  };

  return (
    <>
      <Tooltip title="Date Filter" placement="left" arrow>
        <Button
          aria-describedby={id}
          variant="text"
          onClick={handleClickCalendar}
        >
          <DateRange />
        </Button>
        <Popover
          id={id}
          open={openCalendar}
          anchorEl={anchorElCalendar}
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
                <button
                  className="btn-clear p-2"
                  onClick={onClickClearDateRange}
                >
                  Reset
                </button>
              </div>
            </Typography>
          </div>
        </Popover>
      </Tooltip>
    </>
  );
};

export default DateRangeFilter;
