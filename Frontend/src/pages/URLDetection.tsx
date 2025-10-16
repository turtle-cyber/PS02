import {
  Box,
  Container,
  Typography,
  TextField,
  InputAdornment,
  Select,
  MenuItem,
  FormControlLabel,
  Checkbox as MuiCheckbox,
  IconButton,
  Alert,
  styled,
  Skeleton,
} from "@mui/material";
import { Search, AttachFile, Send, Close } from "@mui/icons-material";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { http } from "@/hooks/config";
import Papa from "papaparse";
import { BULK_SUBMIT, MONITORING_URL, SUBMIT_URL, URLS_SCANNED } from "@/endpoints/urldetection.endpoints";

/* ---------- KPI Card (animated) ---------- */
type KPICardProps = {
  title: string;
  unit?: string;
  data?: number;
  loading?: boolean;
  duration?: number;
};
const KPICard: React.FC<KPICardProps> = ({
  title,
  data,
  loading,
  unit,
  duration = 1500,
}) => {
  const [displayed, setDisplayed] = useState(0);
  const rafRef = useRef<number | null>(null);
  const easeOutCubic = (t: number) => 1 - Math.pow(1 - t, 3);
  useEffect(() => {
    if (!Number.isFinite(data) || (data ?? 0) <= 0) {
      setDisplayed(0);
      return;
    }
    let start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      setDisplayed(Math.round(easeOutCubic(t) * (data as number)));
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
    };
    setDisplayed(0);
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [data, duration]);
  const formatted = useMemo(
    () => new Intl.NumberFormat().format(displayed),
    [displayed]
  );
  return (
    <Box
      sx={{
        backgroundColor: "rgba(255, 255, 255, 0.05)",
        borderRadius: "12px",
        py: "15px",
        px: "20px",
        textAlign: "left",
        minWidth: 170,
        maxWidth: 320,
        border: "1px solid rgba(255, 255, 255, 0.08)",
      }}
    >
      <Typography
        sx={{ fontSize: 16, fontWeight: 400, color: "#A1A1AA", mb: 1 }}
      >
        {title}
      </Typography>
      <Typography sx={{ fontSize: 20, fontWeight: 800, color: "#FFFFFF" }}>
        {loading? <Skeleton/> : <span>{formatted} {unit}</span>}
      </Typography>
    </Box>
  );
};

/* ---------- Styles ---------- */
const dropdownStyles = {
  minWidth: "110px",
  color: "#FFFFFF",
  borderRadius: "10px",
  height: "40px",
  fontSize: "14px",
  "& .MuiOutlinedInput-notchedOutline": {
    border: "none",
    borderBottom: "1px solid rgba(255, 255, 255, 0.5)",
    transition: "border-color 0.3s ease",
  },
  "&:hover .MuiOutlinedInput-notchedOutline": {
    border: "none",
    borderBottom: "1px solid #FFFFFF",
  },
  "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
    border: "none",
    borderBottom: "1px solid #FFFFFF",
  },
  "& .MuiSelect-icon": { color: "#9AA0A6", transition: "color 0.3s ease" },
} as const;

const dropdownMenuStyles = {
  PaperProps: {
    sx: {
      backgroundColor: "rgb(22, 27, 33)",
      color: "#FFFFFF",
      borderRadius: "10px",
      border: "none",
      borderBottom: "1px solid #FFFFFF",
      mt: "5px",
      "& .MuiMenuItem-root": {
        fontSize: "14px",
        transition: "background-color 0.3s ease",
        "&:hover": { backgroundColor: "rgba(255,255,255,0.1)" },
        "&.Mui-selected": {
          backgroundColor: "rgba(255,255,255,0.15)",
          "&:hover": { backgroundColor: "rgba(255,255,255,0.2)" },
        },
      },
    },
  },
} as const;

const SearchContainer = styled(Box)({
  position: "relative",
  zIndex: 1,
  width: "100%",
  maxWidth: "900px",
  margin: "0 auto",
});

const CustomCheckbox = styled(MuiCheckbox)({
  color: "#9AA0A6",
  padding: "8px",
  "&.Mui-checked": { color: "#eb5058ff" },
  "& .MuiSvgIcon-root": { fontSize: "20px" },
});


/* ----------- GET based API Hooks ---------*/
const useGetScannedUrl = () => {
  const [scannedUrlData, setScannedUrlData] = useState<any>([]);
  const [scannedUrlLoading, setScannedUrlLoading] = useState(false);

  const fetchScannedUrlData = useCallback(async ()=>  {
      setScannedUrlLoading(true)
    try{
      const response = await http.get(URLS_SCANNED)
      setScannedUrlData(response?.data || [])
    } catch(error) {
      toast.error('Error Fetching Count Of Scanned URLs')
      console.error('Error Fetching Count Of Scanned URLs', error)
    }finally {
      setScannedUrlLoading(false)
    }
  },[])
  useEffect(()=>{
    fetchScannedUrlData()
  },[fetchScannedUrlData])

  return {scannedUrlData, scannedUrlLoading, refetch: fetchScannedUrlData}
}

const useGetMonitoringUrl = () => {
  const [monitoringUrlData, setMonitoringUrlData] = useState<any>([]);
  const [monitoringUrlLoading, setMonitoringUrlLoading] = useState(false);

  const fetchMonitoringUrlData = useCallback(async ()=>  {
      setMonitoringUrlLoading(true)
    try{
      const response = await http.get(MONITORING_URL)
      setMonitoringUrlData(response?.data || [])
    } catch(error) {
      toast.error('Error Fetching Count Of Monitoring URLs')
      console.error('Error Fetching Count Of Monitoring URLs', error)
    }finally {
      setMonitoringUrlLoading(false)
    }
  },[])
  useEffect(()=>{
    fetchMonitoringUrlData()
  },[fetchMonitoringUrlData])

  return {monitoringUrlData, monitoringUrlLoading, refetch: fetchMonitoringUrlData}
}

/* ---------- Page ---------- */
const URLDetection = () => {
  // text input OR csv file
  const [inputText, setInputText] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [isLookalike, setIsLookAlike] = useState(false);

  const {scannedUrlData, scannedUrlLoading} = useGetScannedUrl();
  const {monitoringUrlData, monitoringUrlLoading} = useGetMonitoringUrl();

  /* ---------- Submit API Hook ---------- */
  const handleSubmit = async (inputUrl?: string, isLookalike?: boolean) => {
    const urlToSubmit = inputUrl;

    const payload = {
      url: urlToSubmit,
      cse_id: "URL from user",
      notes: "User input",
      use_full_pipeline: isLookalike || false,
    };

    try {
      const resp = await http.post(SUBMIT_URL, payload);

      if (resp.status === 200) {
        toast.success("Submitted successfully");
        setInputText("");
        clearFile();
      }
    } catch (err: any) {
      console.error("Submit failed:", err);

      const message =
        err?.response?.data?.error || err.message || "Submission failed";
      toast.error(message);
    } finally {
      setIsLookAlike(false);
    }
  };

  const handleBulkSubmit = async (file: File, isLookalike?: boolean) => {
    Papa.parse(file, {
      header: false,
      skipEmptyLines: true,
      complete: async (results) => {
        try {
          // Extract URLs from CSV (first column of each row)
          const urls = results.data
            .map((row: any) => {
              const url = row[0];
              return url ? String(url).trim() : null;
            })
            .filter((url): url is string => !!url && url.length > 0);

          if (urls.length === 0) {
            toast.error("No valid URLs found in CSV.");
            return;
          }

          const payload = {
            urls: urls,
            use_full_pipeline: isLookalike || false,
            cse_id: "BULK_IMPORT",
            notes: "CSV import from security report",
          };

          const resp = await http.post(BULK_SUBMIT, payload);

          if (resp.status === 200) {
            toast.success(`Successfully submitted ${urls.length} URLs`);
            setInputText("");
            clearFile();
          }
        } catch (err: any) {
          console.error("Submit failed:", err);
          const message =
            err?.response?.data?.error || err.message || "Submission failed";
          toast.error(message);
        } finally {
          setIsLookAlike(false);
        }
      },
      error: (error) => {
        console.error("CSV parsing error:", error);
        toast.error("Failed to parse CSV file");
        setIsLookAlike(false);
      },
    });
  };

  const handleAttachFile = () => fileInputRef.current?.click();

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) {
      toast.info("Please select a .csv file");
      e.target.value = "";
      return;
    }
    setSelectedFile(file);
  };

  const clearFile = () => {
    setSelectedFile(null);
    setInputText("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && (inputText.trim().length > 0 || selectedFile)) {
      e.preventDefault();
      if (selectedFile) {
        handleBulkSubmit(selectedFile, isLookalike);
      } else {
        handleSubmit(inputText, isLookalike);
      }
    }
  };

  const inputValue = selectedFile
    ? `Selected File: ${selectedFile.name}`
    : inputText;

  const handleDurationChange = (event: any) =>
    console.log("Duration changed:", event.target.value);

  const handlePriorityChange = (event: any) =>
    console.log("Priority changed:", event.target.value);

  return (
    <>
      <Container maxWidth="lg" sx={{ position: "relative", zIndex: 1, py: 6 }}>
        {/* KPI Cards */}
        <Box
          sx={{
            display: "flex",
            gap: 3,
            flexWrap: "wrap",
            justifyContent: "center",
          }}
        >
          <KPICard title="URLs Scanned" data={scannedUrlData?.rowCount} loading={scannedUrlLoading}/>
          <KPICard title="Average Risk Score" data={44} unit="%" loading={scannedUrlLoading}/>
          <KPICard title="Active Watchlist" data={monitoringUrlData?.summary?.total_monitoring} loading={monitoringUrlLoading}/>
        </Box>

        {/* World Map + Search */}
        <Box
          sx={{
            position: "relative",
            minHeight: "500px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            px: 2,
          }}
        >
          <Box
            component="img"
            src="/WorldMap.svg"
            alt="World map"
            aria-hidden
            loading="eager"
            sx={{
              width: "65%",
              maxWidth: 980,
              height: "auto",
              opacity: 0.9,
              pointerEvents: "none",
              userSelect: "none",
              filter: "drop-shadow(0 8px 24px rgba(0,0,0,0.35))",
            }}
          />

          {/* Search Input + File */}
          <SearchContainer>
            <input
              type="file"
              accept=".csv,text/csv"
              ref={fileInputRef}
              hidden
              onChange={handleFileChange}
            />

            <TextField
              fullWidth
              placeholder="Analyze URL authenticity and potential threats"
              variant="outlined"
              value={inputValue}
              onChange={(e) => {
                // ignore typing while a file is selected (readOnly also prevents this)
                if (!selectedFile) setInputText(e.target.value);
              }}
              onKeyDown={handleKeyDown}
              InputProps={{
                readOnly: !!selectedFile, // disables typing while showing the file name
                startAdornment: (
                  <InputAdornment position="start">
                    <Search sx={{ color: "#9AA0A6" }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    {selectedFile || inputText ? (
                      <>
                        <IconButton
                          aria-label="clear file"
                          onClick={clearFile}
                          size="small"
                          sx={{ mr: 0.5 }}
                        >
                          <Close sx={{ color: "#9AA0A6" }} fontSize="small" />
                        </IconButton>
                        <IconButton
                          aria-label="submit"
                          onClick={() => {
                            if (selectedFile) {
                              handleBulkSubmit(selectedFile, isLookalike);
                            } else {
                              handleSubmit(inputText, isLookalike);
                            }
                          }}
                          size="small"
                        >
                          <Send sx={{ color: "#9AA0A6" }} fontSize="small" />
                        </IconButton>
                      </>
                    ) : inputText.trim().length > 0 ? (
                      <IconButton
                        aria-label="submit"
                        onClick={() => {
                          handleSubmit(inputText, isLookalike);
                        }}
                        size="small"
                      >
                        <Send sx={{ color: "#9AA0A6" }} fontSize="small" />
                      </IconButton>
                    ) : (
                      <IconButton
                        aria-label="attach csv"
                        onClick={handleAttachFile}
                        size="small"
                      >
                        <AttachFile
                          sx={{ color: "#9AA0A6" }}
                          fontSize="small"
                        />
                      </IconButton>
                    )}
                  </InputAdornment>
                ),
              }}
              sx={{
                "& .MuiOutlinedInput-root": {
                  backgroundColor: "rgba(255, 255, 255, 0.05)",
                  borderRadius: "12px",
                  color: "#FFFFFF",
                  fontSize: "15px",
                  "& fieldset": { borderColor: "rgba(255, 255, 255, 0.1)" },
                  "&:hover fieldset": {
                    borderColor: "rgba(255, 255, 255, 0.2)",
                  },
                  "&.Mui-focused fieldset": { borderColor: "#D71818" },
                  // make caret invisible when readOnly (file selected)
                  "& input.MuiInputBase-input.MuiOutlinedInput-input": {
                    caretColor: selectedFile ? "transparent" : "auto",
                  },
                },
                "& .MuiOutlinedInput-input::placeholder": {
                  color: "#E2333999",
                  opacity: 1,
                },
              }}
            />

            {/* Checkboxes and Dropdowns */}
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: 2,
                mt: 3,
              }}
            >
              {/* Left - Checkboxes */}
              <Box sx={{ display: "flex", gap: 3 }}>
                <FormControlLabel
                  control={
                    <CustomCheckbox
                      checked={isLookalike}
                      onChange={(e) => {
                        setIsLookAlike(e.target.checked);
                      }}
                    />
                  }
                  label={
                    <Typography
                      sx={{
                        color: "#FFFFFF",
                        fontWeight: 500,
                        fontSize: "15px",
                      }}
                    >
                      Lookalike
                    </Typography>
                  }
                />
              </Box>

              {/* Right - Dropdowns */}
              {/* <Box sx={{ display: "flex", gap: 2 }}>
                <Select
                  defaultValue="duration"
                  onChange={handleDurationChange}
                  sx={dropdownStyles}
                  MenuProps={dropdownMenuStyles}
                >
                  <MenuItem value="duration">Duration</MenuItem>
                  <MenuItem value="1h">1 Hour</MenuItem>
                  <MenuItem value="24h">24 Hours</MenuItem>
                  <MenuItem value="7d">7 Days</MenuItem>
                </Select>
                <Select
                  defaultValue="priority"
                  onChange={handlePriorityChange}
                  sx={dropdownStyles}
                  MenuProps={dropdownMenuStyles}
                >
                  <MenuItem value="priority">Priority</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                </Select>
              </Box> */}
            </Box>
          </SearchContainer>
        </Box>
      </Container>
    </>
  );
};

export default URLDetection;
