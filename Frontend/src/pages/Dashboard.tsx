
import {
  Box,
  AppBar,
  Toolbar,
  Container,
  Typography,
  Button,
  Menu,
  MenuItem,
} from "@mui/material";

import { KeyboardArrowDown } from "@mui/icons-material";
import { Link, useLocation } from "react-router-dom";
import { styled } from "@mui/material/styles";
import { mockDashboard } from "@/data/mockDashboard";
import { OverviewCards } from "@/components/dashboard/OverviewCards";
import { DomainsCard } from "@/components/dashboard/DomainsCard";
import { UrlWatchArea } from "@/components/dashboard/UrlWatchArea";
import { OriginCountriesMap } from "@/components/dashboard/OriginCountriesMap";
import { UrlInsightsTable } from "@/components/dashboard/UrlInsightsTable";
import { ThreatLandscapeBar } from "@/components/dashboard/ThreatLandscapeBar";
import { TopCseByRisk } from "@/components/dashboard/TopCseByRisk";
import { ParkedInsightsTable } from "@/components/dashboard/ParkedInsightsTable";
import { MonthRangePicker } from "@/components/dashboard/MonthRangePicker";
import { useCallback, useEffect, useState } from "react";
import { http } from "@/hooks/config";
import { toast } from "sonner";
import { GET_URL_INSIGHTS } from "@/endpoints/dashboard.endpoints";

const NavLink = styled(Typography)<{ active?: boolean }>(({ active }) => ({
  color: active ? "#E50914" : "#FFFFFF",
  textDecoration: "none",
  fontWeight: 500,
  fontSize: "14px",
  position: "relative",
  cursor: "pointer",
  transition: "all 0.3s ease",
  "&:hover": {
    color: "#E50914",
  },
  ...(active && {
    "&::after": {
      content: '""',
      position: "absolute",
      bottom: "-8px",
      left: 0,
      right: 0,
      height: "2px",
      background: "#E50914",
      boxShadow: "0 0 8px rgba(229, 9, 20, 0.6)",
    },
  }),
}));


const useGetUrlInsightsData = () => {
  const [urlInsightsData, setUrlInsightsData] = useState<any>({});
  const [urlInsightsLoading, setUrlInsightsLoading] = useState(false);

  const fetchUrlInsights = useCallback(async ()=>  {
      setUrlInsightsLoading(true)
    try{
      const response = await http.get(GET_URL_INSIGHTS)
      setUrlInsightsData(response?.data || {})
    } catch(error) {
      toast.error('Error Fetching URL Insight Data')
      console.error('Error Fetching URL Insight Data with error: ', error)
    }finally {
      setUrlInsightsLoading(false)
    }
  },[])
  useEffect(()=>{
    fetchUrlInsights()
  },[fetchUrlInsights])

  return {urlInsightsData, urlInsightsLoading, refetch: fetchUrlInsights}
}
const Dashboard = () => {
  const location = useLocation();
  const [reportsAnchorEl, setReportsAnchorEl] =
    useState<null | HTMLElement>(null);
  const reportsOpen = Boolean(reportsAnchorEl);

  const handleReportsClick = (event: React.MouseEvent<HTMLElement>) => {
    setReportsAnchorEl(event?.currentTarget);
  };

  const handleReportsClose = () => {
    setReportsAnchorEl(null);
  };

  /*------ API Data Unpacking ------*/
  const {urlInsightsData, urlInsightsLoading} = useGetUrlInsightsData();

  return (
    <Box
      sx={{
        minHeight: "100vh",
        position: "relative",
        "&::before": {
          content: '""',
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background:
            "radial-gradient(circle at 20% 80%, rgba(229, 9, 20, 0.1) 0%, transparent 50%)",
          pointerEvents: "none",
        },
      }}
    >
      {/* Main Content */}
      <Container
        maxWidth={false}
        sx={{ py: 6, position: "relative", zIndex: 1, px: 2, maxWidth: "98%" }}
      >
        {/* Month Range Picker */}
        <div className="flex justify-end mb-6">
          <MonthRangePicker range={mockDashboard.monthRange} />
        </div>

        {/* Top Grid: Overview, URL Watch, URL Insights */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 mb-6">
          <div className="xl:col-span-4">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              Overview
            </Typography>
            <OverviewCards totals={mockDashboard.totals} />
          </div>
          <div className="xl:col-span-8">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              URL watch
            </Typography>
            <UrlWatchArea series={mockDashboard.urlWatchSeries} />
          </div>
        </div>

        {/* Middle Row: Domains, Originating Countries */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 mb-6">
          <div className="xl:col-span-4">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              Domains
            </Typography>
            <DomainsCard domainsSummary={mockDashboard.domainsSummary} />
          </div>
          <div className="xl:col-span-4">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              Originating Countries
            </Typography>
            <OriginCountriesMap data={mockDashboard.originCountries} />
          </div>
          <div className="xl:col-span-4">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              URL Insights
            </Typography>
            <UrlInsightsTable rows={urlInsightsData?.table_data || []} />
          </div>
        </div>

        {/* Threat Landscape Bar */}
        <div className="mb-6">
          <ThreatLandscapeBar
            segments={mockDashboard.threatLandscapeSegments}
          />
        </div>

        {/* Bottom Row: Top CSE by Risk, Parked Insights */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          <div className="xl:col-span-6">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
            Top CSE By Risk
            </Typography>
            <TopCseByRisk data={mockDashboard.topCseByRisk} />
          </div>
          <div className="xl:col-span-6">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
            Parked Insights
            </Typography>
            <ParkedInsightsTable rows={mockDashboard.parkedInsightsRows} />
          </div>
        </div>
      </Container>
    </Box>
  );
};

export default Dashboard;
