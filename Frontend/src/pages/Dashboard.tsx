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
import {
  GET_DOMAINS,
  GET_ORIGINATING_COUNTRIES,
  GET_OVERVIEW,
  GET_PARKED_INSIGHTS,
  GET_URL_INSIGHTS,
  GET_URL_WATCH_GRAPH,
} from "@/endpoints/dashboard.endpoints";

const useGetUrlInsightsData = () => {
  const [urlInsightsData, setUrlInsightsData] = useState<any>({});
  const [urlInsightsLoading, setUrlInsightsLoading] = useState(false);

  const fetchUrlInsights = useCallback(async () => {
    setUrlInsightsLoading(true);
    try {
      const response = await http.get(GET_URL_INSIGHTS);
      setUrlInsightsData(response?.data || {});
    } catch (error) {
      toast.error("Error Fetching URL Insight Data");
      console.error("Error Fetching URL Insight Data with error: ", error);
    } finally {
      setUrlInsightsLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchUrlInsights();
  }, [fetchUrlInsights]);

  return { urlInsightsData, urlInsightsLoading, refetch: fetchUrlInsights };
};

const useGetOriginatingCountries = () => {
  const [countriesData, setCountriesData] = useState([]);
  const [countriesLoading, setCountriesLoading] = useState(false);

  const fetchCountries = useCallback(async () => {
    setCountriesLoading(true);
    try {
      const response = await http.get(GET_ORIGINATING_COUNTRIES);

      setCountriesData(response?.data?.data || []);
    } catch (error) {
      toast.error("Error Fetching URL Insight Data");
      console.error("Error Fetching URL Insight Data with error: ", error);
    } finally {
      setCountriesLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchCountries();
  }, [fetchCountries]);

  return { countriesData, countriesLoading, refetch: fetchCountries };
};

const useGetUrlWatch = () => {
  const [urlWatchData, setUrlWatchData] = useState([]);
  const [urlWatchLoading, setUrlWatchLoading] = useState(false);

  const fetchUrlWatch = useCallback(async () => {
    setUrlWatchLoading(true);
    try {
      const response = await http.get(GET_URL_WATCH_GRAPH);

      setUrlWatchData(response?.data?.series || []);
    } catch (error) {
      toast.error("Error Fetching URL Insight Data");
      console.error("Error Fetching URL Insight Data with error: ", error);
    } finally {
      setUrlWatchLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchUrlWatch();
  }, [fetchUrlWatch]);

  return { urlWatchData, urlWatchLoading, refetch: fetchUrlWatch };
};

const useGetParkedInsight = () => {
  const [parkedInsightData, setParkedInsightData] = useState([]);
  const [parkedInsightLoading, setParkedInsightLoading] = useState(false);

  const fetchParkedInsight = useCallback(async () => {
    setParkedInsightLoading(true);
    try {
      const response = await http.get(GET_PARKED_INSIGHTS);

      setParkedInsightData(response?.data?.data || []);
    } catch (error) {
      console.error("Error Fetching Parked Insight Data with error: ", error);
    } finally {
      setParkedInsightLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchParkedInsight();
  }, [fetchParkedInsight]);

  return {
    parkedInsightData,
    parkedInsightLoading,
    refetch: fetchParkedInsight,
  };
};

const useGetOverview = () => {
  const [overviewData, setOverviewData] = useState([]);
  const [overviewLoading, setOverviewLoading] = useState(false);

  const fetchOverview = useCallback(async () => {
    setOverviewLoading(true);
    try {
      const response = await http.get(GET_OVERVIEW);
      setOverviewData(response?.data?.overview || []);
    } catch (error) {
      console.error("Error Fetching Overview Data with error: ", error);
    } finally {
      setOverviewLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchOverview();
  }, [fetchOverview]);

  return {
    overviewData,
    overviewLoading,
    refetch: fetchOverview,
  };
};

const useGetDomains = () => {
  const [domainsData, setDomainsData] = useState({});
  const [domainsLoading, setDomainsLoading] = useState(false);

  const fetchDomains = useCallback(async () => {
    setDomainsLoading(true);
    try {
      const response = await http.get(GET_DOMAINS);
      setDomainsData(response?.data?.domains || {});
    } catch (error) {
      console.error("Error Fetching Domain Data with error: ", error);
    } finally {
      setDomainsLoading(false);
    }
  }, []);
  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  return {
    domainsData,
    domainsLoading,
    refetch: fetchDomains,
  };
};

const Dashboard = () => {
  const location = useLocation();
  const [reportsAnchorEl, setReportsAnchorEl] = useState<null | HTMLElement>(
    null
  );
  const reportsOpen = Boolean(reportsAnchorEl);

  const handleReportsClick = (event: React.MouseEvent<HTMLElement>) => {
    setReportsAnchorEl(event?.currentTarget);
  };

  const handleReportsClose = () => {
    setReportsAnchorEl(null);
  };

  /*------ API Data Unpacking ------*/
  const { urlInsightsData, urlInsightsLoading } = useGetUrlInsightsData();
  const { countriesData, countriesLoading } = useGetOriginatingCountries();
  const { urlWatchData, urlWatchLoading } = useGetUrlWatch();
  const { parkedInsightData, parkedInsightLoading } = useGetParkedInsight();
  const { overviewData, overviewLoading } = useGetOverview();
  const { domainsData, domainsLoading } = useGetDomains();

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
            <OverviewCards
              data={overviewData || {}}
              loading={overviewLoading}
            />
          </div>
          <div className="xl:col-span-8">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              URL watch
            </Typography>
            <UrlWatchArea series={urlWatchData} />
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
            <DomainsCard data={domainsData || {}} loading={domainsLoading} />
          </div>
          <div className="xl:col-span-4">
            <Typography
              variant="h6"
              sx={{ color: "#EEEEEE", fontWeight: 600, mb: 3 }}
            >
              Originating Countries
            </Typography>
            <OriginCountriesMap
              data={countriesData}
              loading={countriesLoading}
            />
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
            <ParkedInsightsTable
              rows={parkedInsightData}
              loading={parkedInsightLoading}
            />
          </div>
        </div>
      </Container>
    </Box>
  );
};

export default Dashboard;
