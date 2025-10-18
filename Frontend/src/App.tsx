import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { theme } from "./theme/muiTheme";
import Index from "./pages/Index";
import URLDetection from "./pages/URLDetection";
import LiveMonitoring from "./pages/LiveMonitoring";
import Dashboard from "./pages/Dashboard";
import UrlReportsPage from "./pages/reports/url";
import LookalikesPage from "./pages/reports/lookalikes";
import UrlDetailPage from "./pages/reports/url/detail";
import LookalikeDetailPage from "./pages/reports/lookalikes/detail";
import NotFound from "./pages/NotFound";
import TopNav from "./pages/TopNav";

const queryClient = new QueryClient();

const App = () => (
  <ThemeProvider theme={theme}>
    <CssBaseline />
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <div
          style={{
            backgroundImage: "url('/Background.png')",
            backgroundSize: "cover",
            backgroundPosition: "center",
            backgroundAttachment: "fixed",
            backgroundRepeat: "no-repeat",
            minHeight: "100vh",
            // width: '100%'
          }}
        >
          <BrowserRouter>
            <TopNav />
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/url-detection" element={<URLDetection />} />
              <Route path="/live-monitoring" element={<LiveMonitoring />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/reports/url" element={<UrlReportsPage />} />
              <Route path="/reports/lookalikes" element={<LookalikesPage />} />
              <Route
                path="/reports/url/detail/:id"
                element={<UrlDetailPage />}
              />
              <Route
                path="/reports/lookalikes/detail"
                element={<LookalikeDetailPage />}
              />
              {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  </ThemeProvider>
);

export default App;
