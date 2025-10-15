import * as React from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  AppBar,
  Toolbar,
  Box,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Divider,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import MenuIcon from "@mui/icons-material/Menu";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CloseIcon from "@mui/icons-material/Close";

/* Icons */
import HomeRounded from "@mui/icons-material/HomeRounded";
import LinkRounded from "@mui/icons-material/LinkRounded";
import SensorsRounded from "@mui/icons-material/SensorsRounded";
import DashboardRounded from "@mui/icons-material/DashboardRounded";
import AssessmentRounded from "@mui/icons-material/AssessmentRounded"; // <-- Reports icon
import { Assignment } from "@mui/icons-material";

const NAV_HEIGHT = 64;

/* Links with icons */
const links: { label: string; to: string; icon: React.ReactNode }[] = [
  { label: "Home", to: "/", icon: <HomeRounded fontSize="small" /> },
  {
    label: "URL Detection",
    to: "/url-detection",
    icon: <LinkRounded fontSize="small" />,
  },
  {
    label: "Live Monitoring",
    to: "/live-monitoring",
    icon: <SensorsRounded fontSize="small" />,
  },
  {
    label: "Dashboard",
    to: "/dashboard",
    icon: <DashboardRounded fontSize="small" />,
  },
];

const reportItems = [
  { label: "URL Reports", to: "/reports/url" },
  { label: "Lookalikes", to: "/reports/lookalikes" },
];

function NavButton({
  to,
  label,
  active,
  icon,
  onClick,
}: {
  to?: string;
  label: string;
  active?: boolean;
  icon?: React.ReactNode;
  onClick?: () => void;
}) {
  const sx = {
    px: 2,
    py: 1,
    borderRadius: 1,
    opacity: 0.9,
    textTransform: "none" as const,
    fontWeight: 500,
    "&:hover": { opacity: 1, backgroundColor: "rgba(20,24,31,1)" },
    position: "relative" as const,
    ...(active
      ? {
          color: "primary.main",
          "&::after": {
            content: '""',
            position: "absolute" as const,
            left: 10,
            right: 10,
            bottom: 4,
            height: 2,
            borderRadius: 2,
            background: "#C10007",
          },
        }
      : {}),
  };

  const common = { color: "inherit" as const, startIcon: icon, sx };

  return to ? (
    <Button component={NavLink} to={to} {...common}>
      {label}
    </Button>
  ) : (
    <Button {...common} onClick={onClick}>
      {label}
    </Button>
  );
}

export default function TopNav() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const [mobileOpen, setMobileOpen] = React.useState(false);

  // Reports hover menu state
  const [reportsAnchor, setReportsAnchor] = React.useState<null | HTMLElement>(
    null
  );
  const reportsOpen = Boolean(reportsAnchor);
  const openReports = (e: React.MouseEvent<HTMLElement>) =>
    setReportsAnchor(e.currentTarget);
  const closeReports = () => setReportsAnchor(null);

  const isActive = (to: string) =>
    pathname === to || (to !== "/" && pathname.startsWith(to));
  const isReportsActive = pathname.startsWith("/reports");

  return (
    <AppBar
      position="sticky"
      elevation={0}
      sx={{
        height: NAV_HEIGHT,
        justifyContent: "space-between",
        backgroundColor: "#0B0F11",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        boxShadow: "inset 0 -1px 0 rgba(255,255,255,0.04)",
      }}
    >
      <Toolbar sx={{ minHeight: NAV_HEIGHT, px: { xs: 2, lg: 3 } }}>
        {/* Left: Logo */}
        <Box
          onClick={() => navigate("/")}
          sx={{
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            mr: 2,
          }}
        >
          <Box
            component="img"
            src="/logo.svg"
            alt="Turtleneck logo"
            sx={{ width: 160, display: "block" }}
          />
        </Box>

        <Box sx={{ flex: 1 }} />

        {/* Right actions */}
        {!isMobile && (
          <Box sx={{ gap: 3, display: "flex" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              {links.map((l) => (
                <NavButton
                  key={l.to}
                  to={l.to}
                  label={l.label}
                  icon={l.icon}
                  active={isActive(l.to)}
                />
              ))}

              {/* Reports (hover) with icon */}
              <Box
                onMouseEnter={openReports}
                onMouseLeave={closeReports}
                sx={{ display: "flex", alignItems: "center" }}
              >
                <NavButton
                  label="Reports"
                  active={isReportsActive}
                  icon={<Assignment fontSize="small" />} // <-- added
                />
                <ExpandMoreIcon
                  fontSize="small"
                  sx={{
                    ml: -1,
                    color: isReportsActive ? "primary.main" : "inherit",
                  }}
                />
                <Menu
                  anchorEl={reportsAnchor}
                  open={reportsOpen}
                  onClose={closeReports}
                  MenuListProps={{
                    onMouseLeave: closeReports,
                    sx: { py: 0.5, minWidth: 200 },
                  }}
                  slotProps={{
                    paper: {
                      sx: {
                        mt: 1,
                        borderRadius: 2,
                        border: "1px solid rgba(255,255,255,0.08)",
                        background: "rgba(15, 19, 21, 0.98)",
                        backdropFilter: "blur(8px)",
                      },
                    },
                  }}
                >
                  {reportItems.map((item) => (
                    <MenuItem
                      key={item.to}
                      component={NavLink}
                      to={item.to}
                      onClick={closeReports}
                      sx={{
                        py: 1,
                        gap: 1,
                        ...(isActive(item.to)
                          ? { color: "primary.main", fontWeight: 600 }
                          : {}),
                      }}
                    >
                      {item.label}
                    </MenuItem>
                  ))}
                </Menu>
              </Box>
            </Box>

            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              <Button
                variant="outlined"
                color="inherit"
                component={NavLink}
                to="/signup"
                sx={{
                  textTransform: "none",
                  borderColor: "rgba(255,255,255,0.22)",
                  py: 1,
                  px: 2,
                  height: 40,
                  width: 100,
                }}
              >
                Sign Up
              </Button>
              <Button
                variant="contained"
                color="primary"
                component={NavLink}
                to="/login"
                sx={{
                  textTransform: "none",
                  py: 1,
                  px: 2,
                  height: 40,
                  width: 100,
                }}
              >
                Login
              </Button>
            </Box>
          </Box>
        )}

        {/* Mobile hamburger */}
        {isMobile && (
          <IconButton color="inherit" onClick={() => setMobileOpen((v) => !v)}>
            {mobileOpen ? <CloseIcon /> : <MenuIcon />}
          </IconButton>
        )}
      </Toolbar>

      {/* Mobile menu body */}
      {isMobile && mobileOpen && (
        <Box
          sx={{
            px: 2,
            pb: 2,
            pt: 1,
            display: "grid",
            gap: 0.5,
            backgroundColor: "#0B0F11",
            borderTop: "1px solid rgba(255,255,255,0.06)",
          }}
        >
          {links.map((l) => (
            <Button
              key={l.to}
              component={NavLink}
              to={l.to}
              color="inherit"
              startIcon={l.icon}
              sx={{
                justifyContent: "flex-start",
                textTransform: "none",
                ...(isActive(l.to)
                  ? { color: "primary.main", fontWeight: 600 }
                  : {}),
              }}
              onClick={() => setMobileOpen(false)}
            >
              {l.label}
            </Button>
          ))}

          <Divider sx={{ my: 0.5, borderColor: "rgba(255,255,255,0.06)" }} />

          {/* Mobile Reports header with icon */}
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 1,
              px: 1.25,
              opacity: 0.9,
            }}
          >
            <AssessmentRounded fontSize="small" />
            <Typography variant="caption">Reports</Typography>
          </Box>

          {reportItems.map((r) => (
            <Button
              key={r.to}
              component={NavLink}
              to={r.to}
              color="inherit"
              sx={{
                justifyContent: "flex-start",
                textTransform: "none",
                ...(isActive(r.to)
                  ? { color: "primary.main", fontWeight: 600 }
                  : {}),
              }}
              onClick={() => setMobileOpen(false)}
            >
              {r.label}
            </Button>
          ))}

          <Divider sx={{ my: 0.5, borderColor: "rgba(255,255,255,0.06)" }} />

          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              variant="outlined"
              color="inherit"
              component={NavLink}
              to="/signup"
              sx={{ textTransform: "none", flex: 1 }}
              onClick={() => setMobileOpen(false)}
            >
              Sign Up
            </Button>
            <Button
              variant="contained"
              color="primary"
              component={NavLink}
              to="/login"
              sx={{ textTransform: "none", flex: 1, borderRadius: "999px" }}
              onClick={() => setMobileOpen(false)}
            >
              Login
            </Button>
          </Box>
        </Box>
      )}
    </AppBar>
  );
}
