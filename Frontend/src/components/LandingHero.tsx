import {
  Box,
  Container,
  Typography,
  Button,
  AppBar,
  Toolbar,
  styled,
} from "@mui/material";
import { Link, NavLink, useLocation } from "react-router-dom";
import * as React from "react";

const HeroBackground = styled(Box)({
  position: "relative",
  minHeight: "100vh",
  overflow: "hidden",
  "&::before": {
    content: '""',
    position: "absolute",
    width: "800px",
    height: "800px",
    borderRadius: "50%",
    background:
      "radial-gradient(circle, rgba(215, 24, 24, 0.15) 0%, rgba(215, 24, 24, 0.05) 40%, transparent 70%)",
    top: "-200px",
    left: "-300px",
    filter: "blur(80px)",
    pointerEvents: "none",
  },
  "&::after": {
    content: '""',
    position: "absolute",
    width: "900px",
    height: "900px",
    borderRadius: "50%",
    top: "-100px",
    right: "-400px",
    filter: "blur(100px)",
    pointerEvents: "none",
  },
});

const FeatureCard = styled(Box)({
  position: "relative",
  width: "100%",
  maxWidth: "260px",
  height: "360px",
  borderRadius: "20px",
  border: "1px solid rgba(255, 40, 40, 0.2)",
  boxShadow:
    "0 8px 20px rgba(215, 24, 24, 0.12), 0 0 18px rgba(215, 24, 24, 0.14), inset 0 1px 0 rgba(255, 40, 40, 0.1)",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "space-between",
  transition: "transform 220ms ease, box-shadow 220ms ease",
  overflow: "hidden",
  "&:hover": {
    transform: "translateY(-8px)",
    boxShadow:
      "0 12px 32px rgba(215, 24, 24, 0.18), 0 0 24px rgba(215, 24, 24, 0.18)",
  },
  "&::before": {
    content: '""',
    position: "absolute",
    top: 0,
    right: 0,
    width: "60%",
    height: "40%",
    background:
      "linear-gradient(135deg, rgba(255, 40, 40, 0.15) 0%, transparent 100%)",
    borderRadius: "0 20px 0 100%",
    pointerEvents: "none",
  },
});

const LandingHero = () => {
  const location = useLocation();
  const [reportsAnchorEl, setReportsAnchorEl] =
    React.useState<null | HTMLElement>(null);
  const reportsOpen = Boolean(reportsAnchorEl);

  const handleReportsClick = (event: React.MouseEvent<HTMLElement>) => {
    setReportsAnchorEl(event.currentTarget);
  };

  const handleReportsClose = () => {
    setReportsAnchorEl(null);
  };

  return (
    <>
      {/* Hero Section */}
      <Container
        maxWidth="lg"
        sx={{
          position: "relative",
          zIndex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "calc(100vh - 200px)",
          textAlign: "center",
          py: 8,
        }}
      >
        <Typography
          variant="h2"
          sx={{
            maxWidth: "1100px",
            mb: 2,
            px: 2,
          }}
        >
          Actionable phishing intelligence for India's critical sectors.
        </Typography>

        <Typography
          variant="subtitle1"
          sx={{
            maxWidth: "720px",
            mb: 4,
            px: 2,
            fontSize: { xs: "16px", md: "18px" },
          }}
        >
          We crawl the Indian cyber landscape, analyze suspicious and typosquat
          domains with AI, and monitor critical-sector URLs for 3 months — so
          your org sees threats first.
        </Typography>

        <Box
          sx={{
            display: "flex",
            gap: 3,
            flexWrap: "wrap",
            justifyContent: "center",
            mb: 8,
          }}
        >
          <Button
            component={NavLink}
            to="/url-detection"
            variant="contained"
            size="large"
          >
            Submit URL
          </Button>
          <Button
            component={NavLink}
            to="/dashboard"
            variant="outlined"
            size="large"
          >
            Dashboard
          </Button>
        </Box>

        {/* Feature Cards */}
        <Box
          sx={{
            display: "flex",
            gap: { xs: 3, md: 6 },
            flexWrap: "wrap",
            justifyContent: "center",
            mt: 2,
          }}
        >
          <FeatureCard>
            <Box sx={{ width: "100%", height: "100%" }}>
              <img
                src="Card.svg"
                style={{
                  width: "100%",
                  height: "100%",
                  display: "block",
                  objectFit: "cover",
                }}
              />
            </Box>
          </FeatureCard>

          <FeatureCard>
            <Box sx={{ width: "100%", height: "100%" }}>
              <img
                src="Card2.svg"
                style={{
                  width: "100%",
                  height: "100%",
                  display: "block",
                  objectFit: "cover",
                }}
              />
            </Box>
          </FeatureCard>

          <FeatureCard>
            <Box sx={{ width: "100%", height: "100%" }}>
              <img
                src="Card3.svg"
                style={{
                  width: "100%",
                  height: "100%",
                  display: "block",
                  objectFit: "cover",
                }}
              />
            </Box>
          </FeatureCard>
        </Box>
      </Container>
    </>
  );
};

export default LandingHero;
