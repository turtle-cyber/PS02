import { createTheme } from '@mui/material/styles';

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#D71818',
      light: '#E31F1F',
      dark: '#B70B0B',
    },
    background: {
      default: '#0B0F11',
      paper: '#0F1315',
    },
    text: {
      primary: '#FFFFFF',
      secondary: '#9AA0A6',
    },
  },
  typography: {
    fontFamily: 'SF Pro Display, -apple-system, BlinkMacSystemFont, sans-serif',
    h1: {
      fontWeight: 600,
      fontSize: 'clamp(42px, 6vw, 96px)',
      lineHeight: 1.1,
      color: '#FFFFFF',
    },
    h2: {
      fontWeight: 600,
      fontSize: 'clamp(24px, 4vw, 48px)',
      lineHeight: 1.2,
    },
    subtitle1: {
      fontWeight: 400,
      fontSize: '18px',
      lineHeight: 1.6,
      color: '#9AA0A6',
    },
    button: {
      fontWeight: 500,
      textTransform: 'none',
      fontSize: '16px',
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '999px',
          padding: '14px 36px',
          transition: 'all 220ms ease',
          '&:hover': {
            transform: 'scale(1.02)',
          },
        },
        contained: {
          background: 'linear-gradient(135deg, #E31F1F 0%, #B70B0B 100%)',
          boxShadow: '0 6px 20px rgba(215, 24, 24, 0.18), inset 0 4px 12px rgba(0, 0, 0, 0.45), inset 0 -6px 24px rgba(255, 255, 255, 0.02)',
          '&:hover': {
            background: 'linear-gradient(135deg, #E31F1F 0%, #B70B0B 100%)',
            boxShadow: '0 8px 28px rgba(215, 24, 24, 0.28), inset 0 4px 12px rgba(0, 0, 0, 0.45), inset 0 -6px 24px rgba(255, 255, 255, 0.02)',
          },
        },
        outlined: {
          border: '2px solid #B70B0B',
          backgroundColor: 'transparent',
          color: '#FFFFFF',
          boxShadow: '0 8px 20px rgba(183, 11, 11, 0.06)',
          '&:hover': {
            border: '2px solid #E31F1F',
            backgroundColor: 'rgba(215, 24, 24, 0.05)',
            boxShadow: '0 12px 28px rgba(183, 11, 11, 0.12)',
          },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#0B0F11',
          boxShadow: 'inset 0 -1px 0 rgba(255, 255, 255, 0.02)',
        },
      },
    },
  },
});
