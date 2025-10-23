import * as React from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from "react-simple-maps";

/** Full world TopoJSON from CDN */
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface GeoRippleMapProps {
  data: Array<{ name: string; value: [number, number, number] }>;
  height?: string;
}

/** Animated Ripple Marker Component */
const RippleMarker: React.FC<{
  coords: [number, number];
  name: string;
  info?: {
    city?: string;
    country?: string;
    isp?: string;
    asn?: string | number;
    ip?: string;
  };
}> = ({ coords, name, info }) => {
  const radius = 8;

  return (
    <Marker coordinates={coords}>
      {/* Animated ripple rings */}
      <circle
        r={radius}
        fill="none"
        stroke="rgba(229,9,20,0.6)"
        strokeWidth={2}
      >
        <animate
          attributeName="r"
          from={radius}
          to={radius * 2.5}
          dur="2s"
          begin="0s"
          repeatCount="indefinite"
        />
        <animate
          attributeName="opacity"
          from="0.8"
          to="0"
          dur="2s"
          begin="0s"
          repeatCount="indefinite"
        />
      </circle>

      <circle
        r={radius}
        fill="none"
        stroke="rgba(229,9,20,0.6)"
        strokeWidth={2}
      >
        <animate
          attributeName="r"
          from={radius}
          to={radius * 2.5}
          dur="2s"
          begin="0.7s"
          repeatCount="indefinite"
        />
        <animate
          attributeName="opacity"
          from="0.8"
          to="0"
          dur="2s"
          begin="0.7s"
          repeatCount="indefinite"
        />
      </circle>

      <circle
        r={radius}
        fill="none"
        stroke="rgba(229,9,20,0.6)"
        strokeWidth={2}
      >
        <animate
          attributeName="r"
          from={radius}
          to={radius * 2.5}
          dur="2s"
          begin="1.4s"
          repeatCount="indefinite"
        />
        <animate
          attributeName="opacity"
          from="0.8"
          to="0"
          dur="2s"
          begin="1.4s"
          repeatCount="indefinite"
        />
      </circle>

      {/* Main bubble */}
      <circle
        r={radius}
        fill="rgba(229,9,20,0.35)"
        stroke="rgba(229,9,20,0.7)"
        strokeWidth={2}
        style={{
          filter: "drop-shadow(0 0 12px rgba(229,9,20,0.6))",
          cursor: "pointer",
        }}
      />

      {/* Small core with pulse */}
      <circle r={3} fill="#E50914">
        <animate
          attributeName="r"
          values="3;5;3"
          dur="1.5s"
          repeatCount="indefinite"
        />
      </circle>

      {/* Enhanced Tooltip */}
      {/* <title>
        {info?.city && info?.country ? `${info.city}, ${info.country}` : name}
        {info?.ip && `\n📡 IP: ${info.ip}`}
        {info?.isp && `\n🏢 ISP: ${info.isp}`}
        {info?.asn && `\n🔢 ASN: ${info.asn}`}
        {`\n📍 Coordinates: ${coords[1].toFixed(4)}°, ${coords[0].toFixed(4)}°`}
      </title> */}
    </Marker>
  );
};

export const GeoRippleMap: React.FC<GeoRippleMapProps> = ({
  data,
  height = "400px",
}) => {
  const [position, setPosition] = React.useState({
    coordinates: [0, 20] as [number, number],
    zoom: 1,
  });

  // Auto-center and zoom to marker when data loads
  React.useEffect(() => {
    if (data && data.length > 0 && data[0].value) {
      const [lng, lat] = data[0].value;
      if (lng && lat) {
        setPosition({
          coordinates: [lng, lat],
          zoom: 3.5,
        });
      }
    }
  }, [data]);

  // Zoom control handlers
  const handleZoomIn = () => {
    setPosition((pos) => ({
      ...pos,
      zoom: Math.min(pos.zoom * 1.5, 15),
    }));
  };

  const handleZoomOut = () => {
    setPosition((pos) => ({
      ...pos,
      zoom: Math.max(pos.zoom / 1.5, 1),
    }));
  };

  const handleReset = () => {
    if (data && data.length > 0 && data[0].value) {
      const [lng, lat] = data[0].value;
      setPosition({
        coordinates: [lng, lat],
        zoom: 3.5,
      });
    } else {
      setPosition({
        coordinates: [0, 20],
        zoom: 1,
      });
    }
  };

  const hasValidData =
    data && data.length > 0 && data[0].value?.[0] && data[0].value?.[1];

  return (
    <div className="relative" style={{ height }}>
      {/* Map Container */}
      <div className="w-full h-full flex items-center justify-center">
        {!hasValidData ? (
          <div className="text-slate-400 text-sm">
            No location data available
          </div>
        ) : (
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{
              scale: 140,
              center: [0, 20],
            }}
            style={{ width: "100%", height: "100%" }}
          >
            <ZoomableGroup
              center={position.coordinates}
              zoom={position.zoom}
              onMoveEnd={(newPosition) => {
                setPosition(newPosition as any);
              }}
              minZoom={1}
              maxZoom={15}
            >
              {/* World Map Geographies */}
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      style={{
                        default: {
                          fill: "rgba(255,255,255,0.03)",
                          stroke: "rgba(255,255,255,0.08)",
                          strokeWidth: 0.5,
                          outline: "none",
                        },
                        hover: {
                          fill: "rgba(229,9,20,0.08)",
                          stroke: "rgba(255,255,255,0.12)",
                          strokeWidth: 0.75,
                          outline: "none",
                        },
                        pressed: {
                          fill: "rgba(229,9,20,0.12)",
                          outline: "none",
                        },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Ripple Markers */}
              {data.map((point, idx) => {
                const [lng, lat] = point.value;
                if (!lng || !lat) return null;

                return (
                  <RippleMarker
                    key={idx}
                    coords={[lng, lat]}
                    name={point.name}
                  />
                );
              })}
            </ZoomableGroup>
          </ComposableMap>
        )}
      </div>

      {/* Zoom Controls */}
      {hasValidData && (
        <div className="absolute top-4 right-4 flex flex-col gap-2">
          <button
            onClick={handleZoomIn}
            className="w-8 h-8 rounded-md bg-black/40 backdrop-blur-sm border border-white/10
                     text-white hover:bg-black/60 hover:border-red-500/30 transition-all
                     flex items-center justify-center text-lg font-bold shadow-lg"
            title="Zoom In"
          >
            +
          </button>
          <button
            onClick={handleZoomOut}
            className="w-8 h-8 rounded-md bg-black/40 backdrop-blur-sm border border-white/10
                     text-white hover:bg-black/60 hover:border-red-500/30 transition-all
                     flex items-center justify-center text-lg font-bold shadow-lg"
            title="Zoom Out"
          >
            −
          </button>
          <button
            onClick={handleReset}
            className="w-8 h-8 rounded-md bg-black/40 backdrop-blur-sm border border-white/10
                     text-white hover:bg-black/60 hover:border-red-500/30 transition-all
                     flex items-center justify-center text-xs shadow-lg"
            title="Reset View"
          >
            ⟲
          </button>
        </div>
      )}

      {/* Location Info Panel (Bottom Left) */}
      {hasValidData && data[0] && (
        <div
          className="absolute bottom-4 left-4 px-3 py-2 rounded-lg
                      bg-black/50 backdrop-blur-sm border border-white/10 shadow-lg"
        >
          <div className="text-xs text-slate-300 space-y-0.5">
            <div className="font-semibold text-white">{data[0].name}</div>
            <div className="text-slate-400">
              📍 {data[0].value[1].toFixed(4)}°, {data[0].value[0].toFixed(4)}°
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
