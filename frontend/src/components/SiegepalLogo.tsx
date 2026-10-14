import React from 'react';

interface LogoProps {
  size?: number;
  showText?: boolean;
}

export const SiegepalLogo: React.FC<LogoProps> = ({ size = 32, showText = true }) => {
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.75rem', userSelect: 'none' }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 40 44"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        style={{ filter: 'drop-shadow(0 0 10px rgba(220, 38, 38, 0.45))', flexShrink: 0 }}
      >
        <defs>
          <linearGradient id="shieldRedLeft" x1="0" y1="0" x2="20" y2="40" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#ef4444" />
            <stop offset="50%" stopColor="#dc2626" />
            <stop offset="100%" stopColor="#991b1b" />
          </linearGradient>
          <linearGradient id="shieldDarkRight" x1="20" y1="0" x2="40" y2="40" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#475569" />
            <stop offset="50%" stopColor="#1e293b" />
            <stop offset="100%" stopColor="#0f172a" />
          </linearGradient>
          <linearGradient id="crestHighlight" x1="10" y1="4" x2="20" y2="28" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#fca5a5" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0.1" />
          </linearGradient>
        </defs>

        {/* Outer Shield Shell */}
        {/* Left Wing / Red Facet */}
        <path
          d="M20 2L4 7V22C4 32.5 11 40 20 42.5V2Z"
          fill="url(#shieldRedLeft)"
        />
        {/* Right Wing / Dark Charcoal Facet */}
        <path
          d="M20 2L36 7V22C36 32.5 29 40 20 42.5V2Z"
          fill="url(#shieldDarkRight)"
        />

        {/* Geometric Crown / Castle Battlement Cutouts on Top */}
        <path
          d="M8 7.5L13 13L20 4L27 13L32 7.5L34 11L28 17L20 9L12 17L6 11L8 7.5Z"
          fill="#ffffff"
          fillOpacity="0.15"
        />

        {/* Center Geometric Crest */}
        <path
          d="M20 7L10 12V24C10 30 14.5 35 20 37V7Z"
          fill="url(#crestHighlight)"
        />
        <path
          d="M20 7L30 12V24C30 30 25.5 35 20 37V7Z"
          fill="#0f172a"
          fillOpacity="0.65"
        />

        {/* Center Divider Spine */}
        <line x1="20" y1="2" x2="20" y2="42.5" stroke="#ffffff" strokeOpacity="0.3" strokeWidth="1" />
      </svg>

      {showText && (
        <span
          style={{
            fontFamily: "var(--font-heading)",
            fontWeight: 800,
            fontSize: '1.25rem',
            letterSpacing: '0.08em',
            color: '#ffffff',
            textTransform: 'uppercase',
          }}
        >
          WEBSENTINEL
        </span>
      )}
    </div>
  );
};
