/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        "primary": "#ec5b13",
        "background-light": "#f8f6f6",
        // Wazuh-style deep navy-charcoal (dark-first default)
        "background-dark": "#0b0f19",
        "surface-dark": "#111827",
        // SOC severity scale
        "severity-critical": "#ef4444",
        "severity-high": "#f97316",
        "severity-medium": "#eab308",
        "severity-low": "#38bdf8",
      },
      fontFamily: {
        "display": ["Public Sans", "sans-serif"],
        // Monospace stack for IOCs, IPs, hashes, report IDs
        "mono": ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", "monospace"]
      },
      borderRadius: {
        "DEFAULT": "0.25rem",
        "lg": "0.5rem",
        "xl": "0.75rem",
        "full": "9999px"
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/container-queries'),
    require('@tailwindcss/typography'),
  ],
}
