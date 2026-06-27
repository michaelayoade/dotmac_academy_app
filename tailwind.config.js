/** @type {import('tailwindcss').Config} */
// Dotmac Academy — warm technical-editorial design system.
// Scans every template so all utility classes used across the portal compile.
module.exports = {
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        // Emerald — primary brand
        brand: {
          50:  "oklch(0.97 0.02 155 / <alpha-value>)",
          100: "oklch(0.94 0.04 156 / <alpha-value>)",
          200: "oklch(0.88 0.06 157 / <alpha-value>)",
          300: "oklch(0.80 0.09 158 / <alpha-value>)",
          400: "oklch(0.70 0.12 159 / <alpha-value>)",
          500: "oklch(0.60 0.13 160 / <alpha-value>)",
          600: "oklch(0.52 0.12 161 / <alpha-value>)",
          700: "oklch(0.44 0.10 161 / <alpha-value>)", // primary
          800: "oklch(0.37 0.085 162 / <alpha-value>)",
          900: "oklch(0.30 0.06 162 / <alpha-value>)",
        },
        // Sand / cream — neutrals tinted toward green (never pure white/black)
        sand: {
          50:  "oklch(0.992 0.008 110 / <alpha-value>)",
          100: "oklch(0.972 0.013 115 / <alpha-value>)", // page background
          200: "oklch(0.945 0.017 116 / <alpha-value>)",
          300: "oklch(0.905 0.019 117 / <alpha-value>)",
          400: "oklch(0.84 0.02 120 / <alpha-value>)",
          500: "oklch(0.72 0.022 125 / <alpha-value>)",
        },
        // Ink — warm green-black text
        ink: {
          DEFAULT: "oklch(0.28 0.025 162 / <alpha-value>)",
          soft:    "oklch(0.46 0.022 162 / <alpha-value>)",
        },
        // Clay / amber — restrained warm accent
        clay: {
          400: "oklch(0.76 0.11 62 / <alpha-value>)",
          500: "oklch(0.70 0.125 58 / <alpha-value>)",
          600: "oklch(0.62 0.135 52 / <alpha-value>)",
        },
      },
      fontFamily: {
        display: ['Fraunces', 'ui-serif', 'Georgia', 'serif'],
        sans: ['Manrope', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: "0 1px 2px oklch(0.30 0.06 162 / 0.05), 0 8px 24px -12px oklch(0.30 0.06 162 / 0.18)",
        lift: "0 2px 4px oklch(0.30 0.06 162 / 0.06), 0 18px 40px -18px oklch(0.30 0.06 162 / 0.28)",
      },
      borderRadius: {
        xl: "0.9rem",
        "2xl": "1.25rem",
      },
    },
  },
  plugins: [],
};
