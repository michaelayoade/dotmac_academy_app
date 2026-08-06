/** @type {import('tailwindcss').Config} */
// Dotmac Academy — warm technical-editorial design system.
// Scans every template so all utility classes used across the portal compile.
module.exports = {
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        // Token-backed palettes. Keep existing utility names stable while
        // html[data-theme] swaps the underlying values.
        brand: {
          50:  "oklch(var(--brand-50-oklch) / <alpha-value>)",
          100: "oklch(var(--brand-100-oklch) / <alpha-value>)",
          200: "oklch(var(--brand-200-oklch) / <alpha-value>)",
          300: "oklch(var(--brand-300-oklch) / <alpha-value>)",
          400: "oklch(var(--brand-400-oklch) / <alpha-value>)",
          500: "oklch(var(--brand-500-oklch) / <alpha-value>)",
          600: "oklch(var(--brand-600-oklch) / <alpha-value>)",
          700: "oklch(var(--brand-700-oklch) / <alpha-value>)",
          800: "oklch(var(--brand-800-oklch) / <alpha-value>)",
          900: "oklch(var(--brand-900-oklch) / <alpha-value>)",
        },
        sand: {
          50:  "oklch(var(--sand-50-oklch) / <alpha-value>)",
          100: "oklch(var(--sand-100-oklch) / <alpha-value>)",
          200: "oklch(var(--sand-200-oklch) / <alpha-value>)",
          300: "oklch(var(--sand-300-oklch) / <alpha-value>)",
          400: "oklch(var(--sand-400-oklch) / <alpha-value>)",
          500: "oklch(var(--sand-500-oklch) / <alpha-value>)",
        },
        ink: {
          DEFAULT: "oklch(var(--ink-oklch) / <alpha-value>)",
          soft:    "oklch(var(--ink-soft-oklch) / <alpha-value>)",
        },
        clay: {
          400: "oklch(var(--clay-400-oklch) / <alpha-value>)",
          500: "oklch(var(--clay-500-oklch) / <alpha-value>)",
          600: "oklch(var(--clay-600-oklch) / <alpha-value>)",
        },
      },
      fontFamily: {
        display: ['Fraunces', 'ui-serif', 'Georgia', 'serif'],
        sans: ['Manrope', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: "var(--shadow-card)",
        lift: "var(--shadow-lift)",
      },
      borderRadius: {
        xl: "0.9rem",
        "2xl": "1.25rem",
      },
    },
  },
  plugins: [],
};
