/** @type {import('tailwindcss').Config} */
// Dotmac Academy consumes the generated dotmac-ui preset from the installed
// wheel. Resolving it through Python is deliberate: copying the preset here
// would create another token vocabulary that can drift from the package.
const { execFileSync } = require("node:child_process");

const presetPath = execFileSync(
  "poetry",
  [
    "run",
    "python",
    "-c",
    "import dotmac_ui; print(dotmac_ui.tailwind_preset_path())",
  ],
  { encoding: "utf8" },
).trim();
const dotmacUi = require(presetPath);

const tokenColour = (name) =>
  `rgb(var(--dmui-${name}-rgb) / <alpha-value>)`;

// These aliases keep the existing Academy templates stable while making the
// shared role/ramp variables their canonical values. New markup should prefer
// the preset's role names: surface-*, content-*, stroke-*, action-* and status-*.
const legacyNeutral = Object.fromEntries(
  ["50", "100", "200", "300", "400", "500"].map((step) => [
    step,
    tokenColour(`color-semantic-neutral-${step}`),
  ]),
);
const legacyClay = Object.fromEntries(
  ["50", "100", "200", "300", "400", "500", "600", "700", "800", "900", "950"].map(
    (step) => [step, tokenColour(`color-accent-${step}`)],
  ),
);

module.exports = {
  presets: [dotmacUi],
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        sand: legacyNeutral,
        ink: {
          DEFAULT: tokenColour("text-primary"),
          soft: tokenColour("text-secondary"),
        },
        clay: legacyClay,
      },
      fontFamily: {
        display: ["Fraunces", "ui-serif", "Georgia", "serif"],
        sans: ["Manrope", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "var(--dmui-shadow-md)",
        lift: "var(--dmui-shadow-xl)",
      },
    },
  },
  plugins: [],
};
