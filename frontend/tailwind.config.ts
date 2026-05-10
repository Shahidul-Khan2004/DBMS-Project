// tailwind.config.ts
import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: "#f0f4f8",
          600: "#002D62",
          700: "#00214a",
          900: "#00152f",
        },
        national: {
          green: "#006747",
        },
        emergency: {
          red: "#DA291C",
        },
        success: "#10B981",
      },
    },
  },
  plugins: [],
};

export default config;