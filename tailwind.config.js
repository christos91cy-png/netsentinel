/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0f1117",
        surface: "#161b22",
        border: "#30363d",
        accent: "#00ff88",
        cyan: "#00bcd4",
        muted: "#8b949e",
        danger: "#f85149",
        warning: "#e3b341",
        success: "#3fb950",
      },
    },
  },
  plugins: [],
};
