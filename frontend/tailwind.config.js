/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#030712",        // Deep dark slate-950
          darker: "#090d16",    // Deep dark zinc-like slate
          card: "#0f172a",      // Slate-900 background for containers
          border: "#1e293b",    // Slate-800 for clean subtle lines
          primary: "#6366f1",   // Modern Indigo
          primaryHover: "#4f46e5",
          secondary: "#10b981", // Hacker Emerald Green
          accent: "#f43f5e",    // Cyber Punk Pink/Red
        }
      },
      fontFamily: {
        mono: ["Fira Code", "Courier New", "monospace"],
      }
    },
  },
  plugins: [],
}
