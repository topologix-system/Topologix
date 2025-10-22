/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0369a1', // Updated from #0284c7 for better contrast (WCAG AA compliant)
          700: '#075985',
          800: '#0c4a6e',
          900: '#0a3a54',
        },
      },
    },
  },
  plugins: [],
}