// Software-only simulation / demo — no real systems will be contacted or modified.
/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        primary: '#6366f1',
      },
    },
  },
  plugins: [],
};
