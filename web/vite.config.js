import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The "Load example" buttons import the real fixtures from ../tests/fixtures via
// `?raw`. Those live outside web/, so the dev server needs fs access to the repo
// root ('..'). (For a production build the files are inlined at build time.)
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    fs: { allow: ['..'] },
  },
})
