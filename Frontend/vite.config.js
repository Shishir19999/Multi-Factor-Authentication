import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `vite build --mode pages` produces the static, browser-only demo for GitHub Pages.
export default defineConfig(({ mode }) => {
  const pages = mode === 'pages'
  return {
    plugins: [react()],
    base: pages ? '/Multi-Factor-Authentication/' : '/',
    define: pages ? { 'import.meta.env.VITE_DEMO': JSON.stringify('true') } : {},
    test: { environment: 'jsdom' },
  }
})
