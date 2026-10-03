import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

import pkg from './package.json'

// https://vitejs.dev/config/
export default defineConfig(({ command, mode }) => {


  const env = loadEnv(mode, process.cwd(), '')

  return ({
    plugins: [react()],
    // Single source of truth for the version string. It used to be hardcoded
    // in Login.tsx, which is how the UI ended up showing v0.3.0 while the repo
    // was on 0.6.1 -- a number nobody had a reason to touch when releasing.
    define: {
      __APP_VERSION__: JSON.stringify(pkg.version),
    },
    build: {
      target: ['es2020']
    },
    server: {
      proxy: {
        '/api': {
          target: env["API_SERVER_ENDPOINT"] ?? "http://localhost:5000/",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, '')
        }
      }
    }
  })
})
