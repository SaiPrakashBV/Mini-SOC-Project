import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In development the Vite server proxies API calls exactly like nginx does in Docker.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/tracker': {
        target: process.env.TRACKER_URL || 'http://localhost:8081',
        rewrite: (p) => p.replace(/^\/tracker/, ''),
      },
      '/detection': {
        target: process.env.DETECTION_URL || 'http://localhost:8082',
        rewrite: (p) => p.replace(/^\/detection/, ''),
      },
    },
  },
});
