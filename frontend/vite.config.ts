import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    // Allow all hosts - safe when behind reverse proxy
    allowedHosts: true,
    watch: {
      usePolling: true, // Required for hot reload in Docker environment
    },
  },
  build: {
    // Optimize bundle size with esbuild (faster and no extra dependencies)
    minify: 'esbuild',
    // Note: esbuild minification is faster than terser but doesn't drop console by default
    // Production builds still benefit from tree-shaking and dead code elimination
    // Optimize chunking strategy
    rollupOptions: {
      output: {
        // Manual chunk splitting for better caching
        manualChunks: {
          // Vendor chunks - rarely change
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-query': ['@tanstack/react-query', 'axios'],
          'vendor-ui': ['lucide-react', 'zustand'],
          'vendor-i18n': ['i18next', 'i18next-browser-languagedetector', 'react-i18next'],
          // Cytoscape and layouts in separate chunk (large library)
          'vendor-cytoscape': ['cytoscape'],
          'vendor-cytoscape-layouts': ['cytoscape-cola', 'cytoscape-cose-bilkent', 'cytoscape-dagre'],
        },
        // Optimize chunk names
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId ? chunkInfo.facadeModuleId.split('/').pop() : 'chunk'
          return `assets/js/${facadeModuleId}-[hash].js`
        },
        // Optimize entry file names
        entryFileNames: 'assets/js/[name]-[hash].js',
        // Optimize asset file names
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name?.split('.')
          const ext = info?.[info.length - 1]
          if (/png|jpe?g|svg|gif|tiff|bmp|ico/i.test(ext as string)) {
            return `assets/images/[name]-[hash][extname]`
          } else if (/woff|woff2|eot|ttf|otf/i.test(ext as string)) {
            return `assets/fonts/[name]-[hash][extname]`
          } else if (ext === 'css') {
            return `assets/css/[name]-[hash][extname]`
          }
          return `assets/[name]-[hash][extname]`
        },
      },
    },
    // Increase chunk size warning limit (since we're doing manual chunking)
    chunkSizeWarningLimit: 1000,
    // Enable source maps for production debugging
    sourcemap: false,
    // Optimize CSS
    cssCodeSplit: true,
    // Enable brotli compression for static hosting
    reportCompressedSize: true,
  },
  // Optimize dependencies pre-bundling
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      '@tanstack/react-query',
      'axios',
      'zustand',
      'lucide-react',
      // Include Cytoscape for proper module resolution
      'cytoscape',
      'cytoscape-cola',
      'cytoscape-cose-bilkent',
      'cytoscape-dagre',
    ],
  },
})