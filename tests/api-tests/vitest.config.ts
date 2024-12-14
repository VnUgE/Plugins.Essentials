import { defineConfig } from 'vitest/config'

export default defineConfig({
  server:{
    // Routes api connections to the test server
    proxy: {
       '/api': {
        target: 'https://localhost:8089',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, ''),
        headers: {
          "sec-fetch-mode": "cors",
          "referer": "https://localhost:8089",
          "origin": "https://localhost:8089",
          "Connection": "keep-alive",
        }
      },
    }
  },
  test: {
    name: 'api-tests',
    environment: 'jsdom',
    setupFiles: ['./setup.ts'],
    browser: {
      enabled: true,
      name: 'firefox',
      headless: true,
      provider: 'webdriverio',
      // https://webdriver.io
      providerOptions: {
      },
    },
  },
})