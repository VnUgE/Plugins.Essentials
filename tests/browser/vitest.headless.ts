import { defineConfig } from 'vitest/config'
import { webdriverio } from '@vitest/browser-webdriverio'

export default defineConfig({
  test: {
      name: 'e2e-tests',
      setupFiles: ['./setup.ts'],
      include: ['tests/e2e/**/*.test.ts'],
      browser: {
        enabled: true,
        headless: true,
        ui: false,
        screenshotFailures: false,
        provider: webdriverio(),
        instances: [
          { browser: 'firefox' }
        ],
    }
  },
  server:{
    // Routes api connections to the test server
    proxy: {
      '/test': {
        target: 'https://localhost:8089',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/test/, '/'),
        headers: {
          "sec-fetch-mode": "cors",
          "referer": "https://localhost:8089",
          "origin": "https://localhost:8089",
          "Connection": "keep-alive",
        }
      },
    }
  }
})
