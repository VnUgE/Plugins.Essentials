import { defineWorkspace } from 'vitest/config'

export default defineWorkspace([
  // If you want to keep running your existing tests in Node.js, uncomment the next line.
  // 'vitest.config.ts',
  {
    extends: 'vitest.config.ts',
    test: {
        name: 'api-tests',
        environment: 'jsdom',
        setupFiles: ['./setup.ts'],
        browser: {
            enabled: true,
            headless: false,
            ui: true,
            provider: 'webdriverio',
            instances: [
                { browser: 'firefox' },
            ]
        },
    },
  },
])
