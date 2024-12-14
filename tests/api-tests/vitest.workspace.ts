import { defineWorkspace } from 'vitest/config'

export default defineWorkspace([
  // If you want to keep running your existing tests in Node.js, uncomment the next line.
  // 'vitest.config.ts',
  {
    extends: 'vitest.config.ts',
    test: {
      browser: {
        enabled: true,
        name: 'firefox',
        provider: 'webdriverio',
        // https://webdriver.io
        providerOptions: {},
      },
    },
  },
])