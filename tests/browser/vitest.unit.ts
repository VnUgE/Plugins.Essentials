import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    name: 'unit-tests',
    environment: 'jsdom',
    setupFiles: ['./setup.unit.ts'],
    include: ['tests/unit/**/*.test.ts'],
    globals: true,
  }
})
