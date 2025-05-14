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
    }
})