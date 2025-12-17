import { describe, expect, it, vi, beforeEach } from 'vitest';
import { 
  useAxios,
  getDefaultAxiosRequestConfig,
  createApiConfig,
  type AxiosConfig,
  type WebMessage
} from '@vnuge/vnlib.browser'
import type { AxiosRequestConfig } from 'axios';

describe('Axios Integration - Unit Tests', () => {

  let config: ReturnType<typeof createApiConfig>

  beforeEach(() => {
    // Create fresh config for each test
    config = createApiConfig()
  })

  describe('getDefaultAxiosRequestConfig', () => {
    it('should return default axios request config', () => {
      const defaultConfig = getDefaultAxiosRequestConfig()
      
      expect(defaultConfig).toBeDefined()
      
      expect(defaultConfig.timeout).toBeDefined()
      expect(defaultConfig.timeout).toBeTypeOf('number')
      
      expect(defaultConfig.withCredentials).toBeDefined()
      expect(defaultConfig.withCredentials).toBeTypeOf('boolean')
    })

    it('should have expected timeout value', () => {
      const defaultConfig = getDefaultAxiosRequestConfig()
      expect(defaultConfig.timeout).toBe(60000) // 60 seconds
    })

    it('should have withCredentials set to false', () => {
      const defaultConfig = getDefaultAxiosRequestConfig()
      expect(defaultConfig.withCredentials).toBe(false)
    })
  })

  describe('useAxios - API Structure', () => {
    it('should return axios instance from config', () => {
      const axios = useAxios(config)
      
      expect(axios).toBeDefined()
      expect(axios.get).toBeDefined()
      expect(axios.post).toBeDefined()
      expect(axios.put).toBeDefined()
      expect(axios.delete).toBeDefined()
      expect(axios.interceptors).toBeDefined()
    })

    it('should configure interceptors only once per instance', () => {
      const axios = useAxios(config)
      
      // Call useAxios again with same config
      const axios2 = useAxios(config)
      
      // Should return same instance (due to config.axios.instance being reused)
      expect(axios2).toBe(axios)
      
      // Verify interceptors are configured (both exist)
      expect(axios.interceptors.request).toBeDefined()
      expect(axios.interceptors.response).toBeDefined()
    })

    it('should accept custom axios instance', () => {
      const customAxiosConfig = createApiConfig({
        axios: {
          axiosConfig: {
            baseURL: 'https://custom.example.com'
          }
        }
      })
      
      const axios = useAxios(customAxiosConfig)
      
      expect(axios).toBeDefined()
      expect(axios.defaults.baseURL).toBe('https://custom.example.com')
    })
  })

  describe('AxiosConfig Type', () => {
    it('should have correct structure', () => {
      const axiosConfig: AxiosConfig = config.axios
      
      expect(axiosConfig.instance).toBeDefined()
      
      expect(axiosConfig.tokenHeader).toBeDefined()
      expect(axiosConfig.tokenHeader).toBeTypeOf('string')
      expect(axiosConfig.tokenHeader).toBe('X-Web-Token')
    })

    it('should support custom token header', () => {
      const customConfig = createApiConfig({
        axios: {
          tokenHeader: 'X-Custom-OTP'
        }
      })
      
      expect(customConfig.axios.tokenHeader).toBe('X-Custom-OTP')
    })
  })

  describe('Request Config Merging', () => {
    it('should merge custom axios config with defaults', () => {
      const customConfig = createApiConfig({
        axios: {
          axiosConfig: {
            baseURL: 'https://api.example.com',
            timeout: 30000
          }
        }
      })
      
      const axios = useAxios(customConfig)
      
      expect(axios.defaults.baseURL).toBe('https://api.example.com')
      expect(axios.defaults.timeout).toBe(30000)
    })

    it('should allow configureInstance callback', () => {
      const configureSpy = vi.fn((instance) => instance)
      
      const customConfig = createApiConfig({
        axios: {
          configureInstance: configureSpy
        }
      })
      
      expect(configureSpy).toHaveBeenCalledOnce()
      expect(configureSpy).toHaveBeenCalledWith(customConfig.axios.instance)
    })
  })

})
