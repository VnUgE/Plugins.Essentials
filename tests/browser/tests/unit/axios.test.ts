import { describe, expect, it, beforeEach } from 'vitest';
import {
  useAxios,
  createAxios,
  createApiConfig,
} from '@vnuge/vnlib.browser'
import axios from 'axios'

describe('Axios Integration - Unit Tests', () => {

  let config: ReturnType<typeof createApiConfig>

  beforeEach(() => {
    // Create fresh config for each test
    config = createApiConfig()
  })

  describe('useAxios - Shared Instance', () => {
    it('should return an axios instance with standard HTTP methods', () => {
      const instance = useAxios(config)

      expect(instance).toBeDefined()
      expect(instance.get).toBeDefined()
      expect(instance.post).toBeDefined()
      expect(instance.put).toBeDefined()
      expect(instance.delete).toBeDefined()
      expect(instance.interceptors).toBeDefined()
    })

    it('should return the same instance on repeated calls (interceptors applied once)', () => {
      const first = useAxios(config)
      const second = useAxios(config)

      expect(second).toBe(first)
    })

    it('should use the provided axios instance', () => {
      const customInstance = axios.create({ baseURL: 'https://custom.example.com' })
      const customConfig = createApiConfig({ axios: customInstance })

      const result = useAxios(customConfig)

      expect(result).toBe(customInstance)
      expect(result.defaults.baseURL).toBe('https://custom.example.com')
    })
  })

  describe('createAxios - Per-Call Instance', () => {
    it('should create a new instance with request options merged in', () => {
      const instance = createAxios(config, {
        baseURL: 'https://api.example.com',
        timeout: 30000
      })

      expect(instance).toBeDefined()
      expect(instance.defaults.baseURL).toBe('https://api.example.com')
      expect(instance.defaults.timeout).toBe(30000)
    })

    it('should return a distinct instance on every call', () => {
      const a = createAxios(config, { timeout: 5000 })
      const b = createAxios(config, { timeout: 5000 })

      expect(a).not.toBe(b)
    })

    it('should have interceptors applied on the new instance', () => {
      const instance = createAxios(config, {})

      expect(instance.interceptors.request).toBeDefined()
      expect(instance.interceptors.response).toBeDefined()
    })

    it('should not share interceptor state with the config shared instance', () => {
      const shared = useAxios(config)
      const perCall = createAxios(config, {})

      expect(perCall).not.toBe(shared)
    })
  })

  describe('Token Header', () => {
    it('should default to X-Web-Token', () => {
      expect(config.tokenHeader).toBe('X-Web-Token')
    })

    it('should accept a custom token header name', () => {
      const customConfig = createApiConfig({ tokenHeader: 'X-Custom-OTP' })
      expect(customConfig.tokenHeader).toBe('X-Custom-OTP')
    })
  })

})
