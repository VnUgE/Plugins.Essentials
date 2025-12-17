import { describe, expect, it, vi } from 'vitest';
import { 
  createApiConfig,
  type ApiConfig,
  type ApiConfigOverrides
} from '@vnuge/vnlib.browser'
import axios from 'axios';

describe('API Configuration - Unit Tests', () => {

  describe('createApiConfig - Basic Creation', () => {
    it('should create config with default values when no overrides provided', () => {
      const config: ApiConfig = createApiConfig()
      
      expect(config).toBeDefined()
      expect(config.session).toBeDefined()
      expect(config.axios).toBeDefined()
      expect(config.account).toBeDefined()
      expect(config.storage).toBeDefined()
    })

    it('should have session config with default values', () => {
      const config = createApiConfig()
      
      expect(config.session).toBeDefined()
      
      expect(config.session.browserIdSize).toBeDefined()
      expect(config.session.browserIdSize).toBeTypeOf('number')
      
      expect(config.session.signatureAlgorithm).toBeDefined()
      expect(config.session.signatureAlgorithm).toBeTypeOf('string')
      
      expect(config.session.keyAlgorithm).toBeDefined()
      
      expect(config.session.otpNonceSize).toBeDefined()
      expect(config.session.otpNonceSize).toBeTypeOf('number')
    })

    it('should have account config with default endpoint', () => {
      const config = createApiConfig()
      
      expect(config.account).toBeDefined()
      
      expect(config.account.endpointUrl).toBeDefined()
      expect(config.account.endpointUrl).toBeTypeOf('string')
    })

    it('should have axios config with instance and token header', () => {
      const config = createApiConfig()
      
      expect(config.axios).toBeDefined()
      expect(config.axios.instance).toBeDefined()
      
      expect(config.axios.tokenHeader).toBeDefined()
      expect(config.axios.tokenHeader).toBeTypeOf('string')
      expect(config.axios.tokenHeader).toBe('X-Web-Token')
    })

    it('should have storage implementation', async () => {
      const config = createApiConfig()
      
      expect(config.storage).toBeDefined()
      expect(config.storage.getItem).toBeDefined()
      expect(config.storage.setItem).toBeDefined()
      expect(config.storage.removeItem).toBeDefined()
      
      // Verify storage works
      await config.storage.setItem('test-key', 'test-value')
      const value = await config.storage.getItem('test-key')
      expect(value).toBe('test-value')
      
      await config.storage.removeItem('test-key')
      const removed = await config.storage.getItem('test-key')
      expect(removed).toBeNull()
    })
  })

  describe('createApiConfig - Override Session Config', () => {
    it('should override session browserIdSize', () => {
      const overrides: ApiConfigOverrides = {
        session: {
          browserIdSize: 64
        }
      }
      
      const config = createApiConfig(overrides)
      
      expect(config.session.browserIdSize).toBe(64)
    })

    it('should merge session config with defaults', () => {
      const overrides: ApiConfigOverrides = {
        session: {
          otpNonceSize: 32
        }
      }
      
      const config = createApiConfig(overrides)
      
      // Should have custom otpNonceSize
      expect(config.session.otpNonceSize).toBe(32)
      // Should still have other default properties
      expect(config.session.browserIdSize).toBeDefined()
      expect(config.session.signatureAlgorithm).toBeDefined()
      expect(config.session.keyAlgorithm).toBeDefined()
    })
  })

  describe('createApiConfig - Override Account Config', () => {
    it('should override account endpoint URL', () => {
      const overrides: ApiConfigOverrides = {
        account: {
          endpointUrl: '/custom-account'
        }
      }
      
      const config = createApiConfig(overrides)
      
      expect(config.account.endpointUrl).toBe('/custom-account')
    })
  })

  describe('createApiConfig - Override Axios Config', () => {
    it('should accept custom axios instance', () => {
      const customAxios = axios.create({ baseURL: 'https://example.com' })
      
      const overrides: ApiConfigOverrides = {
        axios: {
          instance: customAxios
        }
      }
      
      const config = createApiConfig(overrides)
      
      expect(config.axios.instance).toBe(customAxios)
      expect(config.axios.tokenHeader).toBe('X-Web-Token')
    })

    it('should override token header name', () => {
      const overrides: ApiConfigOverrides = {
        axios: {
          tokenHeader: 'X-Custom-Token'
        }
      }
      
      const config = createApiConfig(overrides)
      
      expect(config.axios.tokenHeader).toBe('X-Custom-Token')
    })

    it('should merge axios request config when no instance provided', () => {
      const overrides: ApiConfigOverrides = {
        axios: {
          axiosConfig: {
            baseURL: 'https://api.example.com',
            timeout: 5000
          }
        }
      }
      
      const config = createApiConfig(overrides)
      
      expect(config.axios.instance).toBeDefined()
      expect(config.axios.instance.defaults.baseURL).toBe('https://api.example.com')
      expect(config.axios.instance.defaults.timeout).toBe(5000)
    })

    it('should call configureInstance callback when provided', () => {
      const configureSpy = vi.fn()
      
      const overrides: ApiConfigOverrides = {
        axios: {
          configureInstance: configureSpy
        }
      }
      
      const config = createApiConfig(overrides)
      
      expect(configureSpy).toHaveBeenCalledOnce()
      expect(configureSpy).toHaveBeenCalledWith(config.axios.instance)
    })
  })

  describe('createApiConfig - Override Storage', () => {
    it('should accept custom storage implementation', async () => {
      const customStorage = {
        getItem: vi.fn().mockResolvedValue('custom-value'),
        setItem: vi.fn().mockResolvedValue(undefined),
        removeItem: vi.fn().mockResolvedValue(undefined)
      }
      
      const overrides: ApiConfigOverrides = {
        storage: customStorage
      }
      
      const config = createApiConfig(overrides)
      
      expect(config.storage).toBe(customStorage)
      
      // Verify custom storage is used
      await config.storage.getItem('test')
      expect(customStorage.getItem).toHaveBeenCalledWith('test')
    })

    it('should use default in-memory storage when localStorage unavailable', async () => {
      const config = createApiConfig()
      
      // Test in-memory storage behavior
      await config.storage.setItem('key1', 'value1')
      await config.storage.setItem('key2', 'value2')
      
      expect(await config.storage.getItem('key1')).toBe('value1')
      expect(await config.storage.getItem('key2')).toBe('value2')
      
      await config.storage.removeItem('key1')
      expect(await config.storage.getItem('key1')).toBeNull()
      expect(await config.storage.getItem('key2')).toBe('value2')
    })
  })

  describe('createApiConfig - Config Isolation', () => {
    it('should create independent config instances', () => {
      const config1 = createApiConfig({ session: { browserIdSize: 32 } })
      const config2 = createApiConfig({ session: { browserIdSize: 64 } })
      
      expect(config1.session.browserIdSize).toBe(32)
      expect(config2.session.browserIdSize).toBe(64)
      
      // Should not share axios instances
      expect(config1.axios.instance).not.toBe(config2.axios.instance)
    })

    it('should not mutate original override objects', () => {
      const overrides: ApiConfigOverrides = {
        session: {
          browserIdSize: 128
        }
      }
      
      const config = createApiConfig(overrides)
      
      // Original override should be unchanged
      expect(overrides.session?.browserIdSize).toBe(128)
      expect(config.session.browserIdSize).toBe(128)
    })
  })

})
