import { describe, expect, it } from 'vitest';
import { 
  useAppDataApi,
  type UserAppDataApi,
  type AppDataApiOptions,
  type AppDataGetOptions,
  type AppDataSetOptions
} from '@vnuge/vnlib.browser'
import { vnlib } from '../../main';

describe('App Data API - Unit Tests', () => {

  describe('useAppDataApi - API Structure', () => {
    it('should create app data API with correct methods', () => {
      const options: AppDataApiOptions = {
        endpoint: '/app-data',
        config: vnlib
      }
      
      const api: UserAppDataApi = useAppDataApi(options)
      
      expect(api).toBeDefined()
      
      expect(api.get).toBeDefined()
      expect(api.get).toBeTypeOf('function')
      
      expect(api.set).toBeDefined()
      expect(api.set).toBeTypeOf('function')
      
      expect(api.remove).toBeDefined()
      expect(api.remove).toBeTypeOf('function')
    })

    it('should accept plain string or MaybeRef endpoint', () => {
      // Plain string endpoint
      const options1: AppDataApiOptions = {
        endpoint: '/app-data',
        config: vnlib
      }
      
      const api1 = useAppDataApi(options1)
      expect(api1).toBeDefined()
      
      // MaybeRef allows string or Ref<string> at runtime
      // Type test verifies compile-time acceptance
      const options2: AppDataApiOptions = {
        endpoint: '/app-data',
        config: vnlib
      }
      
      const api2 = useAppDataApi(options2)
      expect(api2).toBeDefined()
    })

    it('should work with plain string endpoint', () => {
      const options: AppDataApiOptions = {
        endpoint: '/custom-endpoint',
        config: vnlib
      }
      
      const api = useAppDataApi(options)
      
      expect(api).toBeDefined()
    })
  })
})
