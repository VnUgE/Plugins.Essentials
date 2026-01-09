import { describe, expect, it } from 'vitest';
import {
  useOauthLogin,
  type SocialLoginApi,
  type SocialOAuthMethod,
  type BeginFlowArgs,
  type LogoutArguments,
  type AccountRpcGetResult
} from '@vnuge/vnlib.browser'
import { vnlib } from '../../fixtures';

describe('Social OAuth Login - Unit Tests', () => {

  describe('useOauthLogin - API Structure', () => {
    it('should create social login API with correct methods', () => {
      const api: SocialLoginApi = useOauthLogin(vnlib)

      expect(api).toBeDefined()

      expect(api.getPortals).toBeDefined()
      expect(api.getPortals).toBeTypeOf('function')

      expect(api.beginLoginFlow).toBeDefined()
      expect(api.beginLoginFlow).toBeTypeOf('function')

      expect(api.completeLogin).toBeDefined()
      expect(api.completeLogin).toBeTypeOf('function')

      expect(api.logout).toBeDefined()
      expect(api.logout).toBeTypeOf('function')

      expect(api.isEnabled).toBeDefined()
      expect(api.isEnabled).toBeTypeOf('function')
    })

    it('should check if social OAuth is enabled', () => {
      const { isEnabled } = useOauthLogin(vnlib)

      const enabledData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'social_oauth', options: [] }
        ]
      }

      const disabledData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: []
      }

      expect(isEnabled(enabledData)).toBe(true)
      expect(isEnabled(disabledData)).toBe(false)
    })
  })

  describe('getPortals - Portal Extraction', () => {
    it('should extract OAuth portals from account RPC data', () => {
      const { getPortals } = useOauthLogin(vnlib)

      // Note: properties array contains objects with type field
      // Social OAuth data is accessed through this structure
      const rpcData = {
        properties: [
          {
            type: 'social_oauth',
            methods: [
              {
                supported: true,
                method_id: 'google',
                data: {
                  enabled: true,
                  friendly_name: 'Google',
                  icon_url: 'https://example.com/google-icon.png'
                }
              },
              {
                supported: true,
                method_id: 'github',
                data: {
                  enabled: true,
                  friendly_name: 'GitHub'
                }
              }
            ]
          }
        ]
      } as Pick<AccountRpcGetResult, 'properties'>

      const portals = getPortals(rpcData)

      expect(portals).toBeDefined()
      expect(portals).toBeInstanceOf(Array)
      expect(portals).lengthOf(2)

      expect(portals[0].method_id).toBe('google')
      expect(portals[0].data.friendly_name).toBe('Google')

      expect(portals[1].method_id).toBe('github')
    })

    it('should return empty array when no properties exist', () => {
      const { getPortals } = useOauthLogin(vnlib)

      // Properties undefined scenario
      const emptyData = {
        properties: undefined
      } as unknown as Pick<AccountRpcGetResult, 'properties'>

      const portals = getPortals(emptyData)

      expect(portals).toBeDefined()
      expect(portals).toBeInstanceOf(Array)
      expect(portals).lengthOf(0)
    })

    it('should return empty array when social_oauth not in properties', () => {
      const { getPortals } = useOauthLogin(vnlib)

      const rpcData = {
        properties: [
          { type: 'other_property' }
        ]
      } as Pick<AccountRpcGetResult, 'properties'>

      const portals = getPortals(rpcData)

      expect(portals).toBeDefined()
      expect(portals).toBeInstanceOf(Array)
      expect(portals).lengthOf(0)
    })
  })

  describe('SocialOAuthMethod Structure', () => {
    it('should have correct method structure', () => {
      const method: SocialOAuthMethod = {
        supported: true,
        method_id: 'google',
        data: {
          enabled: true,
          friendly_name: 'Google',
          icon_url: 'https://example.com/icon.png'
        }
      }

      expect(method.supported).toBe(true)
      expect(method.method_id).toBe('google')

      expect(method.data.enabled).toBe(true)
      expect(method.data.friendly_name).toBe('Google')
      expect(method.data.icon_url).toBe('https://example.com/icon.png')
    })

    it('should allow icon_url to be optional', () => {
      const method: SocialOAuthMethod = {
        supported: true,
        method_id: 'github',
        data: {
          enabled: true,
          friendly_name: 'GitHub'
        }
      }

      expect(method.data.icon_url).toBeUndefined()
    })
  })

  describe('BeginFlowArgs Structure', () => {
    it('should have correct flow args structure with autoRedirect', () => {
      const mockMethod: SocialOAuthMethod = {
        supported: true,
        method_id: 'google',
        data: { enabled: true, friendly_name: 'Google' }
      }

      const args: BeginFlowArgs = {
        method: mockMethod,
        autoRedirect: true
      }

      expect(args.method).toBe(mockMethod)
      expect(args.autoRedirect).toBe(true)
    })

    it('should allow autoRedirect to be false', () => {
      const mockMethod: SocialOAuthMethod = {
        supported: true,
        method_id: 'google',
        data: { enabled: true, friendly_name: 'Google' }
      }

      const args: BeginFlowArgs<false> = {
        method: mockMethod,
        autoRedirect: false
      }

      expect(args.autoRedirect).toBe(false)
    })

    it('should allow autoRedirect to be undefined', () => {
      const mockMethod: SocialOAuthMethod = {
        supported: true,
        method_id: 'google',
        data: { enabled: true, friendly_name: 'Google' }
      }

      const args: BeginFlowArgs = {
        method: mockMethod
      }

      expect(args.autoRedirect).toBeUndefined()
    })
  })

  describe('LogoutArguments Structure', () => {
    it('should have correct logout args structure', () => {
      const args: LogoutArguments = {
        autoRedirect: false,
        overrideRedirectUrl: 'https://example.com/custom-logout'
      }

      expect(args.autoRedirect).toBe(false)
      expect(args.overrideRedirectUrl).toBe('https://example.com/custom-logout')
    })

    it('should allow all properties to be optional', () => {
      const args: LogoutArguments = {}

      expect(args).toBeDefined()
      expect(args.autoRedirect).toBeUndefined()
      expect(args.overrideRedirectUrl).toBeUndefined()
    })
  })

})
