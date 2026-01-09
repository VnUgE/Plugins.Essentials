import { describe, it, expect, vi } from 'vitest'
import { 
  useAccount,
  useAccountRpc,
  useProfile,
  isLoggedIn,
  isLocalAccount,
  type AccountApi,
  type AccountRpcApi,
  type AccountRpcGetResult,
  type UserLoginRequest
} from '@vnuge/vnlib.browser'

import { vnlib } from '../../main'

describe('Account API - Unit Tests', () => {

  describe('useAccountRpc - API Structure', () => {
    it('should create account RPC instance with correct type', () => {
      const accountRpc: AccountRpcApi<string> = useAccountRpc<string>(vnlib)
      
      expect(accountRpc).toBeDefined()
      
      expect(accountRpc.getData).toBeDefined()
      expect(accountRpc.getData).toBeTypeOf('function')

      expect(accountRpc.exec).toBeDefined()
      expect(accountRpc.exec).toBeTypeOf('function')

      expect(accountRpc.isMethodEnabled).toBeDefined()
      expect(accountRpc.isMethodEnabled).toBeTypeOf('function')
    })

    it('should properly check if method is enabled', () => {
      const accountRpc: AccountRpcApi<'login' | 'logout'> = useAccountRpc<'login' | 'logout'>(vnlib)
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'login', options: [] },
          { method: 'logout', options: [] }
        ]
      }

      expect(accountRpc.isMethodEnabled(mockData, 'login')).toBe(true)
      expect(accountRpc.isMethodEnabled(mockData, 'logout')).toBe(true)
    })

    it('should handle method checking with empty methods list', () => {
      const { isMethodEnabled } = useAccountRpc<'mfa.get'>(vnlib)
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: []
      }

      expect(isMethodEnabled(mockData, 'mfa.get')).toBe(false)
    })

    it('should support specific method types in generic parameter', () => {
      // Test that the generic parameter properly constrains method types
      type MfaMethods = 'mfa.get' | 'mfa.rpc'
      const { isMethodEnabled } = useAccountRpc<MfaMethods>(vnlib)
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'mfa.get', options: ['auth_required'] },
          { method: 'mfa.rpc', options: [] }
        ]
      }

      expect(isMethodEnabled(mockData, 'mfa.get')).toBe(true)
      expect(isMethodEnabled(mockData, 'mfa.rpc')).toBe(true)
    })

    it('should work with single method type', () => {
      const { isMethodEnabled } = useAccountRpc<'profile.get'>(vnlib)
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'profile.get', options: [] }
        ]
      }

      expect(isMethodEnabled(mockData, 'profile.get')).toBe(true)
    })

    it('should handle undefined or null rpc_methods gracefully', () => {
      const { isMethodEnabled } = useAccountRpc<'test.method'>(vnlib)
      
      // Test with empty array
      expect(isMethodEnabled({ rpc_methods: [] }, 'test.method')).toBe(false)
      
      // The function should handle edge cases gracefully
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'other.method', options: [] }
        ]
      }
      expect(isMethodEnabled(mockData, 'test.method')).toBe(false)
    })
  })

  describe('useAccount - API Structure', () => {
    it('should create account instance with proper types', () => {
      const account: AccountApi = useAccount(vnlib)
      
      expect(account).toBeDefined()
      expect(account.prepareLogin).toBeDefined()
      expect(account.login).toBeDefined()
      expect(account.logout).toBeDefined()
      expect(account.resetPassword).toBeDefined()
      expect(account.heartbeat).toBeDefined()
    })

    it('should prepare login request properly', async () => {
      const { prepareLogin } = useAccount(vnlib)
      
      const loginRequest: UserLoginRequest = await prepareLogin()
      
      expect(loginRequest).toBeDefined()
      expect(loginRequest.finalize).toBeDefined()
      expect(loginRequest.finalize).toBeTypeOf('function')
    })

    it('should handle heartbeat functionality', () => {
      const { heartbeat } = useAccount(vnlib)
      
      expect(heartbeat).toBeDefined()
      expect(heartbeat).toBeTypeOf('function')
    })
  })

  describe('useProfile - API Structure', () => {
    it('should create profile API with correct methods', () => {
      const profileApi = useProfile(vnlib)
      
      expect(profileApi).toBeDefined()
      expect(profileApi.getProfile).toBeDefined()
      expect(profileApi.canGetProfile).toBeDefined()
      expect(profileApi.updateProfile).toBeDefined()
      expect(profileApi.canUpdateProfile).toBeDefined()
    })

    it('should check if profile can be retrieved', () => {
      const { canGetProfile } = useProfile(vnlib)
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'profile.get', options: ['auth_required'] }
        ]
      }

      expect(canGetProfile(mockData)).toBe(true)
    })

    it('should check if profile can be updated', () => {
      const { canUpdateProfile } = useProfile(vnlib)
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'profile.update', options: ['auth_required'] }
        ]
      }

      expect(canUpdateProfile(mockData)).toBe(true)
    })
  })

  describe('Helper Functions', () => {
    it('should correctly identify logged in status', () => {
      const loggedInData: Pick<AccountRpcGetResult, 'status'> = {
        status: { authenticated: true, is_local_account: true }
      }

      const loggedOutData: Pick<AccountRpcGetResult, 'status'> = {
        status: { authenticated: false, is_local_account: false }
      }

      expect(isLoggedIn(loggedInData)).toBe(true)
      expect(isLoggedIn(loggedOutData)).toBe(false)
    })

    it('should correctly identify local account status', () => {
      const localAccount: Pick<AccountRpcGetResult, 'status'> = {
        status: { authenticated: true, is_local_account: true }
      }

      const socialAccount: Pick<AccountRpcGetResult, 'status'> = {
        status: { authenticated: true, is_local_account: false }
      }

      expect(isLocalAccount(localAccount)).toBe(true)
      expect(isLocalAccount(socialAccount)).toBe(false)
    })

    it('should handle edge cases for isLoggedIn', () => {
      // Missing status object should return false (lodash get with default)
      const emptyData = {} as Pick<AccountRpcGetResult, 'status'>
      expect(isLoggedIn(emptyData)).toBe(false)

      // Partial status object
      const partialData: Pick<AccountRpcGetResult, 'status'> = {
        status: { authenticated: false, is_local_account: true }
      }
      expect(isLoggedIn(partialData)).toBe(false)
    })

    it('should handle edge cases for isLocalAccount', () => {
      // Missing status object should return false (lodash get with default)
      const emptyData = {} as Pick<AccountRpcGetResult, 'status'>
      expect(isLocalAccount(emptyData)).toBe(false)

      // Not a local account even if authenticated
      const socialData: Pick<AccountRpcGetResult, 'status'> = {
        status: { authenticated: true, is_local_account: false }
      }
      expect(isLocalAccount(socialData)).toBe(false)
    })
  })

})
