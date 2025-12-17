import { describe, it, expect, beforeEach, vi } from 'vitest'
import { 
  useAccount,
  useAccountRpc,
  useProfile,
  type AccountApi,
  type AccountRpcApi,
  type AccountRpcGetResult,
  type UserLoginCredential,
  type UserLoginRequest,
  type TokenResponse,
  isLoggedIn
} from '@vnuge/vnlib.browser'

const testUser = { userName: 'test@test.com', password: 'Password12!' }

describe('Account API', () => {

  describe('useAccountRpc', () => {
    it('should create account RPC instance with correct type', () => {
      const accountRpc: AccountRpcApi<string> = useAccountRpc<string>()
      
      expect(accountRpc).toBeDefined()
      expect(accountRpc.getData).toBeDefined()
      expect(typeof accountRpc.getData).toBe('function')

      expect(accountRpc.exec).toBeDefined()
      expect(typeof accountRpc.exec).toBe('function')

      expect(accountRpc.isMethodEnabled).toBeDefined()
      expect(typeof accountRpc.isMethodEnabled).toBe('function')
    })

    it('should properly check if method is enabled', () => {
      const accountRpc: AccountRpcApi<'login' | 'logout'> = useAccountRpc<'login' | 'logout'>()
      
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
      const accountRpc: AccountRpcApi<'mfa.get'> = useAccountRpc<'mfa.get'>()
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: []
      }

      expect(accountRpc.isMethodEnabled(mockData, 'mfa.get')).toBe(false)
    })

    it('should support specific method types in generic parameter', () => {
      // Test that the generic parameter properly constrains method types
      type MfaMethods = 'mfa.get' | 'mfa.rpc'
      const mfaRpc: AccountRpcApi<MfaMethods> = useAccountRpc<MfaMethods>()
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'mfa.get', options: ['auth_required'] },
          { method: 'mfa.rpc', options: [] }
        ]
      }

      expect(mfaRpc.isMethodEnabled(mockData, 'mfa.get')).toBe(true)
      expect(mfaRpc.isMethodEnabled(mockData, 'mfa.rpc')).toBe(true)
    })

    it('should work with single method type', () => {
      const profileRpc: AccountRpcApi<'profile.get'> = useAccountRpc<'profile.get'>()
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'profile.get', options: [] }
        ]
      }

      expect(profileRpc.isMethodEnabled(mockData, 'profile.get')).toBe(true)
    })
  })

  describe('useAccount', () => {
    it('should create account instance with proper types', () => {
      const account: AccountApi = useAccount()
      
      expect(account).toBeDefined()
      expect(account.prepareLogin).toBeDefined()
      expect(account.login).toBeDefined()
      expect(account.logout).toBeDefined()
      expect(account.resetPassword).toBeDefined()
      expect(account.heartbeat).toBeDefined()
    })

    it('should prepare login request properly', async () => {
      const { prepareLogin } = useAccount()
      
      const loginRequest: UserLoginRequest = await prepareLogin()
      
      expect(loginRequest).toBeDefined()
      expect(loginRequest.finalize).toBeDefined()
      expect(typeof loginRequest.finalize).toBe('function')
    })

    it('should handle heartbeat functionality', () => {
        const { heartbeat } = useAccount()
        expect(heartbeat).toBeDefined()
        expect(typeof heartbeat).toBe('function')

    })
  })

  describe('useProfile', () => {
    it('should create profile API with correct methods', () => {
      const profileApi = useProfile()
      
      expect(profileApi).toBeDefined()
      expect(profileApi.getProfile).toBeDefined()
      expect(profileApi.canGetProfile).toBeDefined()
      expect(profileApi.updateProfile).toBeDefined()
      expect(profileApi.canUpdateProfile).toBeDefined()
    })

    it('should check if profile can be retrieved', () => {
      const profileApi = useProfile()
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'profile.get', options: ['auth_required'] }
        ]
      }

      expect(profileApi.canGetProfile(mockData)).toBe(true)
    })

    it('should check if profile can be updated', () => {
      const profileApi = useProfile()
      
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'profile.update', options: ['auth_required'] }
        ]
      }

      expect(profileApi.canUpdateProfile(mockData)).toBe(true)
    })
  })

  describe('useAccountRpc advanced features', () => {

    it('should handle exec method with different parameter types', () => {
      const accountRpc = useAccountRpc<'test.method' | 'another.method'>()
      
      expect(accountRpc.exec).toBeDefined()
      expect(typeof accountRpc.exec).toBe('function')
      
      // Should accept method names from the generic type
      expect(accountRpc.exec('test.method')).toBeInstanceOf(Promise)
      expect(accountRpc.exec('another.method', { param: 'value' })).toBeInstanceOf(Promise)
    })

    it('should handle complex method enabling checks', () => {
      const accountRpc = useAccountRpc<'mfa.get' | 'mfa.rpc' | 'profile.get' | 'profile.update'>()
      
      const complexMockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'mfa.get', options: ['auth_required'] },
          { method: 'profile.get', options: ['auth_required'] },
          { method: 'login', options: [] }, // Not in our type, should not affect checks
        ]
      }

      expect(accountRpc.isMethodEnabled(complexMockData, 'mfa.get')).toBe(true)
      expect(accountRpc.isMethodEnabled(complexMockData, 'profile.get')).toBe(true)
      expect(accountRpc.isMethodEnabled(complexMockData, 'mfa.rpc')).toBe(false)
      expect(accountRpc.isMethodEnabled(complexMockData, 'profile.update')).toBe(false)
    })

    it('should handle undefined or null rpc_methods gracefully', () => {
      const accountRpc = useAccountRpc<'test.method'>()
      
      // Test with empty array
      expect(accountRpc.isMethodEnabled({ rpc_methods: [] }, 'test.method')).toBe(false)
      
      // The function should handle edge cases gracefully
      const mockData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'other.method', options: [] }
        ]
      }
      expect(accountRpc.isMethodEnabled(mockData, 'test.method')).toBe(false)
    })

    it('should return the correct data structure from getData', async () => {
        const { getData } = useAccountRpc()
        const dataGetResult  = await getData();

        // Should have the correct structure
        expect(dataGetResult).toBeDefined()
        expect(dataGetResult).toHaveProperty('http_methods')
        expect(dataGetResult).toHaveProperty('rpc_methods')
        expect(dataGetResult).toHaveProperty('accept_content_type')
        expect(dataGetResult).toHaveProperty('properties')
        expect(dataGetResult).toHaveProperty('status')

        expect(dataGetResult.status)
            .toMatchObject({
                authenticated: false,
                is_local_account: false
            })

        expect(dataGetResult.http_methods)
            .toEqual(['POST', 'GET']);

        // During testing, for now, there may be more methods than expected, 
        // but the expected methods should be present
        expect(dataGetResult.rpc_methods)
            .toStrictEqual(expect.arrayContaining([
            {
                "method": "logout",
                "options": []
            },
            {
                "method": "login",
                "options": []
            },
            {
                "method": "mfa.get",
                "options": [ "auth_required" ]
            },
            {
                "method": "mfa.login",
                "options": []
            },
            {
                "method": "mfa.rpc",
                "options": [ "auth_required" ]
            },
            {
                "method": "otp.login",
                "options": []
            },
            {
                "method": "profile.get",
                "options": [ "auth_required" ]
            },
            {
                "method": "profile.update",
                "options": [ "auth_required" ]
            },
            {
                "method": "password.reset",
                "options": [ "auth_required" ]
            },
            {
                "method": "heartbeat",
                "options": [ "auth_required" ]
            }
        ]));
    })

    it('should return login information if the login command is present', async () => {
        const { getData } = useAccountRpc()
        const { rpc_methods, properties } = await getData();
     
        if(rpc_methods.find(method => method.method === 'login')){

            const loginProperty = properties.find(property => property.type === 'login');

            expect(loginProperty)
                .toMatchObject({
                    type: "login",
                    enforce_email: true,
                    username_max_chars: 64,
                })
        }
    })

    it('should return 401 error when the user is not logged in', async () => {
        const errorResponse = { response: { data: { success: false, code: 401, result: 'You are not logged in' } } }

        const { exec } = useAccountRpc()

        await expect(exec('mfa.get'))
                .rejects
                .toMatchObject(errorResponse)

        await expect(exec('mfa.rpc'))
                .rejects
                .toMatchObject(errorResponse)

        await expect(exec('profile.get'))
                .rejects
                .toMatchObject(errorResponse)

        await expect(exec('profile.update'))
                .rejects
                .toMatchObject(errorResponse)

        await expect(exec('password.reset'))
                .rejects
                .toMatchObject(errorResponse)

        await expect(exec('heartbeat'))
                .rejects
                .toMatchObject(errorResponse)
    })

  })

  describe('useAccount advanced scenarios', () => {
    it('should handle prepareLogin with proper credential structure', async () => {
      const { prepareLogin } = useAccount()
      
      const loginRequest: UserLoginRequest = await prepareLogin()
      
      // Should contain all required fields for a login request
      expect(loginRequest).toBeDefined()
      expect(loginRequest.finalize).toBeDefined()
      expect(typeof loginRequest.finalize).toBe('function')
      
      // The request should have correct type signature for finalize
      const mockTokenResponse: TokenResponse = {
        result: 'mock-result',
        success: true,
        token: 'mock-token',
        getResultOrThrow: vi.fn()
      }
      
      // Should be able to call finalize with proper types
      expect(() => loginRequest.finalize(mockTokenResponse)).not.toThrow()
    })

    it('should maintain proper TypeScript types across API calls', () => {
      const account: AccountApi = useAccount()
      
      // Verify all methods are present with correct signatures
      expect(account.prepareLogin).toBeDefined()
      expect(account.login).toBeDefined()
      expect(account.logout).toBeDefined()
      expect(account.resetPassword).toBeDefined()
      expect(account.heartbeat).toBeDefined()
      
      // Test type constraints
      const credentials: UserLoginCredential = {
        userName: 'test@example.com',
        password: 'testPassword123'
      }
      
      // These should all return Promises with correct types
      expect(account.prepareLogin()).toBeInstanceOf(Promise)
      expect(account.login(credentials)).toBeInstanceOf(Promise)
      expect(account.logout()).toBeInstanceOf(Promise)
      expect(account.resetPassword('old', 'new', {})).toBeInstanceOf(Promise)
      expect(account.heartbeat()).toBeInstanceOf(Promise)
    })
  })

  describe('useAccount activity scenario', () => {

    const { getData } = useAccountRpc()
    const { login, logout, resetPassword, heartbeat } = useAccount()

    it('should log the test user in', () => {
      expect(login<any>(testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })
    })

    it('should verify the user is logged in successfully', async () => {
      const result = await getData();

      expect(result.status).toMatchObject({ authenticated: true, is_local_account: true });
      expect(isLoggedIn(result)).toBe(true);
    })

    it('should fail to log the user in again if already authenticated', () => {
        expect(login<any>(testUser))
            .rejects
            .toMatchObject({ response: { data: { code: 409, success: false }}})
    })

    it('should define resetPassword function of the correct type', () => {

        expect(resetPassword).toBeDefined()
        expect(typeof resetPassword).toBe('function')
    })

    it('should successfully update the test users password', () => {
        expect(resetPassword(testUser.password, 'Password123!', {}))
            .resolves
            .toMatchObject({ success: true })
    })

    it('should fail to reset the test user password when its the same password as before', () => {
        expect(resetPassword(testUser.password, 'Password123!', {}))
            .resolves
            .toMatchObject({ success: false })
    })

    //Change password back
    it('should change the password back', () => {
        expect(resetPassword('Password123!', testUser.password, {}))
            .resolves
            .toMatchObject({ success: true })
    })

    //The changed password should fail now
    it('should fail with the old password', () => {
        expect(resetPassword('Password123!', testUser.password, {}))
            .resolves
            .toMatchObject({ success: false })
    })

    it('should should successfully send a heartbeat', async () => {
       // Heartbeat should be async
       const result = heartbeat()
       expect(result).toBeInstanceOf(Promise)

       // Wait for completion
       await result
       expect(result).toBeDefined()
       expect(typeof result).toBe('object')
    })

    it('should log the user out', () => {
        expect(logout())
            .resolves
            .toMatchObject({ code: 200, success: true })
    })
    
  })

  describe('useProfile advanced activity', () => {

    const { getData } = useAccountRpc()
    const { login, logout } = useAccount()
    const { getProfile, canGetProfile, canUpdateProfile, updateProfile } = useProfile()

    it('should log the test user in before accessing profile', async () => {
        expect(login<any>(testUser))
                .resolves
                .toMatchObject({ code: 200, success: true })
    })

    it('should retrieve the user profile data object', async () => {
      const accStatus = await getData();

      expect(isLoggedIn(accStatus)).toBe(true);
      expect(canGetProfile(accStatus)).toBe(true);
      expect(getProfile())
        .resolves
        .toMatchObject({ email: 'test@test.com' })
    })

    it('should update the user profile data object', async () => {
      const accStatus = await getData();

      expect(canUpdateProfile(accStatus)).toBe(true);

      expect(updateProfile({ first: 'New Name' } as any))
        .resolves
        .toMatchObject({ success: true });

      expect(getProfile())
        .resolves
        .toMatchObject({ first: 'New Name' })
    })

    it('should fail to update the user profile data object with invalid data', async () => {
      const accStatus = await getData();

      expect(canUpdateProfile(accStatus)).toBe(true);

      expect(updateProfile({ first: 123 } as any))
        .rejects
        .toThrow();
    })

    it('should log the user out after profile access', async () => {
      expect(logout())
        .resolves
        .toMatchObject({ code: 200, success: true })

      const accStatus = await getData();
      expect(isLoggedIn(accStatus)).toBe(false);
    })
  })

})
