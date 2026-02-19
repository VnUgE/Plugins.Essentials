import { describe, expect, it } from 'vitest';
import {
  useMfaApi,
  mfaGetDataFor,
  type MfaApi,
  type MfaMethod,
  type MfaGetResponse,
  type MfaRequestJson,
  type AccountRpcGetResult
} from '@vnuge/vnlib.browser'
import { vnlib } from '../../fixtures';

describe('MFA API - Unit Tests', () => {

  describe('useMfaApi - API Structure', () => {
    it('should create MFA API with correct methods', () => {
      const api: MfaApi = useMfaApi(vnlib)

      expect(api).toBeDefined()

      expect(api.isEnabled).toBeDefined()
      expect(api.isEnabled).toBeTypeOf('function')

      expect(api.getData).toBeDefined()
      expect(api.getData).toBeTypeOf('function')

      expect(api.sendRequest).toBeDefined()
      expect(api.sendRequest).toBeTypeOf('function')
    })

    it('should check if MFA is enabled from RPC methods', () => {
      const { isEnabled } = useMfaApi(vnlib)

      const enabledData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: [
          { method: 'mfa.get', options: [] }
        ]
      }

      const disabledData: Pick<AccountRpcGetResult, 'rpc_methods'> = {
        rpc_methods: []
      }

      expect(isEnabled(enabledData)).toBe(true)
      expect(isEnabled(disabledData)).toBe(false)
    })
  })

  describe('MFA Method Types', () => {
    it('should support all expected MFA method types', () => {
      const methods: MfaMethod[] = ['totp', 'fido', 'pkotp']

      methods.forEach(method => {
        expect(method).toBeDefined()
        expect(method).toBeTypeOf('string')
      })
    })
  })

  describe('MfaRequestJson Structure', () => {
    it('should have correct request structure', () => {
      const request: MfaRequestJson = {
        type: 'totp',
        action: 'enable',
        password: 'user-password'
      }

      expect(request.type).toBe('totp')
      expect(request.action).toBe('enable')
      expect(request.password).toBe('user-password')
    })

    it('should allow password to be optional', () => {
      const request: MfaRequestJson = {
        type: 'fido',
        action: 'disable'
      }

      expect(request.password).toBeUndefined()
    })

    it('should allow additional properties', () => {
      const request: MfaRequestJson = {
        type: 'totp',
        action: 'verify',
        code: '123456',
        customField: 'custom-value'
      }

      expect(request.type).toBe('totp')
      expect((request as any).code).toBe('123456')
      expect((request as any).customField).toBe('custom-value')
    })
  })

  describe('mfaGetDataFor - Helper Function', () => {
    it('should extract data for specific MFA type', () => {
      const mfaData: Pick<MfaGetResponse, 'methods'> = {
        methods: [
          { type: 'totp', enabled: true, data: { secret: 'TOTP_SECRET' } },
          { type: 'fido', enabled: false, data: { keys: [] } }
        ]
      }

      const totpData = mfaGetDataFor<{ secret: string }>(mfaData, 'totp')
      expect(totpData).toBeDefined()
      expect(totpData?.secret).toBe('TOTP_SECRET')

      const fidoData = mfaGetDataFor<{ keys: any[] }>(mfaData, 'fido')
      expect(fidoData).toBeDefined()
      expect(fidoData?.keys).toBeInstanceOf(Array)
    })

    it('should return undefined for non-existent type', () => {
      const mfaData: Pick<MfaGetResponse, 'methods'> = {
        methods: [
          { type: 'totp', enabled: true, data: {} }
        ]
      }

      const pkotpData = mfaGetDataFor(mfaData, 'pkotp')
      expect(pkotpData).toBeUndefined()
    })

    it('should handle empty methods array', () => {
      const mfaData: Pick<MfaGetResponse, 'methods'> = {
        methods: []
      }

      const totpData = mfaGetDataFor(mfaData, 'totp')
      expect(totpData).toBeUndefined()
    })
  })

  describe('MfaGetResponse Structure', () => {
    it('should have correct response structure', () => {
      const response: MfaGetResponse = {
        supported_methods: ['totp', 'fido'],
        methods: [
          { type: 'totp', enabled: true, data: {} },
          { type: 'fido', enabled: false, data: {} }
        ]
      }

      expect(response.supported_methods).toBeDefined()
      expect(response.supported_methods).toBeInstanceOf(Array)

      expect(response.methods).toBeDefined()
      expect(response.methods).toBeInstanceOf(Array)
    })

    it('should properly type method responses', () => {
      const response: MfaGetResponse = {
        supported_methods: ['totp'],
        methods: [
          {
            type: 'totp',
            enabled: true,
            data: {
              secret: 'SECRET',
              qr_code: 'QR_CODE_URL'
            }
          }
        ]
      }

      expect(response.methods[0].type).toBe('totp')
      expect(response.methods[0].enabled).toBe(true)
      expect(response.methods[0].data).toBeDefined()
    })
  })

})
