import { describe, expect, it } from 'vitest';

import {
  fidoMfaProcessor,
  totpMfaProcessor,
  useMfaLogin,
  type MfaLoginManager,
  type MfaTypeProcessor,
  type MfaContinuation,
  type MfaMethod,
  type WebMessage
} from '@vnuge/vnlib.browser'
import { vnlib as config } from '../../fixtures';

describe('MFA Login - Unit Tests', () => {

  describe('useMfaLogin - API Structure', () => {
    it('should create MFA login manager with correct methods', () => {
      const mfaLogin: MfaLoginManager = useMfaLogin(config, {
        handlers: [totpMfaProcessor(), fidoMfaProcessor()]
      })

      expect(mfaLogin).toBeDefined()

      expect(mfaLogin.isSupported).toBeDefined()
      expect(mfaLogin.isSupported).toBeTypeOf('function')

      expect(mfaLogin.login).toBeDefined()
      expect(mfaLogin.login).toBeTypeOf('function')

      expect(mfaLogin.isMfaResponse).toBeDefined()
      expect(mfaLogin.isMfaResponse).toBeTypeOf('function')
    })

    it('should verify TOTP is supported and FIDO requires WebAuthn (unavailable in jsdom)', () => {
      const { isSupported } = useMfaLogin(config, {
        handlers: [totpMfaProcessor(), fidoMfaProcessor()]
      })

      // FIDO requires WebAuthn API which isn't available in jsdom
      expect(isSupported('fido')).toBe(false)
      // TOTP is always supported (no browser API dependency)
      expect(isSupported('totp')).toBe(true)
    })

    it('should return false for unsupported MFA methods', () => {
      const { isSupported } = useMfaLogin(config, {
        handlers: [totpMfaProcessor()] // Only TOTP loaded
      })

      expect(isSupported('fido')).toBe(false)
      expect(isSupported('totp')).toBe(true)
    })

    it('should handle empty handlers array', () => {
      const { isSupported } = useMfaLogin(config, {
        handlers: []
      })

      expect(isSupported('fido')).toBe(false)
      expect(isSupported('totp')).toBe(false)
      expect(isSupported('pkotp')).toBe(false)
    })

    it('should correctly identify MFA continuation responses', () => {
      const { isMfaResponse } = useMfaLogin(config, {
        handlers: [totpMfaProcessor(), fidoMfaProcessor()]
      })

      // Mock MFA continuation response with actual methods
      const mfaContinuation: MfaContinuation = {
        methods: [
          { type: 'totp', submit: async <T>() => ({} as WebMessage<T>) },
          { type: 'fido', submit: async <T>() => ({} as WebMessage<T>) }
        ],
        expires: 300
      }

      // Mock regular web message response
      const regularResponse: WebMessage = {
        success: true,
        result: {}
      } as WebMessage

      expect(isMfaResponse(mfaContinuation)).toBe(true)
      expect(isMfaResponse(regularResponse)).toBe(false)
    })

    it('should handle MFA response with empty methods array', () => {
      const { isMfaResponse } = useMfaLogin(config, {
        handlers: [totpMfaProcessor()]
      })

      // Empty methods array should return false (no valid continuation)
      const emptyMfa: MfaContinuation = {
        methods: [],
        expires: 300
      }

      expect(isMfaResponse(emptyMfa)).toBe(false)
    })
  })

  describe('MFA Processors - API Structure', () => {
    it('should verify TOTP processor has correct structure', () => {
      const processor: MfaTypeProcessor = totpMfaProcessor()

      expect(processor).toBeDefined()
      expect(processor.type).toBe('totp')

      expect(processor.isSupported).toBeDefined()
      expect(processor.isSupported).toBeTypeOf('function')

      expect(processor.getContinuation).toBeDefined()
      expect(processor.getContinuation).toBeTypeOf('function')
    })

    it('should verify FIDO processor has correct structure', () => {
      const processor: MfaTypeProcessor = fidoMfaProcessor()

      expect(processor).toBeDefined()
      expect(processor.type).toBe('fido')

      expect(processor.isSupported).toBeDefined()
      expect(processor.isSupported).toBeTypeOf('function')

      expect(processor.getContinuation).toBeDefined()
      expect(processor.getContinuation).toBeTypeOf('function')
    })

    it('should verify TOTP is always supported', () => {
      const processor = totpMfaProcessor()
      expect(processor.isSupported()).toBe(true)
    })

    it('should verify FIDO support depends on WebAuthn API', () => {
      const processor = fidoMfaProcessor()
      const hasWebAuthn = typeof window !== 'undefined' &&
        window.PublicKeyCredential !== undefined

      expect(processor.isSupported()).toBe(hasWebAuthn)
    })
  })

  describe('MFA Method Types', () => {
    it('should support all expected MFA method types', () => {
      const methods: MfaMethod[] = ['totp', 'fido', 'pkotp']

      // Verify all method types are valid
      methods.forEach(method => {
        expect(method).toBeDefined()
        expect(method).toBeTypeOf('string')
      })
    })
  })

})
