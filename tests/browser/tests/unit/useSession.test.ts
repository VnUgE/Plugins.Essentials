import { describe, it, expect, beforeEach } from 'vitest'
import {
  useSession,
  getDefaultSessionConfig,
  type Session,
  type ClientCredential,
  type TokenResponse,
  type SessionConfig
} from '@vnuge/vnlib.browser'

import { vnlib } from '../../fixtures'

describe('Session API - Unit Tests', () => {

  describe('useSession - API Structure', () => {
    it('should create session instance with all required methods', () => {
      const session = useSession(vnlib)

      expect(session).toBeDefined()
      expect(session.getClientSecInfo).toBeTypeOf('function')
      expect(session.resetClientSecInfo).toBeTypeOf('function')
      expect(session.clearClientSecInfo).toBeTypeOf('function')
      expect(session.decryptPayload).toBeTypeOf('function')
      expect(session.decryptAndHash).toBeTypeOf('function')
      expect(session.updateCredentials).toBeTypeOf('function')
      expect(session.generateOneTimeToken).toBeTypeOf('function')
    })

    it('should have different instances but share state', () => {
      // useSession is NOT memoized - it creates storage slots per call
      // This is intentional as each call might have different config
      const session1 = useSession(vnlib)
      const session2 = useSession(vnlib)

      // Different instances
      expect(session1).not.toBe(session2)

      // But both share the same underlying storage and will see the same credentials
      expect(session1.getClientSecInfo).toBeDefined()
      expect(session2.getClientSecInfo).toBeDefined()
    })

    it('should share credential state across multiple session instances', async () => {
      // Create two separate session instances from the same config
      const session1 = useSession(vnlib)
      const session2 = useSession(vnlib)

      // Clear any existing state
      await session1.clearClientSecInfo()

      // Generate credentials with first instance
      const creds1 = await session1.getClientSecInfo()

      // Second instance should see the same credentials (shared storage)
      const creds2 = await session2.getClientSecInfo()

      expect(creds1.browserId).toBe(creds2.browserId)
      expect(creds1.publicKey).toBe(creds2.publicKey)

      // Reset from second instance
      const reset = await session2.resetClientSecInfo()

      // First instance should see the new credentials
      const check = await session1.getClientSecInfo()

      expect(check.browserId).toBe(reset.browserId)
      expect(check.publicKey).toBe(reset.publicKey)
      expect(check.browserId).not.toBe(creds1.browserId)
    })
  })

  describe('Session Operations - Client-side', () => {
    let session: Session

    beforeEach(async () => {
      session = useSession(vnlib)
      // Clear any previous state
      await session.clearClientSecInfo()
    })

    it('should clear client security info (idempotent)', async () => {
      // clearClientSecInfo is idempotent - safe to call multiple times
      await session.clearClientSecInfo()
      await session.clearClientSecInfo()
      await session.clearClientSecInfo()

      // Verify cleared by checking new credentials are generated
      const newCreds = await session.getClientSecInfo()
      expect(newCreds.browserId).toBeTruthy()
    })

    it('should generate client security info', async () => {
      const clientInfo: ClientCredential = await session.getClientSecInfo()

      expect(clientInfo).toBeDefined()
      expect(clientInfo).toBeTypeOf('object')

      expect(clientInfo.browserId).toBeDefined()
      expect(clientInfo.browserId).toBeTypeOf('string')
      expect(clientInfo.browserId).lengthOf.above(0)

      expect(clientInfo.publicKey).toBeDefined()
      expect(clientInfo.publicKey).toBeTypeOf('string')
      expect(clientInfo.publicKey).lengthOf.above(0)
    })

    it('should generate consistent browserId across calls', async () => {
      const info1 = await session.getClientSecInfo()
      const info2 = await session.getClientSecInfo()

      // browserId should be stable across calls
      expect(info1.browserId).toBe(info2.browserId)
      expect(info1.publicKey).toBe(info2.publicKey)
    })

    it('should reset client security info with new credentials', async () => {
      const original = await session.getClientSecInfo()
      const reset = await session.resetClientSecInfo()

      // Should generate new credentials
      expect(reset.browserId).not.toBe(original.browserId)
      expect(reset.publicKey).not.toBe(original.publicKey)
    })

    it('should return null when no session token loaded', async () => {
      // Without calling updateCredentials, no HMAC key exists for signing
      const token = await session.generateOneTimeToken('/test/path')
      expect(token).toBeNull()
    })
  })

  // NOTE: updateCredentials, decryptPayload, and decryptAndHash require server-encrypted
  // data and cannot be properly unit tested. These are E2E test concerns.

  describe('Credential Management', () => {
    let session: Session

    beforeEach(async () => {
      session = useSession(vnlib)
      await session.clearClientSecInfo()
    })

    it('should generate credentials on first access', async () => {
      const { browserId, publicKey } = await session.getClientSecInfo()

      expect(browserId).toBeTruthy()
      expect(publicKey).toBeTruthy()
    })

    it('should maintain credentials across multiple gets', async () => {
      const creds1 = await session.getClientSecInfo()
      const creds2 = await session.getClientSecInfo()
      const creds3 = await session.getClientSecInfo()

      expect(creds1).toEqual(creds2)
      expect(creds2).toEqual(creds3)
    })

    it('should fully rotate credentials on reset', async () => {
      const original = await session.getClientSecInfo()
      const rotated = await session.resetClientSecInfo()

      // Everything should be different
      expect(rotated).not.toEqual(original)
      expect(rotated.browserId).not.toBe(original.browserId)
      expect(rotated.publicKey).not.toBe(original.publicKey)

      // New credentials should persist
      const check = await session.getClientSecInfo()
      expect(check).toEqual(rotated)
    })

    it('should clear all credentials completely', async () => {
      await session.getClientSecInfo() // Ensure credentials exist
      await session.clearClientSecInfo()

      // After clear, getClientSecInfo should generate new ones
      const newCreds = await session.getClientSecInfo()
      expect(newCreds.browserId).toBeTruthy()
      expect(newCreds.publicKey).toBeTruthy()
    })
  })

  describe('Configuration', () => {
    it('should provide default session config', () => {
      const config: SessionConfig = getDefaultSessionConfig()

      expect(config).toBeDefined()
      expect(config).toBeTypeOf('object')

      // Should have key algorithm configuration
      expect(config.keyAlgorithm).toBeDefined()
    })

    it('should have valid configuration properties', () => {
      const config = getDefaultSessionConfig()

      expect(config.browserIdSize).toBeDefined()
      expect(config.browserIdSize).toBeTypeOf('number')
      expect(config.browserIdSize).toBeGreaterThan(0)

      expect(config.signatureAlgorithm).toBeDefined()
      expect(config.signatureAlgorithm).toBeTypeOf('string')

      expect(config.keyAlgorithm).toBeDefined()
    })
  })

  describe('Type Safety', () => {
    it('should have correct return types', async () => {
      const session = useSession(vnlib)

      // Test actual return types match interface
      const info: ClientCredential = await session.getClientSecInfo()
      expect(info.browserId).toBeDefined()
      expect(info.publicKey).toBeDefined()

      const token: string | null = await session.generateOneTimeToken('/path')
      // Token can be null (no credentials) or string
      if (token !== null) {
        expect(token).toBeTypeOf('string')
      }

      const reset: ClientCredential = await session.resetClientSecInfo()
      expect(reset.browserId).toBeDefined()
      expect(reset.publicKey).toBeDefined()
    })

    it('should match TokenResponse interface shape', () => {
      // Verify the interface shape is correct (compile-time check)
      const mockToken: TokenResponse = {
        success: true,
        result: { data: 'test' },
        token: 'encrypted-token-string',
        getResultOrThrow: () => ({ data: 'test' })
      }

      expect(mockToken.success).toBe(true)
      expect(mockToken.token).toBe('encrypted-token-string')
      // Note: updateCredentials cannot be tested in unit tests as it requires
      // server-encrypted data. This is verified in E2E tests.
    })
  })

  describe('OTP Token Generation', () => {
    it('should return null when no session token exists', async () => {
      const session = useSession(vnlib)

      // Without updateCredentials, no HMAC key exists for signing
      const emptyPath = await session.generateOneTimeToken('')
      const rootPath = await session.generateOneTimeToken('/')
      const apiPath = await session.generateOneTimeToken('/api/endpoint')

      expect(emptyPath).toBeNull()
      expect(rootPath).toBeNull()
      expect(apiPath).toBeNull()
    })

    it('should handle long paths without crashing', async () => {
      const session = useSession(vnlib)
      const longPath = '/api' + '/segment'.repeat(200)

      const token = await session.generateOneTimeToken(longPath)
      expect(token).toBeNull() // Still null (no credentials), but doesn't crash
    })
  })

  describe('State Isolation', () => {
    it('should handle repeated operations without corruption', async () => {
      const session = useSession(vnlib)

      // Perform lifecycle operations
      const initial = await session.getClientSecInfo()
      expect(initial.browserId).toBeTruthy()

      const rotated = await session.resetClientSecInfo()
      expect(rotated.browserId).not.toBe(initial.browserId)

      await session.clearClientSecInfo()

      const regenerated = await session.getClientSecInfo()
      expect(regenerated.browserId).toBeTruthy()
      expect(regenerated.browserId).not.toBe(rotated.browserId)
    })
  })
})
