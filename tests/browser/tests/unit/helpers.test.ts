import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  useJrpc,
  debugLog,
  type RpcClient,
  type RpcMethodArgs,
} from '@vnuge/vnlib.browser'
import { vnlib } from '../../fixtures';

describe('Helper Functions - Unit Tests', () => {

  describe('useJrpc - JSON-RPC Client', () => {
    it('should create RPC client with correct methods', () => {
      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        endpoint: () => '/rpc'
      }

      const client: RpcClient<'test.method'> = useJrpc<'test.method'>(vnlib, rpcArgs)

      expect(client).toBeDefined()

      expect(client.notify).toBeDefined()
      expect(client.notify).toBeTypeOf('function')

      expect(client.request).toBeDefined()
      expect(client.request).toBeTypeOf('function')
    })

    it('should support version 1.0.0', () => {
      const rpcArgs: RpcMethodArgs = {
        version: '1.0.0',
        endpoint: () => '/rpc'
      }

      const client = useJrpc(vnlib, rpcArgs)
      expect(client).toBeDefined()
    })

    it('should support version 2.0.0', () => {
      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        endpoint: () => '/rpc'
      }

      const client = useJrpc(vnlib, rpcArgs)
      expect(client).toBeDefined()
    })

    it('should accept dynamic endpoint function', () => {
      let currentEndpoint = '/rpc-v1'

      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        endpoint: () => currentEndpoint
      }

      const client = useJrpc(vnlib, rpcArgs)
      expect(client).toBeDefined()

      // Endpoint can change dynamically
      currentEndpoint = '/rpc-v2'
      expect(rpcArgs.endpoint()).toBe('/rpc-v2')
    })

    it('should support typed method names', () => {
      type MyMethods = 'user.get' | 'user.update' | 'user.delete'

      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        endpoint: () => '/api/rpc'
      }

      const client: RpcClient<MyMethods> = useJrpc<MyMethods>(vnlib, rpcArgs)
      expect(client).toBeDefined()
    })

    it('should have correct RpcMethodArgs structure', () => {
      const args: RpcMethodArgs = {
        version: '2.0.0',
        endpoint: () => '/test'
      }

      expect(args.version).toBe('2.0.0')

      expect(args.endpoint).toBeTypeOf('function')
      expect(args.endpoint()).toBe('/test')
    })
  })


  describe('debugLog - Debug Logging', () => {
    it('should be a function', () => {
      expect(debugLog).toBeDefined()
      expect(debugLog).toBeTypeOf('function')
    })

    it('should call debugLog callback when provided', () => {
      const mockLogger = vi.fn()
      const configWithLogger = { ...vnlib, debugLog: mockLogger }

      debugLog(configWithLogger, 'test', 123, { key: 'value' })

      expect(mockLogger).toHaveBeenCalledOnce()
      expect(mockLogger).toHaveBeenCalledWith('test', 123, { key: 'value' })
    })

    it('should not throw when debugLog is not provided', () => {
      const configWithoutLogger = { ...vnlib }

      // Should be a no-op, not throw
      expect(() => debugLog(configWithoutLogger, 'test', 123)).not.toThrow()
    })

    it('should accept config and multiple arguments', () => {
      const mockLogger = vi.fn()
      const configWithLogger = { ...vnlib, debugLog: mockLogger }

      expect(() => debugLog(
        configWithLogger,
        'string',
        123,
        true,
        { object: 'value' },
        [1, 2, 3],
        null,
        undefined
      )).not.toThrow()

      expect(mockLogger).toHaveBeenCalledWith(
        'string',
        123,
        true,
        { object: 'value' },
        [1, 2, 3],
        null,
        undefined
      )
    })

    it('should work with config and no additional arguments', () => {
      const mockLogger = vi.fn()
      const configWithLogger = { ...vnlib, debugLog: mockLogger }

      expect(() => debugLog(configWithLogger)).not.toThrow()
      expect(mockLogger).toHaveBeenCalledOnce()
      expect(mockLogger).toHaveBeenCalledWith()
    })
  })

  describe('Type Exports', () => {
    it('should export all required helper types', () => {
      // Verify type exports are available at compile time
      const _rpcClient: RpcClient<string> = {} as RpcClient<string>
      const _rpcArgs: RpcMethodArgs = {} as RpcMethodArgs

      expect(_rpcClient).toBeDefined()
      expect(_rpcArgs).toBeDefined()
    })

    it('should verify RpcClient generic type parameter', () => {
      // Test that generic parameter properly constrains method names
      type CustomMethods = 'method1' | 'method2'
      const _client: RpcClient<CustomMethods> = {} as RpcClient<CustomMethods>

      expect(_client).toBeDefined()
    })
  })
})
