import { describe, expect, it, vi, beforeEach } from 'vitest';
import { 
  useJrpc,
  createStorageSlot,
  debugLog,
  type RpcClient,
  type RpcMethodArgs,
  type AsyncStorageItem
} from '@vnuge/vnlib.browser'
import { vnlib } from '../../main';

describe('Helper Functions - Unit Tests', () => {

  describe('useJrpc - JSON-RPC Client', () => {
    it('should create RPC client with correct methods', () => {
      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        config: vnlib,
        endpoint: () => '/rpc'
      }
      
      const client: RpcClient<'test.method'> = useJrpc<'test.method'>(rpcArgs)
      
      expect(client).toBeDefined()
      
      expect(client.notify).toBeDefined()
      expect(client.notify).toBeTypeOf('function')
      
      expect(client.request).toBeDefined()
      expect(client.request).toBeTypeOf('function')
    })

    it('should support version 1.0.0', () => {
      const rpcArgs: RpcMethodArgs = {
        version: '1.0.0',
        config: vnlib,
        endpoint: () => '/rpc'
      }
      
      const client = useJrpc(rpcArgs)
      expect(client).toBeDefined()
    })

    it('should support version 2.0.0', () => {
      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        config: vnlib,
        endpoint: () => '/rpc'
      }
      
      const client = useJrpc(rpcArgs)
      expect(client).toBeDefined()
    })

    it('should accept dynamic endpoint function', () => {
      let currentEndpoint = '/rpc-v1'
      
      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        config: vnlib,
        endpoint: () => currentEndpoint
      }
      
      const client = useJrpc(rpcArgs)
      expect(client).toBeDefined()
      
      // Endpoint can change dynamically
      currentEndpoint = '/rpc-v2'
      expect(rpcArgs.endpoint()).toBe('/rpc-v2')
    })

    it('should support typed method names', () => {
      type MyMethods = 'user.get' | 'user.update' | 'user.delete'
      
      const rpcArgs: RpcMethodArgs = {
        version: '2.0.0',
        config: vnlib,
        endpoint: () => '/api/rpc'
      }
      
      const client: RpcClient<MyMethods> = useJrpc<MyMethods>(rpcArgs)
      
      expect(client).toBeDefined()
    })

    it('should have correct RpcMethodArgs structure', () => {
      const args: RpcMethodArgs = {
        version: '2.0.0',
        config: vnlib,
        endpoint: () => '/test'
      }
      
      expect(args.version).toBe('2.0.0')
      expect(args.config).toBe(vnlib)
      
      expect(args.endpoint).toBeTypeOf('function')
      expect(args.endpoint()).toBe('/test')
    })
  })

  describe('createStorageSlot - Async Storage', () => {
    let mockStorage: {
      getItem: (key: string) => Promise<string | null>
      setItem: (key: string, value: string) => Promise<void>
      removeItem: (key: string) => Promise<void>
    }

    beforeEach(() => {
      mockStorage = {
        getItem: vi.fn().mockResolvedValue(null) as any,
        setItem: vi.fn().mockResolvedValue(undefined) as any,
        removeItem: vi.fn().mockResolvedValue(undefined) as any
      }
    })

    it('should create storage slot with getter/setter for each property', () => {
      type Settings = {
        theme: string
        notifications: boolean
      }

      const defaultValue: Settings = {
        theme: 'light',
        notifications: true
      }
      
      const slot: AsyncStorageItem<Settings> = createStorageSlot(
        mockStorage,
        'settings',
        defaultValue
      )
      
      expect(slot).toBeDefined()
      
      expect(slot.theme).toBeDefined()
      expect(slot.theme.get).toBeDefined()
      expect(slot.theme.get).toBeTypeOf('function')
      expect(slot.theme.set).toBeDefined()
      expect(slot.theme.set).toBeTypeOf('function')
      
      expect(slot.notifications).toBeDefined()
      expect(slot.notifications.get).toBeDefined()
      expect(slot.notifications.get).toBeTypeOf('function')
      expect(slot.notifications.set).toBeDefined()
      expect(slot.notifications.set).toBeTypeOf('function')
    })

    it('should work with complex object types', () => {
      type UserPrefs = {
        profile: {
          name: string
          email: string
        }
        settings: {
          darkMode: boolean
          fontSize: number
        }
      }

      const defaultValue: UserPrefs = {
        profile: { name: '', email: '' },
        settings: { darkMode: false, fontSize: 14 }
      }
      
      const slot: AsyncStorageItem<UserPrefs> = createStorageSlot(
        mockStorage,
        'user-prefs',
        defaultValue
      )
      
      expect(slot.profile).toBeDefined()
      expect(slot.settings).toBeDefined()
    })

    it('should work with primitive types', () => {
      type SimpleData = {
        count: number
        message: string
        enabled: boolean
      }

      const defaultValue: SimpleData = {
        count: 0,
        message: 'default',
        enabled: false
      }
      
      const slot = createStorageSlot(mockStorage, 'simple', defaultValue)
      
      expect(slot.count).toBeDefined()
      expect(slot.message).toBeDefined()
      expect(slot.enabled).toBeDefined()
    })

    it('should provide AsyncStorageItem with correct type projection', async () => {
      type Data = { value: number }
      const slot: AsyncStorageItem<Data> = createStorageSlot(
        mockStorage,
        'test',
        { value: 42 }
      )
      
      // Verify type structure at runtime
      expect(slot.value).toBeDefined()
      
      expect(slot.value.get).toBeTypeOf('function')
      expect(slot.value.set).toBeTypeOf('function')
      
      // Verify get returns a Promise
      const getPromise = slot.value.get()
      expect(getPromise).toBeInstanceOf(Promise)
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
      const _storageItem: AsyncStorageItem<{ test: string }> = {} as AsyncStorageItem<{ test: string }>
      
      expect(_rpcClient).toBeDefined()
      expect(_rpcArgs).toBeDefined()
      expect(_storageItem).toBeDefined()
    })

    it('should verify RpcClient generic type parameter', () => {
      // Test that generic parameter properly constrains method names
      type CustomMethods = 'method1' | 'method2'
      const _client: RpcClient<CustomMethods> = {} as RpcClient<CustomMethods>
      
      expect(_client).toBeDefined()
    })

    it('should verify AsyncStorageItem type projection', () => {
      type TestData = {
        prop1: string
        prop2: number
      }
      
      const _item: AsyncStorageItem<TestData> = {} as AsyncStorageItem<TestData>
      
      // Type system should project each property into get/set pair
      expect(_item).toBeDefined()
    })
  })
})
