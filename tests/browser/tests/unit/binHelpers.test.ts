import { describe, it, expect } from 'vitest'
import {
  LongToArray,
  IntToArray,
  Base64ToArray,
  Base64ToUint8Array,
  Utf8StringToBuffer,
  ArrayBuffToBase64,
  ArrayToHexString,
  isCryptoSupported,
  getRandomHex
} from '@vnuge/vnlib.browser'

describe('Binary Helpers - Unit Tests', () => {

  describe('Array Conversions', () => {
    it('should convert Long to Array', () => {
      const result = LongToArray(1234567890)
      
      expect(result).toBeInstanceOf(Array)
      expect(result).lengthOf(8)
      // Verify all elements are numbers
      result.forEach(n => expect(n).toBeTypeOf('number'))
    })

    it('should convert Int to Array', () => {
      const result = IntToArray(12345)
      
      expect(result).toBeInstanceOf(Array)
      expect(result).lengthOf(4)
      // Verify all elements are numbers
      result.forEach(n => expect(n).toBeTypeOf('number'))
    })

    it('should handle edge cases for Long conversion', () => {
      expect(LongToArray(0)).lengthOf(8)
      expect(LongToArray(Number.MAX_SAFE_INTEGER)).lengthOf(8)
      expect(LongToArray(-1)).lengthOf(8)
    })

    it('should handle edge cases for Int conversion', () => {
      expect(IntToArray(0)).lengthOf(4)
      expect(IntToArray(-1)).lengthOf(4)
      expect(IntToArray(2147483647)).lengthOf(4) // Max int32
    })

    it('should convert Base64 to Array', () => {
      const base64 = 'SGVsbG8gV29ybGQ=' // "Hello World"
      const result = Base64ToArray(base64)
      
      expect(result).toBeInstanceOf(Array)
      expect(result).lengthOf(11) // "Hello World" is 11 bytes
    })

    it('should convert Base64 to Uint8Array', () => {
      const base64 = 'SGVsbG8gV29ybGQ=' // "Hello World"
      const result = Base64ToUint8Array(base64)
      
      expect(result).toBeInstanceOf(Uint8Array)
      expect(result).lengthOf(11)
      
      // Verify actual content
      expect(result[0]).toBe(72) // 'H'
      expect(result[1]).toBe(101) // 'e'
    })

    it('should handle empty Base64 strings', () => {
      const result = Base64ToArray('')
      
      expect(result).toBeInstanceOf(Array)
      expect(result).lengthOf(0)
    })

    it('should convert UTF8 String to Buffer', () => {
      const str = 'Hello World'
      const result = Utf8StringToBuffer(str)
      expect(result).toBeInstanceOf(Array)
      expect(result.length).toBeGreaterThan(0)
    })

    it('should handle UTF8 with special characters', () => {
      const str = 'Hello 世界 🌍'
      const result = Utf8StringToBuffer(str)
      expect(result).toBeInstanceOf(Array)
      expect(result.length).toBeGreaterThan(str.length) // Unicode takes more bytes
    })

    it('should handle empty strings', () => {
      const result = Utf8StringToBuffer('')
      expect(result).toBeInstanceOf(Array)
      expect(result).lengthOf(0)
    })

    it('should convert ArrayBuffer to Base64', () => {
      const buffer = new Uint8Array([72, 101, 108, 108, 111]).buffer // "Hello"
      const result = ArrayBuffToBase64(buffer)
      
      expect(result).toBeTypeOf('string')
      expect(result).lengthOf.above(0)
    })

    it('should roundtrip Base64 conversions', () => {
      const original = 'SGVsbG8gV29ybGQ='
      const array = Base64ToUint8Array(original)
      const back = ArrayBuffToBase64(array.buffer)
      expect(back).toBe(original)
    })

    it('should convert Array to Hex String', () => {
      const arr = new Uint8Array([255, 0, 128])
      const result = ArrayToHexString(arr)
      
      expect(result).toBeTypeOf('string')
      expect(result).toMatch(/^[0-9a-f]+$/i)
      expect(result.toLowerCase()).toBe('ff0080')
    })

    it('should handle empty arrays for hex conversion', () => {
      const result = ArrayToHexString(new Uint8Array([]))
      expect(result).toBe('')
    })

    it('should handle single byte hex conversion', () => {
      const result = ArrayToHexString(new Uint8Array([42]))
      expect(result.toLowerCase()).toBe('2a')
    })
  })

  describe('Crypto Helpers', () => {
    it('should check if crypto is supported', () => {
      const supported = isCryptoSupported()
      
      expect(supported).toBeTypeOf('boolean')
      
      // In test environment with webcrypto-shims, should be true
      expect(supported).toBe(true)
    })

    it('should generate random hex string', async () => {
      const length = 16
      const hex = getRandomHex(length)
      
      expect(hex).toBeTypeOf('string')
      expect(hex).toMatch(/^[0-9a-f]+$/i)
      expect(hex).lengthOf(length * 2) // Hex is 2 chars per byte
    })

    it('should handle various lengths for random hex', async () => {
      const lengths = [1, 8, 16, 32, 64]
      
      for (const length of lengths) {
        const hex = getRandomHex(length)
        expect(hex).lengthOf(length * 2)
        expect(hex).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })
})
