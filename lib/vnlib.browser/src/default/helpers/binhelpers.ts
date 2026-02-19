// Copyright (c) 2025 Vaughn Nugent
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


/**
 * Converts a 64-bit integer to an 8-byte little-endian array.
 * @param long - The 64-bit integer to convert
 * @returns 8-byte array in little-endian format
 */
export const LongToArray = function (long : number) {
  const byteArray = Array(8).fill(0)
  for (let index = 0; index < 8; index++) {
    const byte = long & 0xff
    byteArray[index] = byte
    long = (long - byte) / 256
  }
  return byteArray
}

/**
 * Converts a 32-bit integer to a 4-byte little-endian array.
 * @param int - The 32-bit integer to convert
 * @returns 4-byte array in little-endian format
 */
export const IntToArray = function(int : number) {
  const byteArray = Array(4).fill(0)
  for (let index = 0; index < 4; index++) {
    const byte = int & 0xff
    byteArray[index] = byte
    int = (int - byte) / 256
  }
  return byteArray
}

/**
 * Decodes a base64 string into an array of char codes.
 * @param b64string - Base64-encoded string to decode
 * @returns Array of character codes
 */
export const Base64ToArray = function (b64string : string) : Array<number> {
  const decData = atob(b64string)
  return Array.from(decData, c => c.charCodeAt(0))
}

/**
 * Decodes a base64 string into a Uint8Array.
 * @param b64string - Base64-encoded string to decode
 * @returns Uint8Array of decoded bytes
 */
export const Base64ToUint8Array = function (b64string : string) : Uint8Array<ArrayBuffer> {
  const decData = atob(b64string)
  return Uint8Array.from(decData, c => c.charCodeAt(0))
}

/**
 * Encodes a UTF-8 string into an array of byte values.
 * @param str - UTF-8 string to encode
 * @returns Array of byte values
 */
export const Utf8StringToBuffer = function (str : string) : Array<number> {
  const enc = new TextEncoder().encode(str)
  return Array.from(enc);
}

/**
 * Encodes an ArrayBuffer into a base64 string.
 * @param e - ArrayBuffer to encode
 * @returns Base64-encoded string
 */
export const ArrayBuffToBase64 = function(e : ArrayBuffer) : string {
  const arr = Array.from(new Uint8Array(e))
  return btoa(String.fromCharCode.apply(null, arr))
}

/**
 * Converts a byte buffer into a hex string.
 * @param buffer - Byte array or BufferSource to convert
 * @returns Hexadecimal string representation
 */
export const ArrayToHexString = function(buffer : Array<number> | BufferSource) : string {
  return Array.prototype.map.call(buffer, function (byte : number) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2)
  }).join('')
}
