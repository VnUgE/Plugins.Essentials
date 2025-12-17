// Copyright (c) 2024 Vaughn Nugent
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

import { defaultTo, isArrayBuffer, isNil, isPlainObject, isString, memoize } from 'lodash-es';
import { ArrayBuffToBase64, Base64ToUint8Array, ArrayToHexString } from './binhelpers';

type CryptoScope = typeof globalThis & { isSecureContext?: boolean };

/**
 * Represents a normalized crypto runtime across browsers, Node, and test
 * environments so higher-level utilities do not reach for globals directly.
 */
export interface CryptoContext {
    /**
     * The Crypto interface providing random value generation.
     */
    readonly crypto: Crypto;
    
    /**
     * The SubtleCrypto interface for cryptographic operations.
     */
    readonly subtle: SubtleCrypto;
    
    /**
     * Indicates whether the current runtime is a secure context.
     */
    readonly secureContext: boolean;
}

const getRuntimeScope = memoize((): CryptoScope | undefined => {
    return typeof globalThis === 'undefined'
        ? undefined
        : globalThis as CryptoScope;
});

const resolveRuntimeCrypto = (): Crypto | undefined => {
    const scope = getRuntimeScope();
    return scope?.crypto as Crypto | undefined;
};

const resolveSecureFlag = (): boolean => {
    const scope = getRuntimeScope();
    return defaultTo(scope?.isSecureContext, true);
};

/**
 * Checks whether the current runtime exposes `crypto.subtle` APIs.
 */
export const isCryptoSupported = (): boolean => {
    const runtimeCrypto = resolveRuntimeCrypto();
    return !isNil(runtimeCrypto?.subtle);
}

/**
 * Returns the crypto runtime or throws when the platform cannot satisfy the
 * Web Crypto API requirements (subtle crypto missing, insecure context, etc.).
 */
export const getCryptoContext = (): CryptoContext => {

    const runtimeCrypto = resolveRuntimeCrypto();

    if (!runtimeCrypto || !runtimeCrypto.subtle)
    {
        throw new Error('Web Cryptography API is not available in this runtime');
    }

    return {
        crypto: runtimeCrypto,
        subtle: runtimeCrypto.subtle,
        secureContext: resolveSecureFlag()
    };
}

/**
 * Shortcut helper that returns the `SubtleCrypto` interface or throws.
 */
export const getCryptoOrThrow = (): SubtleCrypto => getCryptoContext().subtle;

const getRandomBytes = (size: number): Uint8Array => {
    const { crypto } = getCryptoContext();
    const buffer = new Uint8Array(size);
    crypto.getRandomValues(buffer);
    return buffer;
};

/**
 * Converts base64 strings into Uint8Array or passes through ArrayBuffers.
 */
const normalizeBinary = (value: ArrayBuffer | string): BufferSource => {
    return isString(value)
        ? Base64ToUint8Array(value as string)
        : value as ArrayBuffer;
};

/**
 * Normalizes diverse private key inputs (raw, JWK, CryptoKey) into a CryptoKey instance.
 */
const importPrivateKeyAsync = async (
    algorithm: AlgorithmIdentifier,
    subtle: SubtleCrypto,
    privKey: BufferSource | CryptoKey | JsonWebKey
): Promise<CryptoKey> =>
{
    if (privKey instanceof CryptoKey)
    {
        return privKey;
    }

    if (isArrayBuffer(privKey) || ArrayBuffer.isView(privKey))
    {
        return subtle.importKey('raw', privKey, algorithm, true, ['decrypt']);
    }

    if (isPlainObject(privKey))
    {
        return subtle.importKey('jwk', privKey as JsonWebKey, algorithm, true, ['decrypt']);
    }

    throw new TypeError('Unsupported private key format supplied.');
}

/**
 * Signs arbitrary data using the provided secret key and HMAC algorithm.
 * @param keyBuffer Raw key material or a base64 encoded key string.
 * @param dataBuffer Data to sign as ArrayBuffer or base64 string.
 * @param alg SubtleCrypto-supported hash algorithm name.
 * @param toBase64 When true the digest is returned as a base64 string.
 */
export const hmacSignAsync = async (
    keyBuffer: ArrayBuffer | string,
    dataBuffer: ArrayBuffer | string,
    alg : string,
    toBase64 = false
): Promise<ArrayBuffer | string> => {

    const { subtle } = getCryptoContext();

    const rawKeyBuffer = normalizeBinary(keyBuffer);
    const rawDataBuffer = normalizeBinary(dataBuffer);
   
    // Get the key
    const hmacKey = await subtle.importKey('raw', rawKeyBuffer, { name: 'HMAC', hash: alg }, false, ['sign']);

    // Sign hmac data
    const digest = await subtle.sign('HMAC', hmacKey, rawDataBuffer);

    // Encode to base64 if needed
    return toBase64 ? ArrayBuffToBase64(digest) : digest;
}

/**
 * Decrypts binary data using the supplied algorithm and private key reference.
 * @param algorithm Decryption algorithm descriptor.
 * @param privKey Raw key material, CryptoKey, or JWK object.
 * @param data Encrypted payload as ArrayBuffer or base64 string.
 * @param toBase64 When true the decrypted data is returned as base64.
 */
export const decryptAsync = async (
    algorithm: AlgorithmIdentifier,
    privKey: BufferSource | CryptoKey | JsonWebKey,
    data: string | ArrayBuffer,
    toBase64 = false
): Promise<string | ArrayBuffer> =>
{
    const { subtle } = getCryptoContext();
    const dataBuffer = normalizeBinary(data) as ArrayBuffer;
    const privateKey = await importPrivateKeyAsync(algorithm, subtle, privKey);

    // Decrypt the data and return it
    const decrypted = await subtle.decrypt(algorithm, privateKey as CryptoKey, dataBuffer);
    return toBase64 ? ArrayBuffToBase64(decrypted) : decrypted;
}

/**
 * Creates a random hexadecimal string of the requested byte length.
 * @param size Number of random bytes to generate.
 */
export const getRandomHex = (size: number) : string => {
    const randBuffer = getRandomBytes(size);
    return ArrayToHexString(Array.from(randBuffer));
}
