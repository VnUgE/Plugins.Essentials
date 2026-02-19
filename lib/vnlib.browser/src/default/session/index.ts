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

import { isNil } from 'lodash-es';
import { SignJWT } from 'jose';
import { debugLog } from '../helpers/debugLog';
import { createStorageSlot } from '../helpers/storage';
import { getCryptoOrThrow, decryptAsync, getRandomHex } from '../helpers/webcrypto';
import { ArrayBuffToBase64, Base64ToUint8Array } from '../helpers/binhelpers';
import { getInternalState } from '../config';
import type { ApiConfig, WebMessage } from '../types';

/**
 * Server response containing an encrypted session token.
 * The token is RSA-encrypted with the client's public key and must be
 * decrypted before use. Typically returned after successful authentication.
 */
export interface TokenResponse<T = unknown> extends WebMessage<T> {
    readonly token: string;
}

/**
 * Client credentials sent to the server for registration/authentication.
 * The browser ID uniquely identifies this client instance, while the public
 * key enables the server to encrypt sensitive data for this client.
 */
export interface ClientCredential {
    readonly browserId: string;
    readonly publicKey: string;
}

/**
 * Configuration for client-side session security and cryptographic operations.
 * Controls browser identification, token generation, and encryption parameters.
 * 
 * @remarks
 * Default configuration provides strong security with RSA-4096 encryption and HMAC-SHA256 signatures.
 * Override only if you need specific cryptographic requirements or compatibility needs.
 * 
 * @see {@link getDefaultSessionConfig} for default values
 */
export interface SessionConfig {
    /**
     * Size in bytes of the randomly generated browser identifier.
     * Used to uniquely identify this client instance across sessions.
     * 
     * @defaultValue 32 bytes (256 bits)
     * @remarks Persisted in storage and sent with authentication requests
     */
    readonly browserIdSize: number;
    
    /**
     * JWT signature algorithm for signing one-time tokens.
     * Must match server-side verification configuration.
     * 
     * @defaultValue 'HS256' (HMAC-SHA256)
     * @remarks Used for OTP token generation to prevent replay attacks
     */
    readonly signatureAlgorithm: string;
    
    /**
     * Web Crypto API algorithm specification for RSA key pair generation.
     * Defines encryption parameters for secure token exchange with server.
     * 
     * @defaultValue RSA-OAEP with 4096-bit modulus and SHA-256 hash
     * @remarks Server encrypts session tokens with the client's public key
     */
    readonly keyAlgorithm: AlgorithmIdentifier;
    
    /**
     * Size in bytes for one-time password (OTP) nonce generation.
     * Provides entropy for single-use authentication tokens.
     * 
     * @defaultValue 16 bytes (128 bits)
     * @remarks Each OTP token includes a unique nonce to prevent reuse
     */
    readonly otpNonceSize: number;
}

/**
 * Session manager for handling authentication state and credentials.
 */
export interface Session {
    /**
     * Gets the client security credentials for server registration.
     * @returns Client credentials
     */
    getClientSecInfo(): Promise<ClientCredential>;

    /**
     * Resets all client credentials for security purposes.
     * @returns New client credentials
     */
    resetClientSecInfo(): Promise<ClientCredential>;

    /**
     * Clears all stored session data.
     */
    clearClientSecInfo(): Promise<void>;

    /**
     * Decrypts data received from the server.
     * @param data - Encrypted data to decrypt
     * @returns Decrypted data
     */
    decryptPayload(data: string | ArrayBuffer): Promise<ArrayBuffer>;

    /**
     * Decrypts data and returns a verification hash.
     * @param data - Encrypted data to decrypt and hash
     * @returns Hash of the decrypted data
     */
    decryptAndHash(data: string | ArrayBuffer): Promise<string>;

    /**
     * Updates session credentials from the server response.
     * @param response - Server response containing session token
     */
    updateCredentials(response: TokenResponse): Promise<void>;

    /**
     * Generates an authentication token for API requests.
     * @param path - Request path for the token
     * @returns Token string, or null if not authenticated
     */
    generateOneTimeToken(path: string): Promise<string | null>;
}

/**
 * Returns the default session configuration for browser-based VNLib clients.
 * Defines defaults for browser ID size, OTP nonce size, signature/key algorithms.
 * @returns Default session configuration with secure cryptographic parameters
 */
export const getDefaultSessionConfig = (): SessionConfig => ({
    browserIdSize: 32,
    otpNonceSize: 16,
    signatureAlgorithm: 'HS256',
    keyAlgorithm: {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-256' }
    } as RsaHashedKeyAlgorithm
});

/**
 * Persistent storage structure for session identity and authentication token.
 * Shared globally across all config scopes to maintain consistent client identity.
 */
interface SessionStateStorage {
    token: string | null;       // Base64-encoded HMAC key for OTP signing
    browserId: string | null;   // Unique identifier for this browser instance
    privateKey: string | null;  // Base64-encoded PKCS#8 private key
    publicKey: string | null;   // Base64-encoded SPKI public key
}

const storageSlotFactory = ({ storage }: Pick<ApiConfig, 'storage'>) => {
    return createStorageSlot<SessionStateStorage>(
        storage,
        '_vn-session',
        { token: null, browserId: null, privateKey: null, publicKey: null }
    );
}

/**
 * Creates or retrieves a cached session instance for the given config object.
 * The session provides credential lifecycle management, cryptographic
 * operations, and OTP generation for authenticated server communication.
 * 
 * @param config - ApiConfig instance created at app startup.
 * @returns Session instance bound to the supplied config.
 */
export const useSession = (config: ApiConfig): Session => {
    const { session } = config;
    
    // Get or create shared session storage slot - automatically lazy-initialized
    // Using namespaced key to avoid collisions with other modules
    const state = getInternalState(config, 'session:storage', () => storageSlotFactory(config));

    /**
     * Generates a new random browser ID and persists it to storage.
     * Called during initial setup or when credentials are reset.
     */
    const regenerateBrowserId = async (): Promise<string> => {

        const value = getRandomHex(session.browserIdSize);

        await state.browserId.set(value);

        debugLog(config, 'Generated new browser id for session scope');

        return value;
    };

    /**
     * Retrieves the current browser ID or generates one if missing.
     * Ensures a browser ID always exists after this call.
     */
    const getBrowserId = async (): Promise<string> => {
        const current = await state.browserId.get();
        return isNil(current) ? await regenerateBrowserId() : current;
    };

    /**
     * Exports a CryptoKeyPair to portable formats and writes to storage.
     * Private key is exported as PKCS#8, public as SPKI, both base64-encoded.
     */
    const persistKeyPair = async (pair: CryptoKeyPair): Promise<void> => {
        const subtle = getCryptoOrThrow();

        const [privRaw, pubRaw] = await Promise.all([
            subtle.exportKey('pkcs8', pair.privateKey),
            subtle.exportKey('spki', pair.publicKey)
        ]);

        await Promise.all([
            state.privateKey.set(ArrayBuffToBase64(privRaw)),
            state.publicKey.set(ArrayBuffToBase64(pubRaw))
        ]);
    };

    /**
     * Nulls stored key material without regeneration.
     * Used during credential reset before generating fresh keys.
     */
    const clearKeyMaterial = async (): Promise<void> => {
        await Promise.all([
            state.privateKey.set(null),
            state.publicKey.set(null)
        ]);
    };

    /**
     * Generates a new RSA keypair and persists it to storage.
     * Uses algorithm and key size from scoped config.
     */
    const generateAndStoreKeys = async (): Promise<void> => {
       
        const subtle = getCryptoOrThrow();
       
        const keyPair = await subtle.generateKey(
            session.keyAlgorithm, 
            true, 
            ['encrypt', 'decrypt']
        ) as CryptoKeyPair;
       
        await persistKeyPair(keyPair);
       
        debugLog(config, 'Generated new client keypair for session scope');
    };

    /**
     * Checks if keys exist in storage; generates them if missing.
     */
    const ensureKeys = async (): Promise<void> => {
        const [priv, pub] = await Promise.all([
            state.privateKey.get(),
            state.publicKey.get()
        ]);

        if (!isNil(priv) && !isNil(pub)) {
            return;
        }

        await generateAndStoreKeys();
    };

    /**
     * Loads the private key from storage and imports it as a CryptoKey.
     * Generates a keypair if none exists. The imported key is configured
     * for decryption only (non-extractable).
     */
    const loadPrivateKey = async (): Promise<CryptoKey> => {
        let stored = await state.privateKey.get();
        
        if (isNil(stored)) {
            await generateAndStoreKeys();
            stored = await state.privateKey.get();
        }

        const keyBytes = Base64ToUint8Array(stored ?? '');
        
        const subtle = getCryptoOrThrow();

        return subtle.importKey('pkcs8', keyBytes, session.keyAlgorithm, false, ['decrypt']);
    };

    /**
     * Nulls the stored session token. Called during logout or credential reset
     * to invalidate the ability to sign OTP tokens.
     */
    const clearSharedToken = async (): Promise<void> => state.token.set(null);

    /**
     * Decrypts RSA-encrypted data from the server using the client private key.
     * The server encrypts sensitive payloads (like session tokens) with the
     * client's public key to ensure only this client can read them.
     */
    const decryptPayload = async (data: string | ArrayBuffer): Promise<ArrayBuffer> => {
        const privateKey = await loadPrivateKey();

        return decryptAsync(session.keyAlgorithm, privateKey, data, false) as Promise<ArrayBuffer>;
    };

    /**
     * Decrypts data and computes its SHA-256 hash without exposing plaintext.
     * Useful for challenge-response authentication where the server needs proof
     * the client decrypted the data without transmitting the plaintext.
     */
    const decryptAndHash = async (data: string | ArrayBuffer): Promise<string> => {
        const decrypted = await decryptPayload(data);

        const subtle = getCryptoOrThrow();
        
        const digest = await subtle.digest({ name: 'SHA-256' }, decrypted);

        return ArrayBuffToBase64(digest);
    };

    /**
     * Decrypts and stores the server-provided session token.
     * The token is typically an HMAC key used to sign subsequent OTP requests.
     * Must be called after login to enable authenticated API calls.
     */
    const updateCredentials = async (response: TokenResponse): Promise<void> => {
        const decrypted = await decryptPayload(response.token);
        await state.token.set(ArrayBuffToBase64(decrypted));
    };

    /**
     * Retrieves the decrypted session token as a byte array.
     * Returns null if no token is stored (user not logged in).
     */
    const getSharedKey = async (): Promise<Uint8Array | null> => {
        const stored = await state.token.get();
        return stored ? Base64ToUint8Array(stored) : null;
    };

    /**
     * Generates a signed JWT one-time token for API requests.
     * The token includes a random nonce and request path to prevent replay attacks.
     * Returns null if the user is not logged in (no session token available).
     */
    const generateOneTimeToken = async (path: string): Promise<string | null> => {
        const sharedKey = await getSharedKey();
        if (!sharedKey) {
            return null;
        }
        
        const nonce = getRandomHex(session.otpNonceSize);
        const jwt = new SignJWT({ nonce, path });

        jwt.setProtectedHeader({ alg: session.signatureAlgorithm }).setIssuedAt();

        // Set audience to current origin if available (browser environment)
        if (typeof window !== 'undefined' && window.location?.origin) {
            jwt.setAudience(window.location.origin);
        }

        return jwt.sign(sharedKey);
    };

    /**
     * Ensures credentials exist and returns them for server registration.
     * Idempotent: will not regenerate if credentials already exist.
     * Use this when you need to send client identity to the server.
     */
    const getClientSecInfo = async (): Promise<ClientCredential> => {
        await ensureKeys();

        const [publicKey, browserId] = await Promise.all([
            state.publicKey.get(),
            getBrowserId()
        ]);

        return { publicKey: publicKey ?? '', browserId };
    };

    /**
     * Rotates all client credentials as part of logout or security reset.
     * Invalidates any server-side sessions tied to the old credentials by
     * generating a fresh browser ID and keypair. The session token is also
     * cleared to prevent OTP generation with stale credentials.
     */
    const resetClientSecInfo = async (): Promise<ClientCredential> => {
        await Promise.all([
            clearSharedToken(),
            regenerateBrowserId(),
            (async () => {
                await clearKeyMaterial();
                await generateAndStoreKeys();
            })()
        ]);

        return getClientSecInfo();
    };

    /**
     * Performs a hard-clear of all credentials without regeneration.
     * Use when the user explicitly logs out and should not be automatically
     * re-enrolled. All session state is deleted from storage.
     */
    const clearClientSecInfo = async (): Promise<void> => {
        await Promise.all([
            state.browserId.set(null),
            clearSharedToken(),
            clearKeyMaterial()
        ]);
    };

    return {
        getClientSecInfo,
        resetClientSecInfo,
        clearClientSecInfo,
        decryptPayload,
        decryptAndHash,
        updateCredentials,
        generateOneTimeToken
    };
};
