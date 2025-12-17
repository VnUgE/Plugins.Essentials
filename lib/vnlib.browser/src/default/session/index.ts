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
import type { ApiConfig, WebMessage, SessionConfig } from '../types';

/**
 * Server response containing an encrypted session token.
 * The token is RSA-encrypted with the client's public key and must be
 * decrypted before use. Typically returned after successful authentication.
 */
export interface ITokenResponse<T = unknown> extends WebMessage<T> {
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
 * Persistent storage structure for session identity and authentication token.
 * Shared globally across all config scopes to maintain consistent client identity.
 */
interface SessionStateStorage {
    token: string | null;       // Base64-encoded HMAC key for OTP signing
    browserId: string | null;   // Unique identifier for this browser instance
    privateKey: string | null;  // Base64-encoded PKCS#8 private key
    publicKey: string | null;   // Base64-encoded SPKI public key
}

/**
 * Represents the current server/client session state with consolidated
 * credential management helpers. Provides a unified API for credential
 * lifecycle (get/reset/clear), cryptographic operations (decrypt/hash),
 * and server authentication (OTP token generation).
 */
export interface ISession {
    /**
     * Ensures client credentials exist, generating them if necessary.
     * Returns the browser identifier and public key for server registration.
     * Safe to call repeatedly; will not regenerate existing credentials.
     */
    getClientSecInfo(): Promise<ClientCredential>;

    /**
     * Rotates all client credentials as part of logout or security reset.
     * Generates a fresh browser ID and RSA keypair, invalidating any
     * server-side sessions tied to the old credentials. Use when the
     * client security context must be fully reset.
     */
    resetClientSecInfo(): Promise<ClientCredential>;

    /**
     * Performs a hard-clear of all stored credentials without regeneration.
     * Use when the user explicitly logs out and should not be automatically
     * re-enrolled. All session state (browser ID, keys, tokens) is deleted.
     */
    clearClientSecInfo(): Promise<void>;

    /**
     * Decrypts server-encrypted payloads using the client's private RSA key.
     * The server encrypts sensitive data (like HMAC keys) with the client's
     * public key; only this method can recover the plaintext.
     */
    decryptPayload(data: string | ArrayBuffer): Promise<ArrayBuffer>;

    /**
     * Decrypts a payload and returns its SHA-256 digest as base64.
     * Used for integrity verification without exposing the plaintext,
     * particularly useful for password or token validation flows.
     */
    decryptAndHash(data: string | ArrayBuffer): Promise<string>;

    /**
     * Stores the server-provided session token after decrypting it.
     * This token (typically an HMAC key) is used to sign OTP requests.
     * Must be called after successful login to enable authenticated requests.
     */
    updateCredentials(response: ITokenResponse): Promise<void>;

    /**
     * Generates a signed JWT one-time token for authenticated API calls.
     * Returns null if no session token is available (user not logged in).
     * The token includes a nonce, path, and audience to prevent replay attacks.
     */
    generateOneTimeToken(path: string): Promise<string | null>;
}

/**
 * Returns the default session configuration for browser-based VNLib clients.
 * Defines defaults for browser ID size, OTP nonce size, signature/key algorithms.
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
export const useSession = (config: ApiConfig): ISession => {
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

        debugLog('Generated new browser id for session scope');

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
       
        debugLog('Generated new client keypair for session scope');
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
    const updateCredentials = async (response: ITokenResponse): Promise<void> => {
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
