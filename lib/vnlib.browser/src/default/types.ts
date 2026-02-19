// Copyright (c) 2026 Vaughn Nugent
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

import type { Axios } from "axios";
import type { AccountRpcApiConfig } from "./account/types";
import type { SessionConfig } from "./session";

/**
 * Standard response format for server API calls.
 */
export interface WebMessage<T = unknown> {
    /**
     * The result data when successful, or an error message when failed.
     */
    readonly result: T | string;
    
    /**
     * Whether the operation succeeded.
     */
    readonly success: boolean;
    
    /**
     * Validation errors if the request was rejected.
     */
    readonly errors?: ServerValidationError[];

    /**
     * Gets the result or throws an error if the operation failed.
     * @returns The result data
     * @throws Error if the operation failed
     */
    getResultOrThrow(): T;
}

/**
 * Validation error for a specific property.
 */
export interface ServerValidationError{
    /**
     * The property that failed validation.
     */
    readonly property: string;
    
    /**
     * Error message describing the validation failure.
     */
    readonly message: string;
}

/** Value that may be delivered synchronously or via a Promise. */
export type Awaitable<T> = T | Promise<T>;

/**
 * Storage interface for persisting session state and credentials.
 * Compatible with browser localStorage, sessionStorage, or custom async storage.
 * Supports both synchronous and asynchronous implementations via Awaitable return types.
 * 
 * @remarks
 * The library automatically detects and wraps browser localStorage if available.
 * Falls back to in-memory Map-based storage if localStorage is unavailable.
 * Custom implementations can integrate with IndexedDB, secure storage, or other backends.
 * 
 * @example
 * // Browser localStorage (automatic)
 * const config = createApiConfig(); // Uses localStorage by default
 * 
 * @example
 * // Custom async storage
 * const config = createApiConfig({
 *   storage: {
 *     getItem: async (key) => await db.get(key),
 *     setItem: async (key, value) => await db.set(key, value),
 *     removeItem: async (key) => await db.delete(key)
 *   }
 * });
 */
export interface StorageLikeAsync {
    
    /**
     * Retrieves an item from storage
     * @param key The key to retrieve
     * @returns A promise that resolves to the value of the item, or null if it does not exist
     */
    getItem: (key: string) => Awaitable<string | null>;
    
    /**
     * Sets an item in storage
     * @param key The key to set
     * @param value The value to set
     * @returns A promise that resolves when the item has been set
     */
    setItem: (key: string, value: string) => Awaitable<void>;

    /**
     * Removes an item from storage
     * @param key The key to remove
     * @returns A promise that resolves when the item has been removed
     */
    removeItem: (key: string) => Awaitable<void>;
}

/**
 * Aggregate API configuration passed to all composables. All defaults are
 * local to the module and merged during creation.
 */
export interface ApiConfig {
    readonly session: SessionConfig;
    readonly axios: Axios;
    readonly account: AccountRpcApiConfig;
    readonly storage: StorageLikeAsync;
    readonly tokenHeader: string;
    /**
     * Optional debug logger callback for internal library diagnostics.
     * If provided, the library will call this function with debug messages.
     * Useful for development and troubleshooting.
     * 
     * @example
     * debugLog: (...args) => console.log('[VNLib]', ...args)
     */
    readonly debugLog?: (...args: unknown[]) => void;
}

/**
 * Internal extension of ApiConfig with hidden state management.
 * 
 * Provides symbol-keyed access to shared, lazily-initialized resources.
 * Use getInternalState() and setInternalState() helpers from config.ts
 * instead of accessing this directly.
 * 
 * The state container is a generic Map-like structure where modules can
 * store any type of state they need without predefined schema.
 * 
 * @internal - Not for external use
 */
export interface ApiConfigInternal extends ApiConfig {
    /**
     * Hidden namespace for shared state. Accessed via helper functions
     * to prevent manual symbol juggling and ensure type safety.
     * 
     * Modules can store any value type keyed by string identifiers.
     */
    readonly [key: symbol]: Map<string, any>;
}

/**
 * Configuration overrides for customizing API behavior when creating an ApiConfig.
 * All properties are optional; unspecified values use sensible defaults.
 * 
 * @remarks
 * Pass to {@link createApiConfig} to customize application shared
 * configuration. 
 * 
 * @example
 * // Minimal configuration (uses all defaults)
 * const config = createApiConfig();
 * 
 * @example
 * // Custom endpoint and debug logging
 * const config = createApiConfig({
 *   account: { endpointUrl: '/api/v2/account' },
 *   debugLog: (...args) => console.log('[VNLib]', ...args)
 * });
 * 
 * @example
 * // Custom axios instance with interceptors
 * const customAxios = axios.create({ baseURL: 'https://api.example.com' });
 * customAxios.interceptors.request.use(config => { ... });
 * const config = createApiConfig({
 *   axios: { instance: customAxios, tokenHeader: 'X-Custom-Token' }
 * });
 */
export interface ApiConfigOverrides {
    /**
     * Partial session configuration overrides.
     */
    readonly session?: Partial<SessionConfig>;
    
    /**
     * Axios HTTP client configuration.
     *
     * `tokenHeader` applies regardless of which branch is used.
     * Provide either `instance` (pre-built) or `axiosConfig`/`configureInstance`
     * (let the library build one) — not both at the same time.
     *
     * @remarks
     * The library attaches OTP token injection interceptors after your
     * `configureInstance` callback runs, so custom interceptors are ordered first.
     */
    readonly axios?: Axios 
    
    /**
      * HTTP header name used to send the per-request OTP token.
      * Must match the header your server validates.
      *
      * @defaultValue 'X-Web-Token'
      */
    readonly tokenHeader?: string;
    
    /**
     * Account/profile RPC endpoint configuration.
     * Merged with defaults.
     * 
     * @example
     * account: {
     *   endpointUrl: '/api/v2/user' // Change from default '/account'
     * }
     */
    readonly account?: Partial<AccountRpcApiConfig>;
    
    /**
     * Custom storage implementation for persisting session state.
     * If not provided, automatically uses browser localStorage or in-memory fallback.
     * 
     * @remarks
     * Custom storage useful for:
     * - Server-side rendering (SSR) environments
     * - IndexedDB for larger data storage
     * - Encrypted storage wrappers
     * - Testing with mock storage
     * 
     * @example
     * // In-memory storage for testing
     * const testStorage = new Map<string, string>();
     * storage: {
     *   getItem: (key) => testStorage.get(key) ?? null,
     *   setItem: (key, value) => testStorage.set(key, value),
     *   removeItem: (key) => testStorage.delete(key)
     * }
     */
    readonly storage?: StorageLikeAsync;
    
    /**
     * Optional debug logger callback for internal library diagnostics.
     * If provided, the library will call this function with debug messages.
     * Useful for development and troubleshooting.
     * 
    * @remarks NOTE: May print client-side sensitive data (although it's avoided)
     * 
     * @example
     * // Simple console logging
     * debugLog: (...args) => console.log('[VNLib]', ...args)
     * 
     * @example
     * // Custom logger integration
     * debugLog: (...args) => myLogger.debug('vnlib', ...args)
     */
    readonly debugLog?: (...args: unknown[]) => void;
}