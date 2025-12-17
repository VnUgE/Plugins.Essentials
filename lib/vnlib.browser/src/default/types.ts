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

import type { Axios, AxiosInstance, AxiosRequestConfig } from "axios";
import type { AxiosConfig } from "./axios";
import { AccountRpcApiConfig } from "./account/types";

/**
 * Represents a uniform message from the server
 */
export interface WebMessage<T = unknown> {
    /**
     * The result of the operation, or an error message
     * if the sucess value is false
     */
    readonly result : T | string;
    /**
     * True if the operation was successful, false otherwise
     */
    readonly success : boolean;
    /**
     * Validation errors, if any occured
     */
    readonly errors?: ServerValidationError[]

    /**
     * Returns the result, or throws an error if the operation was not successful
     */
    getResultOrThrow() : T;
}

/**
 * Represents a validation error from the server for a specific property
 */
export interface ServerValidationError{
    /**
     * The property that failed validation
     */
    readonly property : string;
    /**
     * The error message
     */
    readonly message: string;
}

export type Awaitable<T> = T | Promise<T>;

/**
 * Legacy scope token used by deprecated global config helpers. Avoid for new code.
 */
export type ConfigScopeToken = symbol;

/**
 * Represents a storage-like interface that can be used to store and retrieve items
 * in a key-value format, with support for asynchronous operations.
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

export interface SessionConfig {
    /**
     * The size of the browser ID used for 
     * session management.
     */
    readonly browserIdSize: number;
    /**
     * The algorithm used for signing session data.
     */
    readonly signatureAlgorithm: string;
    /**
     * The algorithm used for generating session keys.
     */
    readonly keyAlgorithm: AlgorithmIdentifier;
    /**
     * The size in bytes for OTP nonce generation.
     * Provides sufficient entropy for single-use tokens.
     */
    readonly otpNonceSize: number;
}

/**
 * Aggregate API configuration passed to all composables. All defaults are
 * local to the module and merged during creation.
 */
export interface ApiConfig {
    readonly session: SessionConfig;
    readonly axios: AxiosConfig;
    readonly account: AccountRpcApiConfig;
    readonly storage: StorageLikeAsync;
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
 * Override shape used when creating an ApiConfig instance. Modules merge
 * provided overrides with their local defaults.
 */
export interface ApiConfigOverrides {
    readonly session?: Partial<SessionConfig>;
    readonly axios?: {
        readonly instance?: Axios;
        readonly tokenHeader?: string;
        readonly axiosConfig?: AxiosRequestConfig;
        readonly configureInstance?: (axios: AxiosInstance) => AxiosInstance;
    };
    readonly account?: Partial<AccountRpcApiConfig>;
    readonly storage?: StorageLikeAsync;
}