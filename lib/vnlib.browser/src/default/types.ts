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

import type { AxiosInstance, AxiosRequestConfig } from "axios";

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
}

/**
 * Represents the configuration for the account RPC API.
 */
export interface AccountRpcApiConfig{
    /**
     * The URL of the account RPC API endpoint.
     */
    readonly endpointUrl: string;
}

/**
 * Represents the configuration for the session management API.
 */
export interface GlobalAxiosConfig extends AxiosRequestConfig {
    /**
     * The header name used to send the secondary authentication 
     * token.
     */
    readonly tokenHeader: string;
    /**
     * Configures the axios instance with additional settings.
     * @param axios The axios instance to configure
     * @returns The configured axios instance
     */
    readonly configureAxios?: (axios: AxiosInstance) => AxiosInstance;
}

export interface GlobalApiConfig {
    readonly session: SessionConfig;
    readonly axios: GlobalAxiosConfig;
    readonly account: AccountRpcApiConfig;
    readonly storage: StorageLikeAsync;
}

export interface GlobalConfigUpdate {
    readonly session?: Partial<SessionConfig>;
    readonly axios?: Partial<GlobalAxiosConfig>;
    readonly account?: Partial<AccountRpcApiConfig>;
    readonly storage?: StorageLikeAsync;
} 