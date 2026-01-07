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

import axiosDefault from 'axios';
import { merge } from 'lodash-es';
import type { StorageLikeAsync } from '@vueuse/core';
import type { ApiConfig, ApiConfigInternal, ApiConfigOverrides } from './types';
import { getDefaultSessionConfig } from './session';
import { getDefaultAccountConfig } from './account';
import { getDefaultAxiosRequestConfig, type AxiosConfig } from './axios';

/**
 * Symbol key for accessing internal shared state on ApiConfig instances.
 * Using Symbol.for() ensures the same symbol across module boundaries.
 */
const INTERNAL_STATE_KEY = Symbol.for('vnlib.config.internal');

/**
 * Retrieves or lazily initializes shared state for a config instance.
 * State is stored in a Map, keyed by string identifiers you choose.
 * 
 * @template T - The type of the state value
 * @param config - The ApiConfig instance to access state from
 * @param key - Unique identifier for this state (suggest namespacing: 'module:key')
 * @param factory - Function to create the resource if it doesn't exist
 * @returns The cached or newly created resource
 * 
 * @example
 * const storage = getInternalState(config, 'session:storage', () => 
 *   createStorageSlot(config.storage, '_vn-session', defaultValue)
 * );
 */
export const getInternalState = <T>(config: ApiConfig, key: string, factory: () => T): T => {
    const stateMap = (config as ApiConfigInternal)[INTERNAL_STATE_KEY];
    
    if (!stateMap.has(key)) {
        stateMap.set(key, factory());
    }
    
    return stateMap.get(key) as T;
};

const DEFAULT_TOKEN_HEADER = 'X-Web-Token';

const resolveAxiosConfig = (overrides?: ApiConfigOverrides['axios']): AxiosConfig => {

    if (overrides?.instance) {
        return {
            instance: overrides.instance,
            tokenHeader: overrides.tokenHeader ?? DEFAULT_TOKEN_HEADER
        } satisfies AxiosConfig;
    }

    // No instrance, so create one and assign defaults
    const mergedRequestConfig = merge({}, getDefaultAxiosRequestConfig(), overrides?.axiosConfig);

    // If no instances was provided by the user create a new one
    const axios = axiosDefault.create(mergedRequestConfig);

    // User callback to configure
    if(overrides?.configureInstance){
        overrides.configureInstance(axios);
    }

    return {
        instance: axios,
        tokenHeader: overrides?.tokenHeader ?? DEFAULT_TOKEN_HEADER
    } satisfies AxiosConfig;
};

const resolveDefaultStorage = (): StorageLikeAsync => {

    // Check for browser localStorage (works in both real browsers and jsdom)
    // Verify it actually has the storage methods (jsdom can return empty object)
    if (typeof window !== 'undefined' && window.localStorage && typeof window.localStorage.getItem === 'function') {
        const storage = window.localStorage;
        // Wrap synchronous localStorage with async interface
        return {
            getItem: async (key: string): Promise<string | null> => {
                return storage.getItem(key);
            },
            setItem: async (key: string, value: string): Promise<void> => {
                storage.setItem(key, value);
            },
            removeItem: async (key: string): Promise<void> => {
                storage.removeItem(key);
            }
        } satisfies StorageLikeAsync;
    }

    // Fallback to in-memory storage for non-browser environments
    const store = new Map<string, string>();

    return {
        getItem: async (key: string): Promise<string | null> => {
            return store.has(key) ? store.get(key)! : null;
        },
        setItem: async (key: string, value: string): Promise<void> => {
            store.set(key, value);
        },
        removeItem: async (key: string): Promise<void> => {
            store.delete(key);
        }
    } satisfies StorageLikeAsync;
};

/**
 * Creates an isolated API configuration with module-local defaults merged
 * with user overrides. The returned config must be passed explicitly to
 * composables (e.g., useSession(config)) to ensure side-effect-free usage.
 * @param overrides - Optional configuration overrides for session, axios, account, and storage
 * @returns Fully configured API instance ready for use with library composables
 */
export const createApiConfig = (overrides?: ApiConfigOverrides): ApiConfig => {
    
    const config: ApiConfigInternal = {
        session: merge({}, getDefaultSessionConfig(), overrides?.session),
        axios: resolveAxiosConfig(overrides?.axios),
        account: merge({}, getDefaultAccountConfig(), overrides?.account),
        storage: overrides?.storage ?? resolveDefaultStorage(),
        debugLog: overrides?.debugLog,
        // Initialize empty state Map - modules will populate on demand
        [INTERNAL_STATE_KEY]: new Map<string, any>()
    };

    return config;
};
