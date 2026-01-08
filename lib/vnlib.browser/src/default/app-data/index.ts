
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

import { type MaybeRef } from 'vue'
import { get } from '@vueuse/core'
import { useAxios } from '../axios'
import type { ApiConfig, WebMessage } from '../types'

export interface AppDataGetOptions{
    /** Bypass server cache and force a read-through fetch. */
    readonly noCache?: boolean
}

export interface AppDataSetOptions{
    /** Wait for the server to flush writes before returning. */
    readonly wait?: boolean
}

export interface UserAppDataApi {
    /**
     * Gets data from the server.
     * @param scope - Data scope identifier
     * @param options - Optional request configuration
     * @returns The stored data, or undefined if not found
     */
    get<T>(scope: string, options?: AppDataGetOptions): Promise<T | undefined>
    
    /**
     * Stores data on the server.
     * @param scope - Data scope identifier
     * @param data - Data to store
     * @param options - Optional request configuration
     */
    set<T>(scope: string, data: T, options?: AppDataSetOptions): Promise<void>
    
    /**
     * Removes data from the server.
     * @param scope - Data scope identifier
     */
    remove(scope: string): Promise<void>
}

export interface ScopedUserAppDataApi {
    /**
     * Gets data from the server.
     * @param options - Optional request configuration
     * @returns The stored data, or undefined if not found
     */
    get<T>(options: AppDataGetOptions): Promise<T | undefined>
    
    /**
     * Stores data on the server.
     * @param data - Data to store
     * @param options - Optional request configuration
     */
    set<T>(data: T, options: AppDataSetOptions): Promise<void>
    
    /**
     * Removes data from the server.
     */
    remove(): Promise<void>
}

interface GetUrl{
    readonly noCache: boolean
    readonly flush: boolean
    readonly scope: string
}

/**
 * Configuration for constructing an app-data API client.
 */
export interface AppDataApiOptions {
    /** App-data service endpoint URL (may be reactive for multi-tenant scenarios). */
    readonly endpoint: MaybeRef<string>;
    /** Api configuration used to provision axios and OTP headers. */
    readonly config: ApiConfig;
}

/**
 * Creates an app-data API for server-side user data management.
 * Scopes isolate data partitions that persist across sessions and devices.
 * 
 * @param options - Configuration including endpoint and api config.
 * @returns App-data API with methods for get/set/remove operations.
 */
export const useAppDataApi = (options: AppDataApiOptions): UserAppDataApi => {

    const { endpoint, config } = options;

    // Attach interceptors to config-provided axios instance
    const axiosInstance = useAxios(config);

    const getUrl = ({ flush, noCache, scope }: GetUrl) => {
        const fl = flush ? '&flush=true' : ''
        const nc = noCache ? '&no_cache=true' : ''
        return `${get(endpoint)}?scope=${scope}${nc}${fl}`
    }

    return {
        get: async <T>(scope: string, options?:AppDataGetOptions): Promise<T | undefined> => {
            const { noCache } = options || {};

            const url = getUrl({
                scope,
                noCache: (noCache || false), 
                flush: false 
            })

            //Handle status code errors manually
            const response = await axiosInstance.get<T>(url, {
                validateStatus: (status) => status >= 200 && status < 500
            })

            switch (response.status) {
                case 200:
                    break;
                case 404:
                    return undefined;
                default:
                    (response.data as WebMessage)?.getResultOrThrow();
                    throw { response };
            }

            if('getResultOrThrow' in (response.data as any)) {
                let d = { ...response.data } as any;
                delete d.getResultOrThrow;
                return d;
            }

            return response.data;
        },

        set: async <T>(scope: string, data: T, options?: AppDataSetOptions) => {
            const { wait } = options || {};
           
            const url = getUrl({ 
                scope,
                noCache: false,
                flush: (wait || false)
            })
           
            //Handle status code errors manually
            const { status, data: responseData } = await axiosInstance.put<WebMessage>(url, data)
            switch (status) {
                case 200:
                case 202:
                    break;
                default:
                   (responseData as WebMessage)?.getResultOrThrow();
                   break;
            }
        },
       
        remove: async (scope: string) => {
             //Handle status code errors manually
            const response = await axiosInstance.delete<WebMessage>(getUrl({ scope, noCache: false, flush: false }))

            switch (response.status) {
                case 200:
                case 202:
                    break;
                default:
                    (response.data as WebMessage)?.getResultOrThrow();
                    throw { response };
            }
        }
    }
}

/**
 * Creates an app-data API bound to a fixed scope string.
 * Avoids repeatedly supplying the scope for get/set/remove calls.
 * 
 * @param endpoint - App-data service endpoint URL.
 * @param dataScope - The data scope identifier (not a config scope).
 * @param options - Optional axios and config scope configuration.
 * @returns Scoped app-data API instance.
 */
export const useScopedAppDataApi = (config: { dataScope: string } & AppDataApiOptions): ScopedUserAppDataApi => {

    const api = useAppDataApi(config);

    return {
        get: <T>(options: AppDataGetOptions) => api.get<T>(config.dataScope, options),
        set: <T>(data: T, options: AppDataSetOptions) => api.set(config.dataScope, data, options),
        remove: () => api.remove(config.dataScope)
    }
}
