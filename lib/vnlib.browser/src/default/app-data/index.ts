
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
    /**
     * A value indicating if the request should not use the cache
     */
    readonly noCache?: boolean
}

export interface AppDataSetOptions{
    /**
     * A value indicating if the request should wait for the data to be written to the store
     */
    readonly wait?: boolean
}

export interface UserAppDataApi {
    /**
     * Gets data from the app-data server
     * @param scope The scope of the data to get from the store
     * @param options The options to use when getting the data
     * @returns A promise that resolves to the data or undefined if the data does not exist
     */
    get<T>(scope: string, options?: AppDataGetOptions): Promise<T | undefined>
    /**
     * Sets arbitrary data in the app-data server
     * @param scope The scope of the data to set in the store
     * @param data The data to set in the store
     * @param options The options to use when setting the data 
     */
    set<T>(scope: string, data: T, options?: AppDataSetOptions): Promise<void>
    /**
     * Completely removes data from the app-data server
     * @param scope The scope of the data to remove from the store
     */
    remove(scope: string): Promise<void>
}

export interface ScopedUserAppDataApi {
    /**
     * Gets data from the app-data server for the configured scope
     * @param options The options to use when getting the data 
     * @returns A promise that resolves to the data or undefined if the data does not exist
     */
    get<T>(options: AppDataGetOptions): Promise<T | undefined>
    /**
     * Sets arbitrary data in the app-data server for the configured scope
     * @param data The data to set in the store
     * @param options The options to use when setting the data
     * @returns A promise that resolves when the data has been written to the store
     */
    set<T>(data: T, options: AppDataSetOptions): Promise<void>
    /**
     * Completely removes data from the app-data server for the configured scope
     * @returns A promise that resolves when the data has been removed from the store
     */
    remove(): Promise<void>
}

interface GetUrl{
    readonly noCache: boolean
    readonly flush: boolean
    readonly scope: string
}

/**
 * Configuration options for app-data API.
 */
export interface AppDataApiOptions {
    /**
     * App-data service endpoint URL (can be reactive).
     */
    readonly endpoint: MaybeRef<string>;
    /**
     * Api configuration instance used to create axios when one is not provided.
     */
    readonly config: ApiConfig;
}

/**
 * Creates an app-data storage API for server-side user data management.
 * Provides scoped storage where each scope represents an isolated data partition.
 * Data is stored server-side and survives across sessions and devices.
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
 * Creates an app-data API bound to a constant scope string.
 * Provides a simplified interface where the data scope is pre-configured,
 * eliminating the need to pass it with each operation.
 * 
 * @param endpoint - App-data service endpoint URL.
 * @param dataScope - The data scope identifier (not a config scope).
 * @param options - Optional axios and config scope configuration.
 * @returns Scoped app-data API instance.
 */
export const useScopedAppDataApi = (
    endpoint: string,
    dataScope: string,
    options: { config: ApiConfig }
): ScopedUserAppDataApi => {
    const api = useAppDataApi({ endpoint, ...options });

    return {
        get: <T>(options: AppDataGetOptions) => api.get<T>(dataScope, options),
        set: <T>(data: T, options: AppDataSetOptions) => api.set(dataScope, data, options),
        remove: () => api.remove(dataScope)
    }
}
