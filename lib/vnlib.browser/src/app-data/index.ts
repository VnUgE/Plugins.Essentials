
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

import { MaybeRef, get, type StorageLikeAsync } from '@vueuse/core'
import { useAxios } from '../axios'
import { defaultTo, first } from 'lodash-es'
import type { Axios } from 'axios'

export interface UserAppDataApi {
    /**
     * Gets data from the app-data server
     * @param scope The scope of the data to get from the store
     * @param noCache A value indicating if the cache should be bypassed
     * @returns A promise that resolves to the data or undefined if the data does not exist
     */
    get<T>(scope: string, noCache: boolean): Promise<T | undefined>
    /**
     * Sets arbitrary data in the app-data server
     * @param scope The scope of the data to set in the store
     * @param data The data to set in the store
     * @param wait A value indicating if the request should wait for the data to be written to the store
     */
    set<T>(scope: string, data: T, wait: boolean): Promise<void>
    /**
     * Completely removes data from the app-data server
     * @param scope The scope of the data to remove from the store
     */
    remove(scope: string): Promise<void>
}

export interface ScopedUserAppDataApi {
    /**
     * Gets data from the app-data server for the configured scope
     * @param noCache A value indicating if the cache should be bypassed
     * @returns A promise that resolves to the data or undefined if the data does not exist
     */
    get<T>(noCache: boolean): Promise<T | undefined>
    /**
     * Sets arbitrary data in the app-data server for the configured scope
     * @param data The data to set in the store
     * @param wait A value indicating if the request should wait for the data to be written to the store
     * @returns A promise that resolves when the data has been written to the store
     */
    set<T>(data: T, wait: boolean): Promise<void>
    /**
     * Completely removes data from the app-data server for the configured scope
     * @returns A promise that resolves when the data has been removed from the store
     */
    remove(): Promise<void>
}

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Creates an AppData API for the given endpoint
 * @param endpoint The endpoint to use
 * @param axios The optional axios instance to use for requests
 * @returns The AppData API
 */
export const useAppDataApi = (endpoint: MaybeRef<string>, axios?: Axios): UserAppDataApi => {

    axios = defaultTo(axios, useAxios(null));

    const getUrl = (scope: string, noCache: boolean, flush: boolean) => {
        const fl = flush ? '&flush=true' : ''
        const nc = noCache ? '&noCache=true' : ''
        return `${get(endpoint)}?scope=${scope}${nc}${fl}`
    }

    return {
        get: async <T>(scope: string, noCache: boolean): Promise<T | undefined> => {
            try {
                const { data } = await axios!.get<T>(getUrl(scope, noCache, false))
                return data;
            }
            catch (err: any) {
                //Handle 404 errors as null
                if ('response' in err && err.response.status === 404) {
                    return undefined;
                }
            }
        },

        set: async <T>(scope: string, data: T, wait: boolean) => {
            return axios!.put(getUrl(scope, false, wait), data)
        },
       
        remove: async (scope: string) => {
            return axios!.delete(getUrl(scope, false, false))
        }
    }
}

/**
 * Creates an AppData API that uses at constant scope for all requests
 * @param endpoint The app-data endpoint to use
 * @param scope The data request scope
 * @param axios The optional axios instance to use for requests
 */
export const useScopedAppDataApi = (endpoint: MaybeRef<string>, scope: MaybeRef<string>, axios?: Axios): ScopedUserAppDataApi => {
    const api = useAppDataApi(endpoint, axios);

    return {
        get: <T>(noCache: boolean) => api.get<T>(get(scope), noCache),
        set: <T>(data: T, wait: boolean) => api.set(get(scope), data, wait),
        remove: () => api.remove(get(scope))
    }
}

/**
 * Creates a StorageLikeAsync object that uses the given UserAppDataApi
 * @param api The UserAppDataApi instance to use
 * @returns The StorageLikeAsync object
 */
export const useAppDataAsyncStorage = (api: UserAppDataApi): StorageLikeAsync => {
    return{
        getItem: async (key: string) => {
            const result = await api.get<string[]>(key, false)
            return first(result) || null
        },
        setItem: (key: string, value: string) => {
            //NOTE: An array is used to force axios to serialize the
            //value and send the data to the server a file
            return api.set(key, [value], false)
        },
        removeItem: async (key: string) => {
            return api.remove(key)
        }
    }
}