
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

import { useAxios } from '../axios'
import { defaultTo, isFunction } from 'lodash-es'
import type { Axios } from 'axios'
import type { WebMessage } from '../types'

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
 * Creates an AppData API for the given endpoint
 * @param endpoint The endpoint to use
 * @param axios The optional axios instance to use for requests
 * @returns The AppData API
 */
export const useAppDataApi = (endpoint: string, axios?: Axios): UserAppDataApi => {

    axios = defaultTo(axios, useAxios(null));

    const getEndpoint = () => {
        return isFunction(endpoint) ? endpoint() : endpoint;
    }

    const getUrl = ({ flush, noCache, scope }: GetUrl) => {
        const fl = flush ? '&flush=true' : ''
        const nc = noCache ? '&no_cache=true' : ''
        return `${getEndpoint()}?scope=${scope}${nc}${fl}`
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
            const response = await axios!.get<T>(url, {
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
            const { status, data: responseData } = await axios!.put<WebMessage>(url, data)
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
            const response = await axios.delete<WebMessage>(getUrl({ scope, noCache: false, flush: false }))

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
 * Creates an AppData API that uses at constant scope for all requests
 * @param endpoint The app-data endpoint to use
 * @param scope The data request scope
 * @param axios The optional axios instance to use for requests
 */
export const useScopedAppDataApi = (endpoint: string, scope: string, axios?: Axios): ScopedUserAppDataApi => {
    const api = useAppDataApi(endpoint, axios);

    return {
        get: <T>(options: AppDataGetOptions) => api.get<T>(scope, options),
        set: <T>(data: T, options: AppDataSetOptions) => api.set(scope, data, options),
        remove: () => api.remove(scope)
    }
}
