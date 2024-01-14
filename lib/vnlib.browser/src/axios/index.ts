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

import { computed, MaybeRef, type Ref } from 'vue'
import { cloneDeep, merge, isObjectLike, defaultTo } from 'lodash-es'
import axios, { type Axios, type AxiosRequestConfig, type AxiosResponse } from 'axios'
import { get, toReactive } from '@vueuse/core';
import { useSession, type ISession } from '../session'
import { getGlobalStateInternal } from '../globalState';

const configureAxiosInternal = (instance: Axios, session: ISession, tokenHeader: Ref<string | undefined>) => {

    const { loggedIn, generateOneTimeToken } = session;

    //Add request interceptor to add the token to the request
    instance.interceptors.request.use(async (config) => {

        //Get the current global config/token header value
        const tokenHeaderValue = get(tokenHeader);

        // See if the current session is logged in
        if (tokenHeaderValue && loggedIn.value) {
            // Get an otp for the request
            config.headers[tokenHeaderValue] = await generateOneTimeToken(config.url!);
        }
        // Return the config
        return config
    }, function (error) {
        // Do something with request error
        return Promise.reject(error)
    })

    //Add response interceptor to add a function to the response to get the result or throw an error to match the WebMessage server message
    instance.interceptors.response.use((response: AxiosResponse) => {

        //Add a function to the response to get the result or throw an error
        if (isObjectLike(response.data)) {
            response.data.getResultOrThrow = () => {
                if (response.data.success) {
                    return response.data.result;
                } else {
                    //Throw in apicall format to catch in the catch block
                    throw { response };
                }
            }
        }
        return response;
    })

    return instance;
}

/**
 * Gets a reactive axios instance with the default configuration
 * @param config Optional Axios instance configuration to apply, will be merged with the default config
 * @returns A reactive ref to an axios instance
 */
export const useAxiosInternal = (() => {

    //Get the session and utils
    const { axios: _axiosConfig } = getGlobalStateInternal();

    const tokenHeader = computed(() => defaultTo(_axiosConfig.value.tokenHeader, ''));
    const session = useSession();

    return (config?: MaybeRef<AxiosRequestConfig | undefined | null>): Readonly<Ref<Axios>> => {

        /**
         * Computed config, merges the default config with the passed config. When 
         * the fallback config is updated, it will compute the merged config
         */
        const mergedConfig = config ?
            computed(() => merge(cloneDeep(_axiosConfig.value), get(config)))
            : _axiosConfig

        /**
         * Computes a new axios insance when the config changes
         */
        const computedAxios = computed(() => {
            const instance = axios.create(mergedConfig.value);
            return configureAxiosInternal(instance, session, tokenHeader);
        });

        return computedAxios;
    }
})();

/**
 * Gets a reactive axios instance that merges the supplied config with the global config
 * @param config Optional Axios instance configuration to apply, will be merged with the default config
 * @returns The axios instance
 */
export const useAxios = (config: MaybeRef<AxiosRequestConfig | undefined | null>): Axios => {

    const axiosRef = useAxiosInternal(config);

    /**
     * Return a reactive axios instance. When updates are made to the config, 
     * the instance will be updated without the caller needing to re-request it.
     */
    return toReactive(axiosRef);
}
