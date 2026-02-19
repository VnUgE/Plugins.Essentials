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

import { isObjectLike, merge } from 'lodash-es'
import axiosGlobal from 'axios'
import type { Axios, AxiosResponse, AxiosRequestConfig } from 'axios'
import type { ApiConfig } from '../types'
import { useSession } from '../session'

/**
 * Creates request interceptor that injects OTP tokens into authenticated requests.
 * The token is generated per-request using the session's HMAC key and includes
 * the request path to prevent replay attacks.
 * @param apiConfig - Api configuration instance for token generation
 * @returns Axios request interceptor function
 */
const createRequestInterceptor = (apiConfig: ApiConfig) => {
    const { generateOneTimeToken } = useSession(apiConfig);

    const { tokenHeader } = apiConfig;

    return async (request: any) => {

        // Only inject token if header is configured
        if (tokenHeader) {
            const path = `${request.baseURL}${request.url}`;
            let pathName = path;

            // Extract pathname from absolute URLs
            if (path.match(/https?:\/\//)) {
                pathName = new URL(path).pathname;
            }

            // Generate OTP (returns null if not logged in)
            const token = await generateOneTimeToken(pathName);

            if (token) {
                request.headers = request.headers ?? {};
                request.headers[tokenHeader] = token;
            }
        }

        return request;
    };
};

/**
 * Creates response interceptor that adds getResultOrThrow() helper to WebMessage responses.
 * This provides a convenient way to extract successful results or propagate errors
 * in a consistent format matching server-side validation.
 * @returns Axios response interceptor function
 */
const createResponseInterceptor = () => {
    return (response: AxiosResponse) => {
        // Add getResultOrThrow helper if response is a structured object
        if (isObjectLike(response.data)) {
            response.data.getResultOrThrow = () => {
                if (response.data.success) {
                    return response.data.result;
                } else {
                    // Throw in API call format for consistent error handling
                    throw { response };
                }
            };
        }
        return response;
    };
};

interface AxiosInstanceInternal extends Axios {
    /**
     * Internal flag to track if VNLib interceptors have been added to 
     * this instance. This ensures interceptors are only applied once per
     * instance.
     */
    __vnlib_interceptors_added__?: boolean;
}

/**
 * Returns the shared axios instance preconfigured for use with VNLib 
 * backend server plugins.
 *
 * @param config - Api configuration instance with axios settings
 * @returns The shared axios instance
 */
export const useAxios = (config: ApiConfig): Axios => {
    const defaultInstance = config.axios as AxiosInstanceInternal;

    if (!defaultInstance.__vnlib_interceptors_added__) {
        defaultInstance.interceptors.request.use(createRequestInterceptor(config));
        defaultInstance.interceptors.response.use(createResponseInterceptor());
        defaultInstance.__vnlib_interceptors_added__ = true;
    }

    return defaultInstance;
};

/**
 * Creates a new axios instance derived from the config's shared instance, with
 * the supplied options merged in. VNLib configuration variables are merged
 * overrides for the shared instance's defaults. It's safe to use with VNLib
 * backend plugins.
 *
 * Use this instead of `useAxios` when you need per-request options such as an
 * `AbortSignal`, custom timeout, or progress callbacks. Cache the returned instance
 * yourself if the same options are reused across calls.
 *
 * @param config - Api configuration instance with axios settings
 * @param options - Axios request config merged over the shared instance's defaults
 * @returns A new axios instance with VNLib interceptors attached
 */
export const createAxios = (config: ApiConfig, options: AxiosRequestConfig): Axios => {
    const mergedConfig = merge({}, config.axios.defaults, options);
    const instance = axiosGlobal.create(mergedConfig);

    instance.interceptors.request.use(createRequestInterceptor(config));
    instance.interceptors.response.use(createResponseInterceptor());

    return instance;
};