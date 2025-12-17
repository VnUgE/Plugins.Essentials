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

import { isObjectLike } from 'lodash-es'
import { type Axios, type AxiosResponse, type CreateAxiosDefaults } from 'axios'
import type { ApiConfig } from '../types';
import { useSession } from '../session'
import { getInternalState } from '../config';

/**
 * Axios configuration used by VNLib interceptors. Stores a concrete instance
 * and metadata required by request decorators.
 */
export interface AxiosConfig {
    /**
     * Pre-configured axios instance that interceptors will attach to.
     */
    readonly instance: Axios;
    /**
     * Header name used to send the OTP token.
     */
    readonly tokenHeader: string;
}

/**
 * Returns the default axios request configuration for VNLib API clients.
 * Defines timeout and credential defaults.
 */
export const getDefaultAxiosRequestConfig = (): CreateAxiosDefaults => ({
    timeout: 60 * 1000,
    withCredentials: false
});

/**
 * Creates request interceptor that injects OTP tokens into authenticated requests.
 * The token is generated per-request using the session's HMAC key and includes
 * the request path to prevent replay attacks.
 */
const createRequestInterceptor = (apiConfig: ApiConfig) => {
    const { generateOneTimeToken } = useSession(apiConfig);

    const { tokenHeader } = apiConfig.axios;

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

/**
 * Creates an axios instance configured for VNLib server communication.
 * The instance includes request interceptors for OTP token injection and
 * response interceptors for WebMessage result extraction.
 * 
 * @param config - Optional axios configuration to merge with scoped defaults.
 * @param scope - Optional config scope token. Uses default scope if omitted.
 * @returns Configured axios instance with VNLib interceptors attached.
 */
export const useAxios = (config: ApiConfig, axiosInstance?: Axios): Axios => {

    const instance = axiosInstance ?? config.axios.instance;

    // Cache a set of instnaces for checking if interceptors have 
    // been added already
    const configuredInstances = getInternalState(
        config, 
        'axios:state:instances', 
        () => new WeakSet<Axios>()
    )

    if (!configuredInstances.has(instance)) {
        instance.interceptors.request.use(createRequestInterceptor(config));
        instance.interceptors.response.use(createResponseInterceptor());
        configuredInstances.add(instance);
    }

    return instance;
};