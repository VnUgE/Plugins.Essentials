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

import { cloneDeep, merge, isObjectLike, defaultTo, memoize } from 'lodash-es'
import axios, { type Axios, type AxiosRequestConfig, type AxiosResponse } from 'axios'
import { useSession } from '../session'
import { useLibraryStateInternal } from '../globalState';
import type { GlobalAxiosConfig } from '../types';

const axiosInternal = memoize(() => {
    const _config = useLibraryStateInternal();
    const { generateOneTimeToken } = useSession();

    const axiosConfig = () => _config.get('axios');

    return {
        axiosConfig,
        onRequestFulfilled: async (config: any) => {
            //Get the current global config/token header value
            const { tokenHeader } = axiosConfig();

            // See if the current session is logged in
            if (tokenHeader) {
    
                const path = `${config.baseURL}${config.url}`
                let pathName = path;
    
                //see if absolute url or relative
                if (path.match(/https?:\/\//)) {
                    //Is absolute
                    pathName = new URL(path).pathname
                }
    
                // Get an otp for the request (may be null if not logged in)
                const token = await generateOneTimeToken(pathName);
    
                if(token){
                    config.headers[tokenHeader] = token;
                }
            }
    
            // Return the config
            return config
        },
        // Add response interceptor to add a function to the response to get the 
        // result or throw an error to match the WebMessage server message
        onResponseFulfilled: (response: AxiosResponse) => {
            //Add a function to the response to get the result or throw an error
            if (isObjectLike(response.data)) {
                response.data.getResultOrThrow = () => {
                    if (response.data.success) {
                        return response.data.result;
                    } else {
                        //Throw in apicall format to catch in the catch block
                        throw { response };
                    }
                };
            }
            return response;
        }
    }
});

export type useAxiosConfig =  GlobalAxiosConfig | AxiosRequestConfig | undefined | null;

/**
 * Gets a reactive axios instance with the default configuration
 * @param config Optional Axios instance configuration to apply, will be merged with the default config
 * @returns A reactive ref to an axios instance
 */
export const useAxios = (config?: useAxiosConfig): Axios => {

    const { axiosConfig, onRequestFulfilled, onResponseFulfilled } = axiosInternal();
    const local = defaultTo(config, {});
    const merged = merge<GlobalAxiosConfig, useAxiosConfig>(cloneDeep(axiosConfig()), local);

    //Exec user configuration callback if it's defined
    const instance = merged.configureAxios
        ? merged.configureAxios(axios.create(merged))
        : axios.create(merged);

    //Assign interceptors
    instance.interceptors.request.use(onRequestFulfilled);
    instance.interceptors.response.use(onResponseFulfilled);

    return instance
};