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

import { useAxios } from '../axios'
import { getRandomHex } from './webcrypto'
import type { WebMessage } from '../types'

export interface RpcMethodArgs {
    /**
     * The json rpc version to use for the request
     */
    readonly version: '1.0.0' | '2.0.0'
    /**
     * The endpoint to send the request to
     */
    endpoint(): string;
}

export interface RpcClient<TMethod extends string> {
    /**
     * Sends a notification to the server
     * @param method The method to send
     * @param data The data to send with the method
     */
    notify(method: TMethod, data?: object): Promise<any>;
    /**
     * Sends a request to the server
     * @param method The method to send
     * @param data The data to send with the method
     */
    request<T extends WebMessage>(method: TMethod, data?: object): Promise<T>;
}

/**
 * Creates a json rpc client for the specified endpoint
 * @param args The arguments to create the client with
 * @returns A json rpc client
 */
export const useJrpc = <TMethod extends string>(args: RpcMethodArgs): RpcClient<TMethod> => {

    const { endpoint, version } = args;
    const { post } = useAxios()

    const notify = async (method: TMethod, data?: object): Promise<any> => {
        const { data: result } = await post<WebMessage>(endpoint(), {
            version,
            method,
            data
        });

        return result;
    }

    const request = async <T extends WebMessage>(method: TMethod, data?: object): Promise<T> => {

        const { data: result } = await post<T>(endpoint(), {
            version,
            method,
            data,
            id: getRandomHex(8) //Id is required for request functions
        });

        return result;
    }

    return { notify, request }
}
