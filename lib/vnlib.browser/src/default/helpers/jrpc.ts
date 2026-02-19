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
import { getRandomHex } from './webcrypto'
import type { ApiConfig, WebMessage } from '../types'

/**
 * Configuration for creating a JSON-RPC client instance.
 */
export interface RpcMethodArgs {
    /**
     * The JSON-RPC protocol version to use for requests.
     * Version 2.0.0 is recommended for modern implementations.
     */
    readonly version: '1.0.0' | '2.0.0';
    /**
     * Function that returns the RPC endpoint URL.
     * Allows dynamic endpoint resolution at request time.
     */
    endpoint(): string;
}

/**
 * JSON-RPC client interface providing notification and request methods.
 * Supports both fire-and-forget notifications and request-response patterns.
 */
export interface RpcClient<TMethod extends string> {
    /**
     * Sends a notification to the server (no response expected).
     * Use for fire-and-forget operations where the client doesn't need a response.
     * 
     * @param method - The RPC method name to invoke.
     * @param data - Optional parameters to send with the method.
     * @returns Promise resolving to the raw server response (if any).
     */
    notify(method: TMethod, data?: object): Promise<any>;
    /**
     * Sends a request to the server and waits for a response.
     * Includes a unique request ID for correlation. Use for operations
     * requiring confirmation or return values.
     * 
     * @param method - The RPC method name to invoke.
     * @param data - Optional parameters to send with the method.
     * @returns Promise resolving to the WebMessage response.
     */
    request<T extends WebMessage>(method: TMethod, data?: object): Promise<T>;
}

/**
 * Creates a JSON-RPC 2.0 client for VNLib server communication.
 * The client automatically injects OTP tokens via axios interceptors
 * and provides both notification and request-response patterns.
 * 
 * @param config - Api configuration instance created at app startup.
 * @param args - RPC configuration including endpoint and version.
 * @returns JSON-RPC client with typed method names.
 */
export const useJrpc = <TMethod extends string>(config: ApiConfig, args: RpcMethodArgs): RpcClient<TMethod> => {

    const { endpoint, version } = args;
    
    // Attach interceptors to the config-provided axios instance
    const { post } = useAxios(config);
 
    /**
     * Sends a JSON-RPC notification (no ID, no response expected).
     */
    const notify = async (method: TMethod, data?: object): Promise<any> => {
        const { data: result } = await post<WebMessage>(endpoint(), {
            version,
            method,
            data
        });

        return result;
    }

    /**
     * Sends a JSON-RPC request with a unique ID for response correlation.
     * The server must respond with a matching ID.
     */
    const request = async <T extends WebMessage>(method: TMethod, data?: object): Promise<T> => {

        const { data: result } = await post<T>(endpoint(), {
            version,
            method,
            data,
            id: getRandomHex(8) // Unique request ID required for RPC requests
        });

        return result;
    }

    return { notify, request }
}
