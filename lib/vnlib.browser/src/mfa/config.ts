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

import { useAccountRpc } from '../account';
import { includes, map } from 'lodash-es';
import type { MfaMethod } from "./login"
import { AccountRpcResponse } from '../account/types';

export type UserArg = object;

export interface MfaMethodResponse{
    readonly type: MfaMethod;
    readonly enabled: boolean;
    readonly data: any;
}

export interface MfaGetResponse{
    readonly supported_methods: MfaMethod[];
    readonly methods: MfaMethodResponse[];
}

export interface MfaRequestJson extends Record<string, any>{
    readonly type: MfaMethod;
    readonly action: string;
    readonly password?: string;
}


/**
 * Represents the server api for interacting with the user's 
 * mfa configuration
 */
export interface MfaApi{
    /**
     * Determines if the mfa rpc api is available
     * and enabled on the server
     */
    isEnabled(): Promise<boolean>;
    /**
     * Gets the mfa data for the current user
     */
    getData(): Promise<MfaGetResponse>;
    /**
     * Sends an mfa rpc request to the server
     * @param request The rpc request to send
     * @returns A promise that resolves to the server response
     */
    sendRequest<T>(request: MfaRequestJson): Promise<AccountRpcResponse<T>>;
}

type MfaRpcMethod = 'mfa.rpc' | 'mfa.get';

/**
 * Gets the api for interacting with the the user's mfa configuration
 * @param mfaEndpoint The server mfa endpoint relative to the base url
 * @returns An object containing the mfa api
 */
export const useMfaApi = (): MfaApi =>{

    const { getData: getRpcData, exec } = useAccountRpc<MfaRpcMethod>();

    const isEnabled = async (): Promise<boolean> => {
        const { rpc_methods } = await getRpcData();
        return includes(map(rpc_methods, m => m.method), 'mfa.rpc');
    }

    const getData = async (): Promise<MfaGetResponse> => {
        const data = await exec<MfaGetResponse>('mfa.get');
        return data.getResultOrThrow();
    }

    const sendRequest = async <T>(request: MfaRequestJson): Promise<AccountRpcResponse<T>> => {
        const data = await exec<T>('mfa.rpc' , request);
        data.getResultOrThrow();
        return data;
    }
  
    return {
        isEnabled,
        getData,
        sendRequest
    }
}

