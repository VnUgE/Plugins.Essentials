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

import { find } from 'lodash-es';
import { useAccountRpc } from '../account';
import type { ApiConfig } from '../types';
import type { MfaMethod } from "./login"
import type { AccountRpcGetResult, AccountRpcResponse } from '../account/types';

/**
 * Server representation of a single MFA method for the current user.
 */
export interface MfaMethodResponse{
    readonly type: MfaMethod;
    readonly enabled: boolean;
    readonly data: any;
}

/**
 * Full MFA configuration returned from the server.
 */
export interface MfaGetResponse{
    readonly supported_methods: MfaMethod[];
    readonly methods: MfaMethodResponse[];
}

/**
 * Outgoing MFA RPC request payload.
 */
export interface MfaRequestJson extends Record<string, any>{
    /** MFA method being configured or executed. */
    readonly type: MfaMethod;
    /** Server-side action name (enable, disable, verify, etc.). */
    readonly action: string;
    /** Optional password to satisfy sensitive operations. */
    readonly password?: string;
}

/**
 * Represents the server API for interacting with the user's
 * MFA configuration.
 */
export interface MfaApi{
    /**
     * Determines if the MFA RPC API is available
     * and enabled on the server.
     * @param getData - Account RPC data containing available methods
     * @returns True if MFA is enabled on the server
     */
    isEnabled(getData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;
    /**
     * Retrieves MFA configuration for the current user.
     * @returns Promise resolving to the user's MFA settings
     */
    getData(): Promise<MfaGetResponse>;
    /**
     * Sends an MFA RPC request to the server.
     * @param request - The RPC request to send
     * @returns Promise resolving to the server response
     */
    sendRequest<T>(request: MfaRequestJson): Promise<AccountRpcResponse<T>>;
}

type MfaRpcMethod = 'mfa.rpc' | 'mfa.get';

/**
 * Creates an API for managing user MFA configuration on the server.
 * Provides methods to query enabled MFA methods, retrieve user-specific
 * MFA settings, and send configuration RPC requests.
 * 
 * @param config - Api configuration instance created at app startup.
 * @returns MFA configuration API instance.
 */
export const useMfaApi = (config: ApiConfig): MfaApi => {

    const { exec, isMethodEnabled } = useAccountRpc<MfaRpcMethod>(config);
   
    const isEnabled = (getData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
        return isMethodEnabled(getData, 'mfa.get');
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
   
/**
 * Gets the mfa data object for the specified type from the mfa data 
 * returned from the server
 * @param mfaData The mfa data object returned from the server
 * @param type The type of mfa method to get the data for
 * @return The mfa data for the specified type, or undefined if not found
 */
export const mfaGetDataFor = <T> (mfaData: Pick<MfaGetResponse, 'methods'>, type: MfaMethod) : T | undefined => {
    const method = find(mfaData.methods, m => m.type === type);
    return method ? method.data : undefined;
}