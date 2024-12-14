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

import type {
    IMfaFlow,
    IMfaMessage,
    IMfaTypeProcessor,
    MfaSumissionHandler
} from "./login";

import { type MfaApi } from "./config";
import type { AccountRpcResponse } from "../account/types";

export interface TotpRequestOptions {
    readonly password: string;
}

export interface TotpUpdateResponse {
    secret: string;
    readonly issuer: string;
    readonly algorithm: string;
    readonly digits?: number;
    readonly period?: number;
}


export interface ITotpApi {
    enable(options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse>;
    disable(options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<string>>;
    verify(code: number, options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<void>>;
    updateSecret(options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse>;
}

/**
 * Creates a fido api for configuration and management of fido client devices
 * @param endpoint The fido server endpoint
 * @param axiosConfig The optional axios configuration to use
 * @returns An object containing the fido api
 */
export const useTotpApi = ({ sendRequest }: Pick<MfaApi, 'sendRequest'>): ITotpApi => {

    const enable = async (options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse> => {
        const data = await sendRequest<TotpUpdateResponse>({
            ...options,
            type: 'totp',
            action: 'enable'
        });

        return data.getResultOrThrow();
    }

    const disable = (options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'totp',
            action: 'disable'
        });
    }

    const verify = (code: number, options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<void>> => {
        return sendRequest<void>({
            ...options,
            type: 'totp',
            action: 'verify',
            verify_code: code
        });
    }

    const updateSecret = async (options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse> => {
        const data = await sendRequest<TotpUpdateResponse>({
            ...options,
            type: 'totp',
            action: 'update'
        });
        
        return data.getResultOrThrow();
    }

    return {
        enable,
        disable,
        verify,
        updateSecret
    }
}

/**
 * Gets a pre-configured TOTP mfa flow processor
 * @returns A pre-configured TOTP mfa flow processor
 */
export const totpMfaProcessor = (): IMfaTypeProcessor => {

    const getContinuation = async (payload: IMfaMessage, onSubmit: MfaSumissionHandler): Promise<IMfaFlow> => {
        return {
            ...payload,
            type: 'totp',
            submit: onSubmit.submit
        }
    }

    return {
        type: 'totp',
        getContinuation,
        isSupported: () => true //Totp is always supported there is no limiting api 
    }
}
