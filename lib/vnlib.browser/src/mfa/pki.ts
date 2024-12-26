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

import { decodeJwt } from "jose"
import { trim } from "lodash-es";
import { useAccount, useAccountRpc } from "../account"
import { debugLog } from "../util"
import type { WebMessage } from '../types'
import type { IUserLoginRequest, AccountRpcResponse } from "../account/types"
import type { ITokenResponse } from "../session"
import type { MfaApi } from "./config";

/**
 * Represents the server api for loging in with a signed OTP
 */
export interface PkOtpLogin{
    /**
     * Authenticates a user with a signed JWT one time password
     * @param pkiJwt The user input JWT signed one time password for authentication
     * @returns A promise that resolves to the login result
     */
    login<T>(pkiJwt: string): Promise<WebMessage<T>>
}
export type PkiLogin = PkOtpLogin

export interface PkiPublicKey {
    readonly kid: string;
    readonly alg: string;
    readonly kty: string;
    readonly crv: string;
    readonly x: string;
    readonly y: string;
}

export interface IOtpRequestOptions extends Record<string, any> {
    readonly password: string;
}

/**
 * A base, non-mfa integrated PKI endpoint adapter interface
 */
export interface OtpApi {
    /**
    * Initializes or updates the pki method for the current user
    * @param publicKey The user's public key to initialize or update the pki method
    * @param options Optional extended configuration for the pki method. Gets passed to the server
    */
    addOrUpdate(publicKey: PkiPublicKey, options?: Partial<IOtpRequestOptions>): Promise<AccountRpcResponse<string>>;
    /**
     * Disables the pki method for the current user and passes the given options to the server
     */
    disable(options?: Partial<IOtpRequestOptions>): Promise<AccountRpcResponse<string>>;
    /**
     * Removes a single public key by it's id for the current user
     */
    removeKey(key: PkiPublicKey, options?: Partial<IOtpRequestOptions>): Promise<AccountRpcResponse<string>>;
}

interface PkiLoginRequest extends IUserLoginRequest{
    login: string;
}

/**
 * Creates a pki login api that allows for authentication with a signed JWT
 */
export const useOtpAuth = (): PkOtpLogin =>{

    const { prepareLogin } = useAccount()
    const { exec } = useAccountRpc()

    const login = async <T>(pkiJwt: string): Promise<WebMessage<T>> => {

        //trim any padding 
        pkiJwt = trim(pkiJwt);

        //try to decode the jwt to confirm its form is valid
        const jwt = decodeJwt(pkiJwt)
        debugLog(jwt)

        //Prepare a login message
        const loginMessage = await prepareLogin() as PkiLoginRequest;

        //Set the 'login' field to the otp
        loginMessage.login = pkiJwt;

        const data = await exec('otp.login', loginMessage)

        data.getResultOrThrow();

        if('token' in data){
            //Finalize the login
            await loginMessage.finalize(data as ITokenResponse);
        }

        return data as WebMessage<T>;
    }

    return { login }
}

/**
 * Gets the api for interacting with the the user's pki configuration
 * @param pkiEndpoint The server pki endpoint relative to the base url
 * @returns An object containing the pki api
 */
export const useOtpApi = ({ sendRequest }: Pick<MfaApi, 'sendRequest'>): OtpApi => {

    const addOrUpdate = async (publicKey: PkiPublicKey, options?: Partial<IOtpRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'pkotp',
            action: 'add_key',
            public_key: publicKey
        })
    }

    const disable = (options?: Partial<IOtpRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'pkotp',
            action: 'disable'
        })
    }

    const removeKey = (key: PkiPublicKey, options?: Partial<IOtpRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'pkotp',
            action: 'remove_key',
            delete_id: key.kid
        })
    }

    return { addOrUpdate, disable, removeKey }
}
