// Copyright (c) 2023 Vaughn Nugent
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
import { get } from "@vueuse/core"
import { type MaybeRef } from "vue";
import { useAxiosInternal } from "../axios"
import { useUser } from "../user"
import { debugLog } from "../util"
import type { WebMessage } from '../types'
import type { IUserLoginRequest } from "../user/types"
import type { ITokenResponse } from "../session"
import type { UserArg } from "./config";


/**
 * Represents the server api for loging in with a signed OTP
 */
export interface PkiLogin{
    /**
     * Authenticates a user with a signed JWT one time password
     * @param pkiJwt The user input JWT signed one time password for authentication
     * @returns A promise that resolves to the login result
     */
    login<T>(pkiJwt: string): Promise<WebMessage<T>>
}

export interface PkiPublicKey {
    readonly kid: string;
    readonly alg: string;
    readonly kty: string;
    readonly crv: string;
    readonly x: string;
    readonly y: string;
}

/**
 * A base, non-mfa integrated PKI endpoint adapter interface
 */
export interface PkiApi {
    /**
    * Initializes or updates the pki method for the current user
    * @param publicKey The user's public key to initialize or update the pki method
    * @param options Optional extended configuration for the pki method. Gets passed to the server
    */
    addOrUpdate(publicKey: PkiPublicKey, options?: UserArg): Promise<WebMessage>;
    /**
     * Disables the pki method for the current user and passes the given options to the server
     */
    disable(options?: UserArg): Promise<WebMessage>;
    /**
     * Gets all public keys for the current user
     */
    getAllKeys(): Promise<PkiPublicKey[]>;
    /**
     * Removes a single public key by it's id for the current user
     */
    removeKey(kid: string): Promise<WebMessage>;
}

interface PkiLoginRequest extends IUserLoginRequest{
    login: string;
}

/**
 * Creates a pki login api that allows for authentication with a signed JWT
 */
export const usePkiAuth = (pkiEndpoint: MaybeRef<string>): PkiLogin =>{

    const axios = useAxiosInternal()
    const { prepareLogin } = useUser()

    const login = async <T>(pkiJwt: string): Promise<WebMessage<T>> => {

        //try to decode the jwt to confirm its form is valid
        const jwt = decodeJwt(pkiJwt)
        debugLog(jwt)

        //Prepare a login message
        const loginMessage = await prepareLogin() as PkiLoginRequest;

        //Set the 'login' field to the otp
        loginMessage.login = pkiJwt;

        const { post } = get(axios)
        const { data } = await post<ITokenResponse>(get(pkiEndpoint), loginMessage)

        data.getResultOrThrow();

        //Finalize the login
        await loginMessage.finalize(data);

        return data as WebMessage<T>;
    }

    return { login }
}

/**
 * Gets the api for interacting with the the user's pki configuration
 * @param pkiEndpoint The server pki endpoint relative to the base url
 * @returns An object containing the pki api
 */
export const usePkiConfig = (pkiEndpoint: MaybeRef<string>): PkiApi => {

    const axios = useAxiosInternal(null)

    const addOrUpdate = async (publicKey: PkiPublicKey, options?: UserArg): Promise<WebMessage> => {
        const { patch } = get(axios);
        const { data } = await patch<WebMessage>(get(pkiEndpoint), { ...publicKey, ...options });
        return data;
    }

    const getAllKeys = async (): Promise<PkiPublicKey[]> => {
        const { data } = await axios.value.get<WebMessage<PkiPublicKey[]>>(get(pkiEndpoint));
        return data.getResultOrThrow();
    }

    const disable = async (options?: UserArg): Promise<WebMessage> => {
        const { delete: del } = get(axios);
        //emtpy delete request deletes all keys
        const { data } = await del<WebMessage>(get(pkiEndpoint), options);
        return data;
    }

    const removeKey = async (kid: string): Promise<WebMessage> => {
        const { delete: del } = get(axios);
        //Delete request with the id parameter deletes a single key
        const { data } = await del<WebMessage>(`${get(pkiEndpoint)}?id=${kid}`);
        return data;
    }

    return { addOrUpdate, disable, getAllKeys, removeKey }
}
