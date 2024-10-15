
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

import { isNil } from 'lodash-es'
import { useSession, type ITokenResponse } from '../session'
import { useAxios } from '../axios'
import { getGlobalStateInternal } from '../globalState'
import type { WebMessage } from '../types'
import type { 
    AccountApi, 
    UserProfile, 
    ExtendedLoginResponse 
} from './types'
import { manualComputed } from '../storage'
import { useJrpc } from '../helpers/jrpc'

//Export public types
export type * from './types'

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'

export interface AccountRpcMethod {
    readonly method: string;
    readonly options: string[];
}

export interface AccountRpcResponse<T> extends WebMessage<T> {
    readonly id: string;
    readonly code: number;
    readonly method?: string;
}

export interface AccountRpcRequest{
    readonly id: string;
    readonly method: string;
    readonly args: object;
}

export interface AccountRpcApi<TMethod>{
    getMethods(): Promise<AccountRpcMethod[]>;
    exec<T = any>(method: AccountRpcMethod | TMethod, args?: object): Promise<AccountRpcResponse<T>>;
}

export interface AccountRpcApiConfig{
    readonly endpointUrl: string;
}

interface RpcGetResponse {
    readonly httpMethods: HttpMethod[];
    readonly rpc_methods: AccountRpcMethod[];
}

/**
 * Gets the rpc api for interacting with the user's account/profile 
 * login, mfa, and other account related functions
 */
export const useAccountRpc = <TMethod extends string>(): AccountRpcApi<TMethod> => {
    
    const gConfig = getGlobalStateInternal();
    const config = manualComputed(() => gConfig.get('account'));
    const { get } = useAxios()

    const { request } = useJrpc<TMethod>({
        endpoint: () => config.get('endpointUrl'),
        version: '2.0.0'
    })

    const getMethods = async (): Promise<AccountRpcMethod[]> => {
        const ep = config.get('endpointUrl');

        const { data } = await get<RpcGetResponse>(ep);
        return data.rpc_methods;
    }

    const exec = async <T>(method: TMethod, args?: object): Promise<AccountRpcResponse<T>> => {
        return request(method, args);
    }

    return { getMethods, exec }
}

type UserAccountMethods = 'login' | 'logout' | 'profile.get' | 'password.reset' | 'heartbeat'

export const useAccount = (): AccountApi => {

    const { updateCredentials, getClientSecInfo, KeyStore } = useSession()

    const { exec } = useAccountRpc<UserAccountMethods>();

    const prepareLogin = async () => {
        //Store a copy of the session data and the current time for the login request
        const finalize = async (response: ITokenResponse): Promise<void> => {
            //Update the session with the new credentials
            await updateCredentials(response);
        }

        //Get or regen the client public key
        const { publicKey, browserId } = await getClientSecInfo();

        return {
            clientid: browserId,
            pubkey: publicKey,
            localtime: new Date().toISOString(),
            locallanguage: navigator.language,
            username: '',
            password: '',
            finalize
        }
    }

    const logout = async (): Promise<WebMessage> => {
     
        const result = await exec('logout');

        //regen session credentials on successful logout
        await KeyStore.regenerateKeysAsync()

        // return the response
        return result;
    }

    const login = async <T>(userName: string, password: string): Promise<ExtendedLoginResponse<T>> => {

        const prepped = await prepareLogin();

        //Set the username and password
        prepped.username = userName;
        prepped.password = password;

        //Send the login request
        const data = await exec<T>('login', prepped);

        // Check the response
        if (data.success === true && 'token' in data) {

            // If the server returned a token, complete the login
            if (!isNil(data.token)) {
                await prepped.finalize(data as ITokenResponse);
            }
        }

        return {
            ...data,
            finalize: prepped.finalize
        }
    }

    const getProfile = async <T extends UserProfile>(): Promise<T> => {

        // Get the user's profile from the profile endpoint
        const data = await exec<T>('profile.get');

        // return response data
        return data.getResultOrThrow();
    }

    const resetPassword = async (current: string, newPass: string, args: object): Promise<WebMessage> => {

        // Send a post to the reset password endpoint
        const data = await exec<WebMessage>('password.reset', {
            ...args,
            current,
            new_password: newPass,
        });

        return data
    }

    const heartbeat = async (): Promise<void> => {
        // Send a post to the heartbeat endpoint
        const data = await exec('heartbeat');

        //If success flag is set, update the credentials
        if (data.success && 'token' in data) {

            //Update credential
            await updateCredentials(data as ITokenResponse);
        }
    }

    return {
        prepareLogin,
        logout,
        login,
        getProfile,
        resetPassword,
        heartbeat
    }
}
