
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

import { filter, isNil } from 'lodash-es'
import { useSession, type ITokenResponse } from '../session'
import { useAxios } from '../axios'
import { useLibraryStateInternal } from '../globalState'
import type { WebMessage } from '../types'
import type { 
    AccountApi, 
    UserProfile, 
    ExtendedLoginResponse, 
    UserLoginCredential,
    AccountRpcApi,
    AccountRpcResponse,
    AccountRpcGetResult,
    UserProfileApi
} from './types'
import { useJrpc } from '../helpers/jrpc'
import { debugLog } from '../helpers/debugLog'

export type * from './types'

/**
 * Gets the rpc api for interacting with the user's account/profile 
 * login, mfa, and other account related functions
 */
export const useAccountRpc = <TMethod extends string>(): AccountRpcApi<TMethod> => {
    
    const gConfig = useLibraryStateInternal();
    const { get } = useAxios();

    const endpoint = () => {
        const { endpointUrl } = gConfig.get('account');
        return endpointUrl;
    }

    const { request } = useJrpc<TMethod>({ endpoint, version: '2.0.0' });

    const getData = async (): Promise<AccountRpcGetResult> => {
        const { data } = await get<AccountRpcGetResult>(endpoint());
        return data;
    }

    const exec = async <T>(method: TMethod, args?: object): Promise<AccountRpcResponse<T>> => {
        return request(method, args);
    }

    const isMethodEnabled = ({ rpc_methods }: Pick<AccountRpcGetResult, 'rpc_methods'>, method: TMethod): boolean => {
        return filter(rpc_methods, { method }).length > 0;
    }

    return { getData, exec, isMethodEnabled }
}

type UserAccountMethods = 'login' | 'logout' | 'password.reset' | 'heartbeat';

export const useAccount = (): AccountApi => {

    const { updateCredentials, getClientSecInfo, KeyStore } = useSession();

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

    const login = async <T>({ userName, password }: UserLoginCredential): Promise<ExtendedLoginResponse<T>> => {

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

        debugLog('Account login response', data);

        return {
            ...data,
            finalize: prepped.finalize
        }
    }

    const resetPassword = async (current: string, newPass: string, args: object): Promise<WebMessage> => {

        // Send a post to the reset password endpoint
        const data = await exec<WebMessage>('password.reset', {
            ...args,
            current,
            new_password: newPass,
        });

        return data;
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
        resetPassword,
        heartbeat
    }
}

type UserProfileMethods = 'profile.get' | 'profile.update';

/**
 * Gets the user profile api for getting and updating the user's profile
 * @returns An object containing the user profile api for getting and updating the user's profile
 */
export const useProfile = () : UserProfileApi => {

    const { exec, isMethodEnabled } = useAccountRpc<UserProfileMethods>();

    const canGetProfile = (accData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
        return isMethodEnabled(accData, 'profile.get');
    }

    const canUpdateProfile = (accData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
        return isMethodEnabled(accData, 'profile.update');
    }

    const getProfile = async <T extends UserProfile>(): Promise<T> => {
        // Get the user's profile from the profile endpoint
        const data = await exec<T>('profile.get');
        return data.getResultOrThrow();
    }

    const updateProfile = async <T extends UserProfile>(profile: Partial<T>): Promise<WebMessage> => {
        return exec<T>('profile.update', profile);
    }

    return {
        canGetProfile,
        canUpdateProfile,
        getProfile,
        updateProfile
    }
}

/**
 * Reads an account status object and returns true if the user is logged in
 * as indicated by the server
 */
export const isLoggedIn = (data: Pick<AccountRpcGetResult, 'status'>) : boolean => {
    return data?.status?.authenticated === true;
}

/**
 * Reads an account status object and returns true if the user is a local account
 * as indicated by the server
 */
export const isLocalAccount = (data: Pick<AccountRpcGetResult, 'status'>): boolean => {
    return data?.status?.is_local_account === true;
}