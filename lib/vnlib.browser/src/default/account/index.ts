
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

import { isNil, get, some } from 'lodash-es'
import { useSession, type TokenResponse } from '../session'
import { useAxios } from '../axios'
import type { ApiConfig, WebMessage } from '../types'
import type {
    AccountApi,
    UserProfile,
    ExtendedLoginResponse,
    UserLoginCredential,
    AccountRpcApi,
    AccountRpcResponse,
    AccountRpcGetResult,
    ProfileApi,
    AccountRpcApiConfig
} from './types'
import { useJrpc } from '../helpers/jrpc'

/**
 * Returns the default account RPC configuration.
 * Defines the default endpoint URL for account-related operations.
 * @returns Default account RPC configuration with standard endpoint
 */
export const getDefaultAccountConfig = (): AccountRpcApiConfig => ({
    endpointUrl: '/account'
});

/**
 * Gets the RPC API for interacting with the user's account/profile 
 * login, MFA, and other account-related functions.
 * 
 * @template TMethod - The union of RPC method names supported by this API instance
 * @param config - Api configuration instance.
 * @returns Account RPC API instance with methods for executing RPC calls
 */
export const useAccountRpc = <TMethod extends string>(config: ApiConfig): AccountRpcApi<TMethod> => {

    const axios = useAxios(config);

    const { request } = useJrpc<TMethod>(config, {
        endpoint: () => config.account.endpointUrl,
        version: '2.0.0'
    })

    const getData = async (): Promise<AccountRpcGetResult> => {
        const ep = config.account.endpointUrl;

        const { data } = await axios.get<AccountRpcGetResult>(ep);
        return data;
    }

    const exec = async <T>(method: TMethod, args?: object): Promise<AccountRpcResponse<T>> => {
        return request(method, args);
    }

    const isMethodEnabled = ({ rpc_methods }: Pick<AccountRpcGetResult, 'rpc_methods'>, method: TMethod): boolean => {
        return some(rpc_methods, { method });
    }

    return { getData, exec, isMethodEnabled }
}

type UserAccountMethods = 'login' | 'logout' | 'profile.get' | 'password.reset' | 'heartbeat'

/**
 * Creates the main account API for managing user authentication and sessions.
 * Provides methods for login, logout, profile retrieval, password reset, and heartbeat.
 * 
 * @param config - Api configuration instance created at app startup.
 * @returns Account API instance with methods for user authentication and session management
 */
export const useAccount = (config: ApiConfig): AccountApi => {

    const { updateCredentials, getClientSecInfo, resetClientSecInfo } = useSession(config);

    const { exec } = useAccountRpc<UserAccountMethods>(config);

    const prepareLogin = async () => {
        //Store a copy of the session data and the current time for the login request
        const finalize = async (response: TokenResponse): Promise<void> => {
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

        //Ensure local credentials are rotated on logout
        await resetClientSecInfo()

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
                await prepped.finalize(data as TokenResponse);
            }
        }

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
            await updateCredentials(data as TokenResponse);
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

/**
 * Creates a profile API for managing user profile operations using RPC methods.
 * Provides methods to get and update user profiles, along with capability checks.
 * 
 * @param config - Api configuration instance created at app startup.
 * @returns Profile API instance with methods for profile management
 */
export const useProfile = (config: ApiConfig): ProfileApi => {

    const { exec } = useAccountRpc<'profile.get' | 'profile.update'>(config);

    const getProfile = async <T extends UserProfile>(): Promise<T> => {
        const data = await exec<T>('profile.get');
        return data.getResultOrThrow();
    }

    const updateProfile = async <T extends UserProfile>(profile: Partial<T>): Promise<WebMessage<T>> => {
        return await exec<T>('profile.update', profile);
    }

    const canGetProfile = (data: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
        return some(data.rpc_methods, m => m.method === 'profile.get');
    }

    const canUpdateProfile = (data: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
        return some(data.rpc_methods, m => m.method === 'profile.update');
    }

    return {
        getProfile,
        updateProfile,
        canGetProfile,
        canUpdateProfile
    }
}

/**
 * Checks whether the user is currently authenticated based on account RPC data.
 * 
 * @param data - Account RPC result containing authentication status
 * @returns True if user is authenticated, false otherwise
 */
export const isLoggedIn = (data: Pick<AccountRpcGetResult, 'status'>): boolean => {
    return get(data, 'status.authenticated', false) as boolean;
}

/**
 * Checks whether the authenticated user has a local account (not a social/federated account).
 * 
 * @param data - Account RPC result containing account type information
 * @returns True if user has a local account, false otherwise
 */
export const isLocalAccount = (data: Pick<AccountRpcGetResult, 'status'>): boolean => {
    return get(data, 'status.is_local_account', false) as boolean;
}
