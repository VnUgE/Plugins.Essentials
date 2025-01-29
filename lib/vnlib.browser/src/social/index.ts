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

import { defaultTo, filter } from "lodash-es";
import { useAccount } from "../account";
import { useSession, type ITokenResponse } from "../session";
import { useAccountRpc } from "../account"
import { AccountRpcResponse } from "../account/types";

type ProcedureName = 'upgrade' | 'authenticate' | 'logout';

/**
 * A social OAuth portal that defines a usable server 
 * enabled authentication method
 */
export interface SocialOAuthMethod {
    readonly supported: boolean;
    readonly method_id: string;
    readonly data:{
        readonly enabled: boolean;
        readonly friendly_name: string;
        readonly icon_url?: string;
    }
}

export interface SocialLoginRpcResponse{
    readonly supported_procedures : ProcedureName[]
    readonly methods: SocialOAuthMethod[]
}

export type BeginFlowArgs<T = true> = {
    readonly method: SocialOAuthMethod;
    readonly autoRedirect?: T;
}

export interface SocialLoginApi{
    /**
     * Gets enabled social login methods
     */
    getPortals(): Promise<SocialOAuthMethod[]>
    /**
     * Begins an OAuth2 social web authentication flow against the server
     * handling encryption and redirection of the browser
     * @param method The desired method to use for login
     */
    beginLoginFlow(args: BeginFlowArgs): Promise<void>;
    /**
     * Begins an OAuth2 social web authentication flow against the server
     * handling encryption and redirection of the browser
     * @param method The desired method to use for login
     */
    beginLoginFlow(args: BeginFlowArgs<false>): Promise<{ authUrl: string }>;
    /**
     * Completes a login flow if authorized, otherwise throws an error
     * with the message from the server
     * @returns A promise that resolves when the login is complete 
     */
    completeLogin(): Promise<void>;
    /**
     * Logs out of the current session
     * @returns A promise that resolves to true if the logout could be handled by 
     * the current method, otherwise false
     */
    logout(): Promise<void>;
}

export interface UseOauthLoginInterface {
     <T extends AccountRpcExtendedProps>(getData: () => Promise<T>): SocialLoginApi
    (): Pick<SocialLoginApi, 'logout' | 'completeLogin'>
}

export interface AccountRpcExtendedProps {
    readonly properties: object & {
        readonly type: string
    } []
}

type UpgradeResponse = {
    readonly auth_url: string;
}

const useSocialRpc = () => {
    const rpc = useAccountRpc();

    const execRaw = async <T>(procedure: ProcedureName, args?: object): Promise<AccountRpcResponse<T>> => {
        const result = await rpc.exec<T>('social_oauth', { procedure, args });

        if (result.method !== 'social_oauth') {
            throw new Error('The server did not return a valid social_oauth response');
        }

        return result;
    }

    const exec = async <T>(procedure: ProcedureName, args?: object): Promise<T> => {
        const { getResultOrThrow } = await execRaw<T>(procedure, args);
        return getResultOrThrow();
    }

    return { exec, execRaw }
}

/**
 * Creates a new social login api for the given methods
 */
export const useOauthLogin : UseOauthLoginInterface = <T extends AccountRpcExtendedProps>(getData?: () => Promise<T>): SocialLoginApi => {

    const { exec, execRaw } = useSocialRpc()
    const { prepareLogin, } = useAccount();
    const { clearLoginState } = useSession();

    const getPortals = async (): Promise<SocialOAuthMethod[]> => {

        if (!getData) {
            return [];
        }

        const { properties } = await getData();
        const [social_properties] = filter(properties, { type: 'social_oauth' });
        return defaultTo((social_properties as any as SocialLoginRpcResponse)?.methods, []);
    }

    const beginLoginFlow = async ({ method, autoRedirect }: BeginFlowArgs): Promise<{authUrl: string } | undefined> => {
        if(!method.data.enabled){
            throw new Error('The selected method is not enabled on the server');
        }

        const login = await prepareLogin()

        //The server should have returned an auth url on a successful upgrade
        const { auth_url: authUrl } = await exec<UpgradeResponse>('upgrade', {
            method_id: method.method_id,
            ...login,
         })
        
         //user requested to not redirect
        if((autoRedirect as boolean | undefined) === false){
            return { authUrl };
        }

        //Redirect to the auth url otherwise
        window.location.assign(authUrl);
    }

    const completeLogin = async (): Promise<void> => {
        //get query arguments from the current url
        const search = new URLSearchParams(window.location.search);
        const state = search.get('state');
        const code = search.get('code');

        if(!state || !code){
            throw new Error('The server did not return a valid state or code');
        }

        //Exchange code with the server to login
        const result = await execRaw('authenticate', { state, code });
        result.getResultOrThrow();

        if ('token' in result){
            const { finalize } = await prepareLogin();
            await finalize(result as ITokenResponse);
        }
        else{
            throw new Error('The server did not return a valid login response');
        }
    }

    const logout = async (): Promise<void> => {
        await exec<void>('logout');
        clearLoginState();
    }

    return {
        getPortals,
        beginLoginFlow: (beginLoginFlow as any),
        completeLogin,
        logout
    }
}