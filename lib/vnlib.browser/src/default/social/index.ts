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

import { defaultTo, filter, isNil } from "lodash-es";
import { useAccountRpc, useAccount } from "../account";
import { useSession, type TokenResponse } from "../session";
import type { ApiConfig } from "../types";
import type { AccountRpcGetResult, AccountRpcResponse } from "../account/types";

type ProcedureName = 'upgrade' | 'authenticate' | 'logout';

/**
 * A social OAuth portal that defines a usable server-enabled authentication method.
 */
export interface SocialOAuthMethod {
    /** Whether this method is supported by the server */
    readonly supported: boolean;
    /** Unique identifier for this OAuth method */
    readonly method_id: string;
    /** Method configuration and display data */
    readonly data:{
        /** Whether this method is currently enabled */
        readonly enabled: boolean;
        /** Display name for UI presentation */
        readonly friendly_name: string;
        /** Optional icon URL for branding */
        readonly icon_url?: string;
        /** Optional error message if the method is not enabled */
        readonly error?: string;
    }
}

/**
 * Server response containing available OAuth procedures and configured methods.
 */
export interface SocialLoginRpcResponse{
    /** List of OAuth RPC procedures supported by the server */
    readonly supported_procedures : ProcedureName[]
    /** List of configured OAuth methods/providers */
    readonly methods: SocialOAuthMethod[]
}

/**
 * Arguments for initiating a social OAuth login flow.
 * @template T - Whether auto-redirect is enabled (default true)
 */
export type BeginFlowArgs<T = true> = {
    /** The OAuth method/provider to use */
    readonly method: SocialOAuthMethod;
    /** Whether to automatically redirect to the provider (default true) */
    readonly autoRedirect?: T;
}

/**
 * Options for social OAuth logout operations.
 */
export interface LogoutArguments {
    /** Whether to automatically redirect after logout */
    readonly autoRedirect?: boolean;
    /** Override URL to use instead of server-provided redirect */
    readonly overrideRedirectUrl?: string;
}

/**
 * Server response from social OAuth logout operation.
 */
export interface LogoutResponse {
    /** Optional redirect URL provided by the OAuth provider */
    readonly redirect_url?: string;
}

/**
 * API for managing OAuth2 social login flows with third-party providers.
 */
export interface SocialLoginApi{
    /**
     * Retrieves enabled OAuth portals from server configuration.
     * Filters account RPC data to extract social login methods configured by the server.
     * @param rpcData - Account RPC properties containing social OAuth config
     * @returns Array of enabled social authentication portals
     */
    getPortals(rpcData: Pick<AccountRpcGetResult, 'properties'>): SocialOAuthMethod[]
    /**
     * Begins an OAuth2 social login flow (optionally without auto-redirect).
     * @param args - Social method to use and autoRedirect preference
     * @returns Promise resolving when redirected (or void if autoRedirect is false)
     */
    beginLoginFlow(args: BeginFlowArgs): Promise<void>;
    /**
     * Begins an OAuth2 social login flow and returns the auth URL instead of redirecting.
     * @param args - Social method to use with autoRedirect disabled
     * @returns Promise resolving to the authorization URL
     */
    beginLoginFlow(args: BeginFlowArgs<false>): Promise<{ authUrl: string }>;
    /**
     * Completes the OAuth2 callback exchange and finalizes login.
     * @returns Promise resolving when login is finalized
     */
    completeLogin(): Promise<void>;
    /**
     * Logs out of the current session and optionally redirects to the provider.
     * @param args - Optional redirect configuration
     * @returns Promise resolving to logout response with optional redirect URL
     */
    logout(args?: LogoutArguments): Promise<LogoutResponse | undefined>;
    /**
     * Checks if social OAuth is enabled on the server.
     * @param rpcData - Account RPC data containing available methods
     * @returns True if social OAuth is enabled
     */
    isEnabled(rpcData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;
}

type UpgradeResponse = {
    readonly auth_url: string;
}

/**
 * Internal helper for social OAuth RPC communication.
 * Wraps the account RPC to provide social-specific method execution.
 * @param config - Api configuration instance
 * @returns Social RPC execution helpers with typed method calls
 */
const useSocialRpc = (config: ApiConfig) => {
    const rpc = useAccountRpc(config);

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
 * Configuration options for social OAuth login (reserved for future use).
 */
export interface OauthLoginOptions {
}

/**
 * Creates a social OAuth login API for third-party authentication flows.
 * Supports OAuth2 flows with server-side portal configuration, including
 * authorization URL generation, callback handling, and session management.
 * @param config - Api configuration instance created at app startup
 * @param _options - Reserved for future configuration options
 * @returns Social login API with methods for OAuth flow management
 */
export const useOauthLogin = (config: ApiConfig, _options?: OauthLoginOptions): SocialLoginApi => {

    const { exec, execRaw } = useSocialRpc(config);
    const { prepareLogin, } = useAccount(config);
    const session = useSession(config);
    const { isMethodEnabled } = useAccountRpc<'social_oauth'>(config);

    const getPortals = ({ properties } : Pick<AccountRpcGetResult, 'properties'>): SocialOAuthMethod[] => {
        if (!properties) {
            return [];
        }
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
            await finalize(result as TokenResponse);
        }
        else {
            throw new Error('The server did not return a valid login response');
        }
    }

    const logout = async (args?: LogoutArguments): Promise<LogoutResponse | undefined> => {
        const response = await exec<LogoutResponse | undefined>('logout');
        
        // Rotate client credentials after logout to avoid reuse
        await session.resetClientSecInfo();

        // If the server returned a redirect url, redirect the user to it
        if (args?.autoRedirect === true) {

            // If the user specified an override redirect url, use it 
            // otherwise use the server provided redirect url
            if(!isNil(args.overrideRedirectUrl)){
                window.location.assign(args.overrideRedirectUrl);
            } 
            else if (!isNil(response?.redirect_url)){
                window.location.assign(response.redirect_url);
            }
        }

        return response;
    }

    const isEnabled = ({ rpc_methods } : Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
        return isMethodEnabled({ rpc_methods }, 'social_oauth');
    }

    return {
        getPortals,
        beginLoginFlow: beginLoginFlow as SocialLoginApi['beginLoginFlow'],
        completeLogin,
        logout,
        isEnabled
    }
}