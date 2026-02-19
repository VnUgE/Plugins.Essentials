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

import type { WebMessage } from "../types"
import type { TokenResponse } from "../session"

/**
 * Configuration for the account RPC API endpoint.
 */
export interface AccountRpcApiConfig {
    /**
     *  Absolute or relative URL for account RPC operations. 
     */
    readonly endpointUrl: string;
}

/**
 * Username/password credential used for primary authentication.
 */
export interface UserLoginCredential {
    /** Username or email, depending on server policy. */
    readonly userName: string;
    /** Plain-text password entered by the user. */
    readonly password: string;
}

/**
 * Account API for user authentication and profile management.
 */
export interface AccountApi {
    /**
     * Prepares a login request for the server.
     * @returns Prepared login request
     */
    prepareLogin(): Promise<UserLoginRequest>

    /**
     * Logs the current user out of their session.
     * @returns Server response
     */
    logout(): Promise<WebMessage>

    /**
     * Authenticates a user with the server using the specified credentials.
     * @param credential - User's login credentials
     * @returns Login result, may include MFA requirements
     */
    login<T>(credential: UserLoginCredential): Promise<ExtendedLoginResponse<T>>

    /**
     * Changes the current user's password.
     * @param current - Current password
     * @param newPass - New password
     * @param args - Additional arguments for the password reset
     * @returns Server response
     */
    resetPassword(current: string, newPass: string, args: object): Promise<WebMessage>

    /**
     * Keeps the user's session active with the server.
     */
    heartbeat(): Promise<void>
}

/**
 * Login request prepared for server authentication.
 */
export interface UserLoginRequest {
    /**
     * Completes the login process with the server's response.
     * @param response - Server response containing session token
     */
    finalize(response: TokenResponse): Promise<void>
}

/**
 * Login response with optional continuation for multi-factor authentication.
 */
export interface ExtendedLoginResponse<T> extends WebMessage<T> {
    /**
     * Completes the login process with the server's response.
     * @param response - Server response containing session token
     */
    finalize: (response: TokenResponse) => Promise<void>
}

export interface UserProfile {
    readonly email: string | undefined;
}

export interface AccountRpcMethod {
    readonly method: string;
    readonly options: string[];
}

/**
 * JSON-RPC response envelope returned by account endpoints.
 */
export interface AccountRpcResponse<T> extends WebMessage<T> {
    readonly id: string;
    readonly code: number;
    readonly method?: string;
}

/**
 * JSON-RPC request payload for account operations.
 */
export interface AccountRpcRequest {
    readonly id: string;
    readonly method: string;
    readonly args: object;
}

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'

export interface AccountRpcGetResult {
    /** 
     * HTTP methods supported by the server.
     */
    readonly http_methods: HttpMethod[];
    /** 
     * Available RPC methods on the server. 
     */
    readonly rpc_methods: AccountRpcMethod[];
    /** 
     * Content type expected by the server.
     */
    readonly accept_content_type: string;
    /** 
     * Server feature configuration
     */
    readonly properties: object & {
        readonly type: string
    }[];
    /**
     * Current authentication status. 
     */
    readonly status: {
        readonly authenticated: boolean;
        readonly is_local_account: boolean;
    }
}

/**
 * RPC client for account operations.
 */
export interface AccountRpcApi<TMethod> {
    /**
     * Gets server configuration and available methods.
     * @returns Server configuration and RPC methods
     */
    getData(): Promise<AccountRpcGetResult>;

    /**
     * Executes an RPC method on the server.
     * @param method - RPC method name
     * @param args - Optional method arguments
     * @returns Server response
     */
    exec<T = any>(method: AccountRpcMethod | TMethod, args?: object): Promise<AccountRpcResponse<T>>;

    /**
     * Checks if a method is available on the server.
     * @param data - Server RPC configuration
     * @param method - Method name to check
     * @returns True if the method is available
     */
    isMethodEnabled(data: Pick<AccountRpcGetResult, 'rpc_methods'>, method: TMethod): boolean;
}

/**
 * Represents the profile management API for retrieving and updating user profiles.
 */
export interface ProfileApi {
    /**
     * Retrieves the current user's profile from the server.
     * @template T - The profile type extending UserProfile
     * @returns Promise resolving to the user's profile
     * @throws Error if profile cannot be retrieved or user is not authenticated
     */
    getProfile<T extends UserProfile>(): Promise<T>;

    /**
     * Updates the current user's profile on the server.
     * @template T - The profile type extending UserProfile
     * @param profile - Partial profile object containing fields to update
     * @returns Promise resolving to a web message with the updated profile
     */
    updateProfile<T extends UserProfile>(profile: Partial<T>): Promise<WebMessage<T>>;

    /**
     * Checks if the profile.get RPC method is available/enabled.
     * @param data - Account RPC result containing available methods
     * @returns True if profile retrieval is supported
     */
    canGetProfile(data: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;

    /**
     * Checks if the profile.update RPC method is available/enabled.
     * @param data - Account RPC result containing available methods
     * @returns True if profile updates are supported
     */
    canUpdateProfile(data: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;
}