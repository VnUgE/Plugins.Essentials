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
import type { ITokenResponse } from "../session"

/**
 * Represents a user login credential
 */
export interface UserLoginCredential{
    readonly userName: string;
    readonly password: string;
}

/**
 * Represents the user/account server api
 */
export interface AccountApi {
    /**
     * Prepares a login request for the server
     */
    prepareLogin(): Promise<IUserLoginRequest>
    /**
     * Attempts to log the user out 
     */
    logout(): Promise<WebMessage>
    /**
     * Attempts to log the user in with a possible mfa upgrade result
     * @param userName The username to login with
     * @param password The password to login with
     * @returns A promise that resolves to the login result
     */
    login<T>(credential: UserLoginCredential): Promise<ExtendedLoginResponse<T>>
    /**
     * Resets the password for the current user
     * @param current the user's current password
     * @param newPass the user's new password
     * @param args any additional arguments to send to the server
     */
    resetPassword(current: string, newPass: string, args: object): Promise<WebMessage>
    /**
     * Sends a heartbeat to the server to keep the session alive
     * and regenerate credentials as designated by the server.
     */
    heartbeat(): Promise<void>
}

/**
 * Represents the user profile api for getting and updating 
 * the user's profile
 */
export interface UserProfileApi {
    /**
     * Determines if the user can get their profile
     * @param accData The account data to check against
     * @returns true if the user can get their profile, false otherwise
     */
    canGetProfile(accData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;
    /**
     * Determines if the user can update their profile
     * @param accData The account data to check against
     * @returns true if the user can update their profile, false otherwise
     */
    canUpdateProfile(accData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;
    /**
     * Gets the user profile from the server
     */
    getProfile<T extends UserProfile>(): Promise<T>
    /**
      * Updates the user profile with the given data
      * @param data The data to update the user profile with
      */
    updateProfile<T extends UserProfile>(data: Partial<T>): Promise<WebMessage>
}

/**
 * Represents a request to finalize a user login
 */
export interface IUserLoginRequest {
    /**
     * Finalizes a login process with the given response from the server
     * @param response The finalized login response from the server
     */
    finalize(response: ITokenResponse): Promise<void>
}

export interface ExtendedLoginResponse<T> extends WebMessage<T> {
    finalize: (response : ITokenResponse) => Promise<void>
}

/**
 * Represents the minimal user profile supported/returned 
 * from the server
 */
export interface UserProfile {
    readonly email: string | undefined;
}

/**
 * Represents an RPC method that can be called on the 
 * account rpc server
 */
export interface AccountRpcMethod {
    readonly method: string;
    readonly options: string[];
}

/**
 * Represents the basic response template from an account
 * rpc method
 */
export interface AccountRpcResponse<T> extends WebMessage<T> {
    readonly id: string;
    readonly code: number;
    readonly method?: string;
}

/**
 * Represents a basic request to an account rpc method
 */
export interface AccountRpcRequest {
    readonly id: string;
    readonly method: string;
    readonly args: object;
}

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'

// Must match Essentials.Accounts rpc server GET response
export interface AccountRpcGetResult {
    readonly http_methods: HttpMethod[];
    readonly rpc_methods: AccountRpcMethod[];
    readonly accept_content_type: string;
    readonly properties: object & { 
        readonly type: string 
    }[];
    readonly status: {
        readonly authenticated: boolean;
        readonly is_local_account: boolean;
    }
}

/**
 * Represents the account rpc api interacting with the rpc server
*/
export interface AccountRpcApi<TMethod>{
    /**
     * Determines if the account rpc api is enabled on the server
     * @param rpcData The account rpc data returned from a call to getData()
     */
    getData(): Promise<AccountRpcGetResult>;
    /**
     * Executes the given account rpc method with the given arguments
     * @param method The account rpc method to execute
     * @param args The arguments to pass to the method
     * @return A promise that resolves to the account rpc response
     */
    exec<T = any>(method: AccountRpcMethod | TMethod, args?: object): Promise<AccountRpcResponse<T>>;
    /**
     * Determines if the given method is enabled on the server
     * @param data The account rpc data returned from a call to getData()
     * @param method The method to check for
     * @return true if the method is enabled, false otherwise
     */
    isMethodEnabled(data: Pick<AccountRpcGetResult, 'rpc_methods'>, method: TMethod): boolean;
}
