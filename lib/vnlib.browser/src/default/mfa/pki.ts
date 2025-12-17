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

import { decodeJwt } from "jose"
import { trim } from "lodash-es";
import { useAccount, useAccountRpc } from "../account"
import { debugLog } from "../helpers/debugLog"
import type { ApiConfig, WebMessage } from '../types'
import type { UserLoginRequest, AccountRpcResponse, AccountRpcGetResult } from "../account/types"
import type { TokenResponse } from "../session"
import { mfaGetDataFor, type MfaGetResponse, type MfaApi } from "./config";

/**
 * Represents the server API for logging in with a signed OTP JWT token.
 * Enables public key-based authentication using registered cryptographic keys.
 */
export interface OtpLogin {
    /**
     * Authenticates a user with a signed JWT one-time password.
     * The JWT must be signed with a private key matching a registered public key.
     * 
     * @param otpJwt - The user's signed JWT one-time password token
     * @returns A promise that resolves to the login result
     */
    login<T>(otpJwt: string): Promise<WebMessage<T>>

    /**
     * Checks if OTP login method is enabled on the server.
     * 
     * @param getResponse - RPC method list from server capabilities
     * @returns True if 'otp.login' method is available
     */
    isEnabled(getResponse: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean;
}

/**
 * JWK format public key for OTP authentication.
 * Represents an elliptic curve public key registered for cryptographic login.
 */
export interface OtpPublicKey {
    /** Key ID - unique identifier for this public key */
    readonly kid: string;
    /** Algorithm - cryptographic algorithm (e.g., 'ES256', 'ES384', 'ES512') */
    readonly alg: string;
    /** Key type - typically 'EC' for elliptic curve */
    readonly kty: string;
    /** Curve - elliptic curve name (e.g., 'P-256', 'P-384', 'P-521') */
    readonly crv: string;
    /** X coordinate - base64url-encoded x coordinate of the public key */
    readonly x: string;
    /** Y coordinate - base64url-encoded y coordinate of the public key */
    readonly y: string;
}

/**
 * Must match the OTP RPC response object from the server.
 */
export interface OtpRpcGetData {
    /**
     * The list of OTP public keys registered for the user
     */
    readonly keys: OtpPublicKey[]; 
    /**
     * Whether the user can add new keys
     */
    readonly can_add_keys: boolean;
    /**
     * The total size of all OTP device data stored 
     * on the server for the user
     */
    readonly data_size: number;
    /**
     * The maximum size of OTP device data that can be 
     * stored on the server for the user
     */
    readonly max_size: number;
}

/**
 * Options for OTP key management operations.
 * Typically requires password verification for security-sensitive operations.
 */
export interface OtpManagementOptions extends Record<string, any> {
    /** User's current password for verification */
    readonly password: string;
}

/**
 * API for managing OTP public keys and authentication settings.
 * Provides operations to add, remove, and disable OTP authentication.
 */
export interface OtpApi {
    /**
     * Adds a new public key or updates an existing one for OTP authentication.
     * 
     * @param publicKey - The user's public key in JWK format
     * @param options - Optional password and extended configuration
     * @returns Server response with operation result
     */
    addOrUpdate(publicKey: OtpPublicKey, options?: Partial<OtpManagementOptions>): Promise<AccountRpcResponse<string>>;
    
    /**
     * Disables OTP authentication for the current user.
     * Removes all registered keys and prevents OTP login.
     * 
     * @param options - Optional password for verification
     * @returns Server response with operation result
     */
    disable(options?: Partial<OtpManagementOptions>): Promise<AccountRpcResponse<string>>;
    
    /**
     * Removes a single public key by its key ID.
     * 
     * @param key - The public key to remove (uses kid property)
     * @param options - Optional password for verification
     * @returns Server response with operation result
     */
    removeKey(key: OtpPublicKey, options?: Partial<OtpManagementOptions>): Promise<AccountRpcResponse<string>>;
}

interface OtpLoginRequest extends UserLoginRequest {
    login: string;
}

/**
 * Configuration options for OTP cryptographic authentication.
 * Used to create an {@link OtpLogin} instance via {@link useOtpLogin}.
 */
export interface OtpAuthOptions {
    /**
     * API configuration instance created at app startup.
     */
    readonly config: ApiConfig;
}

/**
 * Creates an OTP-based authentication API for cryptographic login.
 * Enables login via signed JWT tokens using the user's registered public keys.
 * Supports ECDSA signatures (ES256, ES384, ES512) for authentication.
 * 
 * @param options - Configuration including API config
 * @returns OTP login API instance
 * 
 * @remarks
 * This is the login mechanism, not the key management API.
 * Use {@link useOtpApi} for managing registered public keys.
 */
export const useOtpLogin = (options: OtpAuthOptions): OtpLogin => {

    const { config } = options;
    
    const { prepareLogin } = useAccount(config)
    const { exec, isMethodEnabled } = useAccountRpc<'otp.login'>(config)

    const login = async <T>(otpJwt: string): Promise<WebMessage<T>> => {

        //trim any padding 
        otpJwt = trim(otpJwt);

        //try to decode the jwt to confirm its form is valid
        const jwt = decodeJwt(otpJwt)
        debugLog(config, jwt)

        //Prepare a login message
        const loginMessage = await prepareLogin() as OtpLoginRequest;

        //Set the 'login' field to the otp
        loginMessage.login = otpJwt;

        const data = await exec('otp.login', loginMessage)

        data.getResultOrThrow();

        if('token' in data){
            //Finalize the login
            await loginMessage.finalize(data as TokenResponse);
        }

        return data as WebMessage<T>;
    }

    const isEnabled = (getResponse: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
       return isMethodEnabled(getResponse, 'otp.login');
    }

    return { login, isEnabled }
}

/**
 * Creates an API for managing OTP public keys and authentication settings.
 * Provides operations to add, update, remove keys and disable OTP authentication.
 * 
 * @param sendRequest - MFA request sender from {@link useMfaApi}
 * @returns OTP management API instance
 * 
 * @remarks
 * This is for key management, not authentication.
 * Use {@link useOtpLogin} for the actual login mechanism.
 */
export const useOtpApi = ({ sendRequest }: Pick<MfaApi, 'sendRequest'>): OtpApi => {

    const addOrUpdate = async (publicKey: OtpPublicKey, options?: Partial<OtpManagementOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'pkotp',
            action: 'add_key',
            public_key: publicKey
        })
    }

    const disable = (options?: Partial<OtpManagementOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'pkotp',
            action: 'disable'
        })
    }

    const removeKey = (key: OtpPublicKey, options?: Partial<OtpManagementOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'pkotp',
            action: 'remove_key',
            delete_id: key.kid
        })
    }

    return { addOrUpdate, disable, removeKey }
}


/**
 * Gets the OTP mfa data for the user
 * @param mfaData The mfa data object returned from the server
 * @returns The OTP mfa data for the user, or undefined if not found
 */
export const otpGetMfaData = (mfaData : MfaGetResponse): OtpRpcGetData | undefined => {
    return mfaGetDataFor<OtpRpcGetData>(mfaData, 'pkotp');
}