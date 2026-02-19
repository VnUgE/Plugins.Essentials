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

import type {
    MfaFlow,
    MfaMessage,
    MfaTypeProcessor,
    MfaUpgradeState
} from "./login";

import { type MfaApi } from "./config";
import type { AccountRpcResponse } from "../account/types";
import type { WebMessage } from "../types";

/**
 * Options for TOTP operations requiring password verification.
 */
export interface TotpRequestOptions {
    /** User's current password for sensitive operations */
    readonly password: string;
}

/**
 * Server response containing TOTP configuration data for QR code generation.
 */
export interface TotpUpdateResponse {
    /** Base32-encoded shared secret for the authenticator app */
    readonly secret: string;
    /** Issuer name displayed in authenticator app */
    readonly issuer: string;
    /** Hash algorithm (typically SHA1 or SHA256) */
    readonly algorithm: string;
    /** Number of digits in generated codes (typically 6) */
    readonly digits?: number;
    /** Time step in seconds (typically 30) */
    readonly period?: number;
}


/**
 * API for managing TOTP (time-based one-time password) authenticator app configuration.
 */
export interface TotpApi {
    /**
     * Enables TOTP for the current user and returns the generated secret.
     * @param options - Optional password and request configuration
     * @returns Promise resolving to TOTP configuration including secret and QR code data
     */
    enable(options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse>;
    /**
     * Disables TOTP for the current user.
     * @param options - Optional password for verification
     * @returns Promise resolving to operation status
     */
    disable(options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<string>>;
    /**
     * Verifies a TOTP code for the current session/user.
     * @param code - Six-digit TOTP code from authenticator app
     * @param options - Optional password and request configuration
     * @returns Promise resolving to verification status
     */
    verify(code: number, options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<void>>;
    /**
     * Rotates the TOTP secret and returns the new seed.
     * @param options - Optional password for verification
     * @returns Promise resolving to new TOTP configuration
     */
    updateSecret(options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse>;
}

/**
 * Creates a TOTP API for configuration and validation of authenticator apps.
 * @param sendRequest - MFA request sender from useMfaApi
 * @returns TOTP API bound to the provided MFA request sender
 */
export const useTotpApi = ({ sendRequest }: Pick<MfaApi, 'sendRequest'>): TotpApi => {

    const enable = async (options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse> => {
        const data = await sendRequest<TotpUpdateResponse>({
            ...options,
            type: 'totp',
            action: 'enable'
        });

        return data.getResultOrThrow();
    }

    const disable = (options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'totp',
            action: 'disable'
        });
    }

    const verify = (code: number, options?: Partial<TotpRequestOptions>): Promise<AccountRpcResponse<void>> => {
        return sendRequest<void>({
            ...options,
            type: 'totp',
            action: 'verify',
            verify_code: code
        });
    }

    const updateSecret = async (options?: Partial<TotpRequestOptions>): Promise<TotpUpdateResponse> => {
        const data = await sendRequest<TotpUpdateResponse>({
            ...options,
            type: 'totp',
            action: 'update'
        });
        
        return data.getResultOrThrow();
    }

    return {
        enable,
        disable,
        verify,
        updateSecret
    }
}

/**
 * Gets a pre-configured TOTP mfa flow processor
 * @returns A pre-configured TOTP mfa flow processor
 */
export const totpMfaProcessor = (): MfaTypeProcessor => {

    const getContinuation = async (payload: MfaMessage, state: MfaUpgradeState): Promise<MfaFlow<'totp'>> => {
        return {
            ...payload,
            type: 'totp',
            submit: state.submit
        }
    }

    return {
        type: 'totp',
        getContinuation,
        isSupported: () => true //Totp is always supported there is no limiting api 
    }
}

/**
 * Options for submitting a TOTP code during MFA login flow.
 */
export interface TotpSubmitCodeOptions {
    /**
     * The six-digit TOTP code from authenticator app
     */
    readonly code: number;
    /**
     * Optional password and request configuration
     */ 
    readonly options?: Partial<TotpRequestOptions>;
}

/**
 * Submits a TOTP code for verification using the provided flow
 * @param flow The TOTP mfa flow to submit the code to
 * @param options The options for submitting the TOTP code
 * @returns A promise that resolves to the web message response from the server
 */
export const totpSubmitCode = async (flow: MfaFlow<'totp'>, options: TotpSubmitCodeOptions): Promise<WebMessage> => {

    const result = await flow.submit({
        code: options.code,
        ...options.options
    });

    result.getResultOrThrow();
    return result;
}