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

import { decodeJwt, type JWTPayload } from "jose";
import { find, isArray, map, mapKeys, without } from 'lodash-es';
import type { AuthenticationResponseJSON } from "@simplewebauthn/browser";
import { debugLog } from "../helpers/debugLog";
import { useAccountRpc, useAccount } from "../account";
import type { AccountRpcGetResult, ExtendedLoginResponse, UserLoginCredential } from "../account/types";
import type { TokenResponse } from "../session";
import type { ApiConfig, WebMessage } from "../types";

export type MfaMethod = 'totp' | 'fido' | 'pkotp';

export interface MfaSubmission {
    /**
     * Verification code from authenticator app.
     */
    readonly code?:  number;
    
    /**
     * FIDO security key credential.
     */
    readonly fido?: AuthenticationResponseJSON;
}

/**
 * MFA challenge issued by the server during login.
 */
export interface MfaMessage extends JWTPayload {
    /**
     * Available MFA methods for this user.
     */
    readonly capabilities: MfaMethod[];
    
    /**
     * How long the challenge remains valid (seconds).
     */
    readonly expires?: number;
}

export interface MfaFlow<T extends MfaMethod>{
    /**
     * The MFA method for this flow.
     */
    readonly type: T;
    
    /**
     * Submits the MFA response to complete login.
     * @param message - MFA verification data
     * @returns Server response with authentication result
     */
    submit: <T>(message: MfaSubmission) => Promise<WebMessage<T>>;
}

/**
 * MFA challenge that requires additional verification to complete login.
 */
export interface MfaContinuation {
    /**
     * How long the challenge remains valid (seconds).
     */
    readonly expires?: number;
    
    /**
     * Available verification methods.
     */
    readonly methods: MfaFlow<MfaMethod>[]
}

/**
 * Handler for submitting MFA verification responses.
 */
export interface MfaUpgradeState {
    /**
     * Submits MFA verification to the server.
     * @param submission - MFA verification data
     * @returns Server response
     */
    submit<T>(submission: MfaSubmission): Promise<WebMessage<T>>;

    /**
     * RPC command executor for server communication.
     */
    execRpcCommand: ReturnType<typeof useAccountRpc>['exec'];
}

/**
 * Handler for a specific MFA method.
 */
export interface MfaTypeProcessor {
    readonly type: MfaMethod;
    
    /**
     * Checks if this MFA method is supported on this device.
     * @returns True if supported
     */
    readonly isSupported: () => boolean;

    /**
     * Prepares the MFA verification flow.
     * @param payload - Server challenge data
     * @param state - Submission handler
     * @returns MFA flow for this method
     */
    getContinuation: (payload: MfaMessage, state: MfaUpgradeState) => Promise<MfaFlow<MfaMethod>>
}

export interface MfaLoginManager {
    /**
     * Checks if an MFA method is supported on this device.
     * @param method - MFA method to check
     * @returns True if the method is supported
     */
    isSupported(method: MfaMethod): boolean;
    
    /**
     * Authenticates a user, handling MFA if required.
     * @param credential - User login credentials
     * @returns Login result or MFA continuation
     */
    login(credential: UserLoginCredential): Promise<WebMessage | MfaContinuation>;
    
    /**
     * Checks if a response requires MFA verification.
     * @param response - Server response to check
     * @returns True if MFA is required
     */
    isMfaResponse: (response: WebMessage | MfaContinuation) => response is MfaContinuation;
}

/**
 * Configuration options for creating an MFA login manager.
 */
export interface MfaLoginOptions {
    /**
     * Array of MFA type processors to enable (TOTP, FIDO, PKI OTP).
     */
    readonly handlers: MfaTypeProcessor[];
}

/**
 * Internal factory for processing MFA upgrade messages.
 * Manages the MFA continuation flow by coordinating registered handlers
 * with server-provided capabilities.
 * 
 * @param handlers - Array of MFA type processors (TOTP, FIDO, PKI OTP).
 * @param config - Api configuration instance.
 */
const getMfaProcessor = (handlers: MfaTypeProcessor[], config: ApiConfig) => {

    //Store handlers by their mfa type
    const handlerMap = mapKeys(handlers, (h) => h.type)

    const { exec } = useAccountRpc<'mfa.login'>(config);

    //Creates a submission handler for an mfa upgrade
    const createState = (type: MfaMethod, upgrade : string, finalize: (res: TokenResponse) => Promise<void>) 
    : MfaUpgradeState => {

        const submit = async<T>(submission: MfaSubmission): Promise<WebMessage<T>> => {
           
            //Exec against the mfa.login method
            const data = await exec<T>('mfa.login', {
                //publish submission
                ...submission,
                //Pass raw upgrade message back to server as its signed
                upgrade,
                //Pass the desired mfa type back to the server
                type,
                //Local time as an ISO string of the current time
                localtime: new Date().toISOString(),
                //Tell endpoint this is an mfa submission
                mfa: true
            })

            // If the server returned a token, finalize the login
            if (data.success && 'token' in data) {
                await finalize(data as TokenResponse);
            }

            return data;
        }

        return { submit, execRpcCommand: exec }
    }

    const processMfa = async (mfaMessage: string, finalize: (res: TokenResponse) => Promise<void>): Promise<MfaContinuation> => {

        //Mfa message is a jwt, decode it (unsecure decode)
        const mfa = decodeJwt(mfaMessage) as MfaMessage;
        debugLog(config, 'mfa login upgrade', mfa);

        const supportedContinuations = map(mfa.capabilities, (supportedType): Promise<MfaFlow<MfaMethod> | undefined> => {
            //Select the mfa handler
            const handler = handlerMap[supportedType];

            //If no handler is found, throw an error
            if (!handler || handler.type !== supportedType) {
                return Promise.resolve(undefined);
            }

            //Init api state handler
            const submitHandler = createState(supportedType, mfaMessage, finalize);

            //Process the mfa message
            return handler.getContinuation(mfa, submitHandler);
        })

        const methods = await Promise.all(supportedContinuations);

        return {
            expires: mfa.expires,
            methods: without(methods, undefined) as MfaFlow<MfaMethod>[]
        }
    }

    const isSupported = (method: MfaMethod): boolean => {
        return handlerMap[method]?.isSupported() || false;
    }

    return { processMfa, isSupported }
}

interface IMfaUpgradeResponse{
    readonly mfa: boolean;
    readonly upgrade: string;
}

/**
 * Creates an MFA-aware login handler that processes multi-factor authentication flows.
 * Extends the basic login process to handle MFA upgrade challenges from the server,
 * coordinating between registered MFA handlers (TOTP, FIDO, PKI) and user credentials.
 * 
 * @param config - Api configuration instance created at app startup.
 * @param options - Configuration including handlers.
 * @returns MFA login manager with methods for login and capability checking.
 */
export const useMfaLogin = (config: ApiConfig, options: MfaLoginOptions): MfaLoginManager => {

    const { handlers } = options;

    //get the user instance
    const { login: userLogin } = useAccount(config)

    //Get new mfa processor
    const { processMfa, isSupported } = getMfaProcessor(handlers, config);

    //Login that passes through logins with mfa
    const login = async <T>(credential: UserLoginCredential): Promise<ExtendedLoginResponse<T> | MfaContinuation> => {

        //User-login with mfa response
        const response = await userLogin<T | IMfaUpgradeResponse>(credential);

        const { mfa, upgrade } = response.getResultOrThrow() as IMfaUpgradeResponse;

        //Get the mfa upgrade message from the server
        if (mfa && upgrade && mfa === true){

            /**
             * Builds all continuations for the intersection of client-enabled
             * handlers and server-declared MFA capabilities for this user.
             */
            const continuations = await processMfa(upgrade, response.finalize);

            return { ...continuations };
        }

        //If no mfa upgrade message is returned, the login is complete
        return response as ExtendedLoginResponse<T>;
    }

    const isMfaResponse = (response: WebMessage | MfaContinuation): response is MfaContinuation => {
        //Check if the response is an mfa continuation 
        return 'methods' in response 
            && isArray(response.methods)
            && response.methods.length > 0
            && 'expires' in response;
    }

    return { login, isSupported, isMfaResponse }
}

/**
 * Checks if MFA login is supported by the server based on the available RPC methods.
 * @param getData - Account RPC data containing available methods
 * @returns True if MFA login is supported on the server
 */
export const isMfaLoginSupported = (getData: Pick<AccountRpcGetResult, 'rpc_methods'>): boolean => {
    return find(getData.rpc_methods, m => m.method === 'mfa.login') !== undefined;
}