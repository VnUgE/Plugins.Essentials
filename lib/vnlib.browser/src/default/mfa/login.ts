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

import { decodeJwt, type JWTPayload } from "jose";
import { isArray, map, mapKeys, without } from 'lodash-es';
import { debugLog } from "../helpers/debugLog";
import { useAccountRpc, useAccount } from "../account";
import type { ExtendedLoginResponse, UserLoginCredential } from "../account/types";
import type { ITokenResponse } from "../session";
import type { WebMessage } from "../types";

export type MfaMethod = 'totp' | 'fido' | 'pkotp';

export interface IMfaSubmission {
    /**
     * TOTP code submission
     */
    readonly code?:  number;

    readonly fido?: any;
}

/**
 * The mfa upgrade message that is signed and sent to the client
 * to complete the mfa upgrade process
 */
export interface IMfaMessage extends JWTPayload {
    /**
     * The supported mfa methods for the user
     */
    readonly capabilities: MfaMethod[];
    /**
     * The time in seconds that the mfa upgrade is valid for
     */
    readonly expires?: number;
}

export interface IMfaFlow<T extends MfaMethod>{
    /**
     * The mfa method this continuation is for 
     */
    readonly type: T;
    /**
     * Sumits the mfa message to the server and attempts to complete 
     * a login process
     * @param message The mfa submission to send to the server
     * @returns A promise that resolves to a login result
     */
    submit: <T>(message: IMfaSubmission) => Promise<WebMessage<T>>;
}

/**
 * Retuned by the login API to signal an MFA upgrade is 
 * required to continue the login process
 */
export interface IMfaContinuation {
    /**
   * The time in seconds that the mfa upgrade is valid for
   */
    readonly expires?: number;
    /**
     * The mfa methods that are supported by the user
     * to continue the login process
     */
    readonly methods: IMfaFlow<MfaMethod>[]
}

/**
 * Interface for handling mfa upgrade submissions to the server
 */
export interface MfaUpgradeState {
    /**
     * Submits an mfa upgrade submission to the server
     * @param submission The mfa upgrade submission to send to the server to complete an mfa login
     */
    submit<T>(submission: IMfaSubmission): Promise<WebMessage<T>>;

    execRpcCommand: ReturnType<typeof useAccountRpc>['exec'];
}

/**
 * Interface for processing mfa messages from the server of a given 
 * mfa type
 */
export interface IMfaTypeProcessor {
    readonly type: MfaMethod;
    /**
     * Determines if the current runtime supports login with this method
     * @returns True if the mfa type is supported by the client
     */
    readonly isSupported: () => boolean;

    /**
    * Processes an MFA message payload of the registered mfa type
    * @param payload The mfa message from the server as a string
    * @param state The submission handler to use to submit the mfa upgrade
    * @returns A promise that resolves to a Login request
    */
    getContinuation: (payload: IMfaMessage, state: MfaUpgradeState) => Promise<IMfaFlow<MfaMethod>>
}

export interface IMfaLoginManager {
    /**
     * Gets a value that indicates if the given mfa method is supported by the client
     * @param method The mfa method to check for support
     * @returns True if the mfa method is supported by the client
     */
    isSupported(method: MfaMethod): boolean;
    /**
     * Logs a user in with the given username and password, and returns a login result
     * or a mfa flow continuation depending on the login flow
     * @param credential The login credential to for the user (username and password)
     */
    login(credential: UserLoginCredential): Promise<WebMessage | IMfaContinuation>;
    /**
     * Checks if the given response is an mfa continuation response
     * @param response The response to check
     * @returns True if the response is an mfa continuation response
     */
    isMfaResponse: (response: WebMessage | IMfaContinuation) => response is IMfaContinuation;
}

const getMfaProcessor = (handlers: IMfaTypeProcessor[]) =>{

    //Store handlers by their mfa type
    const handlerMap = mapKeys(handlers, (h) => h.type)

    const { exec } = useAccountRpc<'mfa.login'>();

    //Creates a submission handler for an mfa upgrade
    const createState = (type: MfaMethod, upgrade : string, finalize: (res: ITokenResponse) => Promise<void>) 
    : MfaUpgradeState => {

        const submit = async<T>(submission: IMfaSubmission): Promise<WebMessage<T>> => {
           
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
                await finalize(data as ITokenResponse);
            }

            return data;
        }

        return { submit, execRpcCommand: exec }
    }

    const processMfa = async (mfaMessage: string, finalize: (res: ITokenResponse) => Promise<void>): Promise<IMfaContinuation> => {

        //Mfa message is a jwt, decode it (unsecure decode)
        const mfa = decodeJwt(mfaMessage) as IMfaMessage;
        debugLog('mfa login upgrade', mfa);

        const supportedContinuations = map(mfa.capabilities, (supportedType): Promise<IMfaFlow<MfaMethod> | undefined> => {
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
            methods: without(methods, undefined) as IMfaFlow<MfaMethod>[]
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
 * Gets the mfa login handler for the accounts backend
 * @param handlers A list of mfa handlers to register
 * @returns The configured mfa login handler
 */
export const useMfaLogin = (handlers: IMfaTypeProcessor[]): IMfaLoginManager => {

    //get the user instance
    const { login: userLogin } = useAccount()

    //Get new mfa processor
    const { processMfa, isSupported } = getMfaProcessor(handlers);

    //Login that passes through logins with mfa
    const login = async <T>(credential: UserLoginCredential): Promise<ExtendedLoginResponse<T> | IMfaContinuation> => {

        //User-login with mfa response
        const response = await userLogin<T | IMfaUpgradeResponse>(credential);

        const { mfa, upgrade } = response.getResultOrThrow() as IMfaUpgradeResponse;

        //Get the mfa upgrade message from the server
        if (mfa && upgrade && mfa === true){

            /**
             * Gets all contiuations from the server's list of supported 
             * mfa upgrade types. This table will be the union of all 
             * enabled client handlers and the mfa methods the user has
             * enabled on their account for continuation of the login process
             */
            const continuations = await processMfa(upgrade, response.finalize);

            return { ...continuations };
        }

        //If no mfa upgrade message is returned, the login is complete
        return response as ExtendedLoginResponse<T>;
    }

    const isMfaResponse = (response: WebMessage | IMfaContinuation): response is IMfaContinuation => {
        //Check if the response is an mfa continuation
        return 'methods' in response 
            && isArray(response.methods) 
            && response.methods.length > 0;
    }

    return { login, isSupported, isMfaResponse }
}