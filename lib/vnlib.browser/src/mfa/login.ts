// Copyright (c) 2023 Vaughn Nugent
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
import { forEach, isNil } from 'lodash-es';
import { get } from "@vueuse/core";
import { debugLog } from "../util"
import { useUser, type ExtendedLoginResponse } from "../user";
import { AccountEndpoint, type IUserInternal } from "../user/internal";
import { useAxiosInternal } from "../axios";
import type { Ref } from "vue";
import type { Axios } from "axios";
import type { ITokenResponse } from "../session";
import type { WebMessage } from "../types";

export enum MfaMethod {
    TOTP = 'totp'
}

export interface IMfaSubmission {
    /**
     * TOTP code submission
     */
    readonly code?:  number;
}

export interface IMfaMessage extends JWTPayload {
    /**
     * The type of mfa upgrade
     */
    readonly type: MfaMethod;
    /**
     * The time in seconds that the mfa upgrade is valid for
     */
    readonly expires?: number;
}

export interface IMfaFlowContinuiation extends IMfaMessage {
    /**
     * Sumits the mfa message to the server and attempts to complete 
     * a login process
     * @param message The mfa submission to send to the server
     * @returns A promise that resolves to a login result
     */
    submit: <T>(message: IMfaSubmission) => Promise<WebMessage<T>>;
}

/**
 * Interface for handling mfa upgrade submissions to the server
 */
export interface MfaSumissionHandler {
    /**
     * Submits an mfa upgrade submission to the server
     * @param submission The mfa upgrade submission to send to the server to complete an mfa login
     */
    submit<T>(submission: IMfaSubmission): Promise<WebMessage<T>>;
}

/**
 * Interface for processing mfa messages from the server of a given 
 * mfa type
 */
export interface IMfaTypeProcessor {
    readonly type: MfaMethod;
    /**
     * Processes an MFA message payload of the registered mfa type
     * @param payload The mfa message from the server as a string
     * @param onSubmit The submission handler to use to submit the mfa upgrade
     * @returns A promise that resolves to a Login request
     */
    processMfa: (payload: IMfaMessage, onSubmit : MfaSumissionHandler) => Promise<IMfaFlowContinuiation>
}

export interface IMfaLoginManager {
    /**
     * Logs a user in with the given username and password, and returns a login result
     * or a mfa flow continuation depending on the login flow
     * @param userName The username of the user to login
     * @param password The password of the user to login
     */
    login(userName: string, password: string): Promise<WebMessage | IMfaFlowContinuiation>;
}

const getMfaProcessor = (user: IUserInternal, axios:Ref<Axios>) =>{

    //Store handlers by their mfa type
    const handlerMap = new Map<string, IMfaTypeProcessor>();

    //Creates a submission handler for an mfa upgrade
    const createSubHandler = (upgrade : string, finalize: (res: ITokenResponse) => Promise<void>) :MfaSumissionHandler => {

        const submit = async<T>(submission: IMfaSubmission): Promise<WebMessage<T>> => {
            const { post } = get(axios);

            //All mfa upgrades use the account login endpoint
            const ep = user.getEndpoint(AccountEndpoint.Login);

            //Get the mfa type from the upgrade message
            const { type } = decodeJwt(upgrade) as IMfaMessage;

            //MFA upgrades currently use the login endpoint with a query string. The type that is captured from the upgrade
            const endpoint = `${ep}?mfa=${type}`;

            //Submit request
            const response = await post<ITokenResponse>(endpoint, {
                //Pass raw upgrade message back to server as its signed
                upgrade,
                //publish submission
                ...submission,
                //Local time as an ISO string of the current time
                localtime: new Date().toISOString()
            })

            // If the server returned a token, complete the login
            if (response.data.success && !isNil(response.data.token)) {
                await finalize(response.data)
            }

            return response.data as WebMessage<T>;
        }

        return { submit }
    }

    const processMfa = (mfaMessage: string, finalize: (res: ITokenResponse) => Promise<void>) : Promise<IMfaFlowContinuiation> => {
        
        //Mfa message is a jwt, decode it (unsecure decode)
        const mfa = decodeJwt(mfaMessage) as IMfaMessage;
        debugLog(mfa)

        //Select the mfa handler
        const handler = handlerMap.get(mfa.type);

        //If no handler is found, throw an error
        if(!handler){
            throw new Error('Server responded with an unsupported two factor auth type, login cannot continue.')
        }

        //Init submission handler
        const submitHandler = createSubHandler(mfaMessage, finalize);

        //Process the mfa message
        return handler.processMfa(mfa, submitHandler);
    }

    const registerHandler = (handler: IMfaTypeProcessor) => {
        handlerMap.set(handler.type, handler);
    }

    return { processMfa, registerHandler }
}

/**
 * Gets a pre-configured TOTP mfa flow processor
 * @returns A pre-configured TOTP mfa flow processor
 */
export const totpMfaProcessor = (): IMfaTypeProcessor => {

    const processMfa = async (payload: IMfaMessage, onSubmit: MfaSumissionHandler): Promise<IMfaFlowContinuiation> => {
        return { ... payload, submit: onSubmit.submit }
    }

    return {
        type: MfaMethod.TOTP,
        processMfa
    }
}

/**
 * Gets the mfa login handler for the accounts backend
 * @param handlers A list of mfa handlers to register
 * @returns The configured mfa login handler
 */
export const useMfaLogin = (handlers : IMfaTypeProcessor[]): IMfaLoginManager => {
    
    //get the user instance
    const user = useUser() as IUserInternal

    const axios = useAxiosInternal(null)

    //Get new mfa processor
    const mfaProcessor = getMfaProcessor(user, axios);

    //Login that passes through logins with mfa
    const login = async <T>(userName: string, password: string) : Promise<ExtendedLoginResponse<T> | IMfaFlowContinuiation> => {

        //User-login with mfa response
        const response = await user.login(userName, password);

        const { mfa } = response as { mfa?: boolean }

        //Get the mfa upgrade message from the server
        if (mfa === true){

            // Process the two factor auth message and add it to the response
            const result = await mfaProcessor.processMfa(response.result as string, response.finalize);

            return {
                ...result
            };
        }

        //If no mfa upgrade message is returned, the login is complete
        return response as ExtendedLoginResponse<T>;
    }

    //Register all the handlers
    forEach(handlers, mfaProcessor.registerHandler);

    return { login }
}

