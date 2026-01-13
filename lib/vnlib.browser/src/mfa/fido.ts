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

import type { 
    IMfaFlow, 
    IMfaMessage, 
    IMfaTypeProcessor, 
    MfaSumissionHandler,
    IMfaSubmission
} from "./login";
import { 
    startRegistration, 
    startAuthentication, 
    browserSupportsWebAuthn,
    type RegistrationResponseJSON, 
    type PublicKeyCredentialCreationOptionsJSON, 
    type PublicKeyCredentialRequestOptionsJSON
} from "@simplewebauthn/browser";
import type { WebMessage } from "../types";
import { type MfaApi } from "./config";
import type { AccountRpcResponse } from "../account/types";

export type IFidoServerOptions = PublicKeyCredentialCreationOptionsJSON

export interface IFidoMfaFlow extends IMfaFlow {
    readonly authenticate: <T>(useAutoFill: boolean, options?: Partial<IFidoRequestOptions>) => Promise<WebMessage<T>>;
}

export interface IFidoRequestOptions extends Record<string, any>{
    readonly password: string;
}

export interface IFidoDevice{
    readonly n: string;
    readonly id: string;
    readonly alg: number;
}

interface FidoRegistration{
    readonly id: string;
    readonly friendlyName: string;
    readonly publicKey?: string;
    readonly publicKeyAlgorithm: number;
    readonly clientDataJSON: string;
    readonly authenticatorData?: string;
    readonly attestationObject?: string;
}

export interface IFidoApi {   
     /*
    * Checks if the current browser supports the FIDO authentication API
    */
    isSupported(): boolean;
    /**
     * Gets fido credential options from the server for a currently logged-in user
     * @returns A promise that resolves to the server options for the FIDO API
     */
    beginRegistration: (options?: Partial<IFidoRequestOptions>) => Promise<PublicKeyCredentialCreationOptionsJSON>;

    /**
     * Creates a new credential for the currently logged-in user
     * @param credential The credential to create
     * @returns A promise that resolves to a web message
     */
    registerCredential: (credential: RegistrationResponseJSON, commonName: string) => Promise<AccountRpcResponse<string>>;
    
    /**
     * Registers the default device for the currently logged-in user
     * @returns A promise that resolves to a web message status of the operation
     */
    registerDefaultDevice: (commonName: string, options?: Partial<IFidoRequestOptions>) => Promise<AccountRpcResponse<string>>;

    /**
     * Disables a device for the currently logged-in user.
     * May require a password to be passed in the options
     * @param device The device descriptor to disable
     * @param options The options to pass to the server
     * @returns A promise that resolves to a web message status of the operation
     */
    disableDevice: (device: IFidoDevice, options?: Partial<IFidoRequestOptions>) => Promise<AccountRpcResponse<string>>;

    /**
     * Disables all devices for the currently logged-in user.
     * May require a password to be passed in the options
     * @param options The options to pass to the server
     * @returns A promise that resolves to a web message status of the operation
     */
    disableAllDevices: (options?: Partial<IFidoRequestOptions>) => Promise<AccountRpcResponse<string>>;
}

export interface UseFidoApi {
    /**
     * Creates a minimal fido api for checking browser support 
     */
    (): Pick<IFidoApi, 'isSupported'>;
    (options: Pick<MfaApi, 'sendRequest'>): IFidoApi;
}

 /**
 * Creates a fido api for configuration and management of fido client devices
 * @param sendRequest The function to send a request to the server
 * @returns An object containing the fido api
 */
export const useFidoApi: UseFidoApi = (options?: Pick<MfaApi, 'sendRequest'>): IFidoApi =>{

    const sendRequest = options?.sendRequest ?? (() => { throw new Error('No sendRequest function provided') });

    const beginRegistration = async (options?: Partial<IFidoRequestOptions>) : Promise<IFidoServerOptions> => {
        const data = await sendRequest<IFidoServerOptions>({ 
             ...options,
            type: 'fido',
            action: 'prepare_device'
        });
        return data.getResultOrThrow();
    }

    const registerCredential = (reg: RegistrationResponseJSON, commonName: string, options?: Partial<IFidoRequestOptions>): Promise<AccountRpcResponse<string>> => {

        const registration: FidoRegistration = {
            id: reg.id,
            publicKey: reg.response.publicKey,
            publicKeyAlgorithm: reg.response.publicKeyAlgorithm!,
            clientDataJSON: reg.response.clientDataJSON,
            authenticatorData: reg.response.authenticatorData,
            attestationObject: reg.response.attestationObject,
            friendlyName: commonName
        }

        return sendRequest<string>({
            ...options,
            type: 'fido',
            action: 'register_device',
            registration
        })
    }

    const registerDefaultDevice = async (commonName: string, options?: Partial<IFidoRequestOptions>): Promise<AccountRpcResponse<string>> => {
        //begin registration
        const serverOptions = await beginRegistration(options);

        const reg = await startRegistration({ optionsJSON: serverOptions });
    
        return await registerCredential(reg, commonName, options);
    }

    const disableDevice = async (device: IFidoDevice, options?: Partial<IFidoRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'fido',
            action: 'disable_device',
            device_id: device.id
        })
    }

    const disableAllDevices = async (options?: Partial<IFidoRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'fido',
            action: 'disable_all'
        })
    }

    return {
        isSupported: browserSupportsWebAuthn,
        beginRegistration,
        registerCredential,
        registerDefaultDevice,
        disableDevice,
        disableAllDevices
    }
}

/**
 * Enables fido as a supported multi-factor authentication method
 * @returns A mfa login processor for fido multi-factor
 */
export const fidoMfaProcessor = () : IMfaTypeProcessor => {
    
    const getContinuation = (payload: IMfaMessage, onSubmit: MfaSumissionHandler) : Promise<IFidoMfaFlow> => {

        const authenticate = async <T>(useAutoFill: boolean, options?: Partial<IFidoRequestOptions>) : Promise<WebMessage<T>> => {
            
            if(!('fido' in payload)){
                throw new Error('Fido mfa flow is not supported by the server. This is an internal error.');
            }
            
            const { fido } = (payload as any) as { fido: PublicKeyCredentialRequestOptionsJSON }; 

            const result = await startAuthentication({ 
                optionsJSON: fido, 
                useBrowserAutofill: useAutoFill 
            }) as IMfaSubmission

            return await onSubmit.submit({ fido: result, ...options });
        }

        return Promise.resolve({
            ...payload,
            authenticate,
            type: 'fido',
            submit: onSubmit.submit,
        })
    }

    return{
        type: "fido",
        getContinuation,
        isSupported: browserSupportsWebAuthn
    }
}