// Copyright (c) 2024 Vaughn Nugent
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

import { get } from "@vueuse/core";
import { type MaybeRef } from "vue";
import { useAxiosInternal } from "../axios";
import type { WebMessage } from "../types";
import type { AxiosRequestConfig } from "axios";
import type { 
    IMfaFlowContinuiation, 
    IMfaMessage, 
    IMfaTypeProcessor, 
    MfaSumissionHandler 
} from "./login";
import { startRegistration } from "@simplewebauthn/browser";
import type { RegistrationResponseJSON, PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/types";

export type IFidoServerOptions = PublicKeyCredentialCreationOptionsJSON

export interface IFidoRequestOptions{
    readonly password: string;
}

export interface IFidoDevice{
    readonly id: string;
    readonly name: string;
    readonly registered_at: number;
}


interface FidoRegistration{
    readonly id: string;
    readonly publicKey?: string;
    readonly publicKeyAlgorithm: number;
    readonly clientDataJSON: string;
    readonly authenticatorData?: string;
    readonly attestationObject?: string;
}

export interface IFidoApi {
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
    registerCredential: (credential: RegistrationResponseJSON, commonName: string) => Promise<WebMessage>;
    
    /**
     * Registers the default device for the currently logged-in user
     * @returns A promise that resolves to a web message status of the operation
     */
    registerDefaultDevice: (commonName: string, options?: Partial<IFidoRequestOptions>) => Promise<WebMessage>;

    /**
     * Lists all devices for the currently logged-in user
     * @returns A promise that resolves to a list of devices
     */
    listDevices: () => Promise<IFidoDevice[]>;

    /**
     * Disables a device for the currently logged-in user.
     * May require a password to be passed in the options
     * @param device The device descriptor to disable
     * @param options The options to pass to the server
     * @returns A promise that resolves to a web message status of the operation
     */
    disableDevice: (device: IFidoDevice, options?: Partial<IFidoRequestOptions>) => Promise<WebMessage>;

    /**
     * Disables all devices for the currently logged-in user.
     * May require a password to be passed in the options
     * @param options The options to pass to the server
     * @returns A promise that resolves to a web message status of the operation
     */
    disableAllDevices: (options?: Partial<IFidoRequestOptions>) => Promise<WebMessage>;
}

/**
 * Creates a fido api for configuration and management of fido client devices
 * @param endpoint The fido server endpoint
 * @param axiosConfig The optional axios configuration to use
 * @returns An object containing the fido api
 */
export const useFidoApi = (endpoint: MaybeRef<string>, axiosConfig?: MaybeRef<AxiosRequestConfig | undefined | null>)
    : IFidoApi =>{
    const ep = () => get(endpoint);
    
    const axios = useAxiosInternal(axiosConfig)

    const beginRegistration = async (options?: Partial<IFidoRequestOptions>) : Promise<IFidoServerOptions> => {
        const { data } = await axios.value.put<WebMessage<IFidoServerOptions>>(ep(), options);
        return data.getResultOrThrow();
    }

    const registerCredential = async (registration: RegistrationResponseJSON, commonName: string): Promise<WebMessage> => {

        const response: FidoRegistration = {
            id: registration.id,
            publicKey: registration.response.publicKey,
            publicKeyAlgorithm: registration.response.publicKeyAlgorithm!,
            clientDataJSON: registration.response.clientDataJSON,
            authenticatorData: registration.response.authenticatorData,
            attestationObject: registration.response.attestationObject
        }

        const { data } = await axios.value.post<WebMessage>(ep(), { response, commonName });
        return data;
    }

    const registerDefaultDevice = async (commonName: string, options?: Partial<IFidoRequestOptions>): Promise<WebMessage> => {
        //begin registration
        const serverOptions = await beginRegistration(options);

        const reg = await startRegistration(serverOptions);
    
        return await registerCredential(reg, commonName);
    }

    const listDevices = async (): Promise<IFidoDevice[]> => {
        const { data } = await axios.value.get<WebMessage<IFidoDevice[]>>(ep());
        return data.getResultOrThrow();
    }

    const disableDevice = async (device: IFidoDevice, options?: Partial<IFidoRequestOptions>): Promise<WebMessage> => {
        const { data } = await axios.value.post<WebMessage>(ep(), { delete: device, ...options });
        return data;
    }

    const disableAllDevices = async (options?: Partial<IFidoRequestOptions>): Promise<WebMessage> => {
        const { data } = await axios.value.post<WebMessage>(ep(), options);
        return data;
    }

    return {
        beginRegistration,
        registerCredential,
        registerDefaultDevice,
        listDevices,
        disableDevice,
        disableAllDevices
    }
}

/**
 * Enables fido as a supported multi-factor authentication method
 * @returns A mfa login processor for fido multi-factor
 */
export const fidoMfaProcessor = () : IMfaTypeProcessor => {
    
    const processMfa = (payload: IMfaMessage, onSubmit: MfaSumissionHandler) : Promise<IMfaFlowContinuiation> => {

        return Promise.resolve({
            ...payload,
            submit: onSubmit.submit,
        })
    }

    return{
        type: "fido",
        processMfa
    }
}