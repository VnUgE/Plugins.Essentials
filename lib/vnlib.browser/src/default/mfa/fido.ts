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
    MfaFlow, 
    MfaMessage, 
    MfaTypeProcessor, 
    MfaUpgradeState
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
import { type MfaApi, type MfaGetResponse, mfaGetDataFor } from "./config";
import type { AccountRpcResponse } from "../account/types";
import { defaultTo } from "lodash-es";

export type FidoServerOptions = PublicKeyCredentialCreationOptionsJSON

/**
 * Options for FIDO operations requiring password verification.
 */
export interface FidoRequestOptions extends Record<string, any>{
    /** User's current password for sensitive operations */
    readonly password: string;
}

/**
 * Represents a registered FIDO device for the current user.
 */
export interface FidoDevice{
    /** Friendly name for the device */
    readonly n: string;
    /** Unique device identifier */
    readonly id: string;
    /** COSE algorithm identifier */
    readonly alg: number;
}

/*
 * Must match the fido RPC response object
 */
export interface FidoRpcGetData{
    /**
     * The list of FIDO devices registered for the user
     */
    readonly devices: FidoDevice[]; 
    /**
     * Whether the user can add new devices
     */
    readonly can_add_devices: boolean;
    /**
     * The total size of all FIDO device data stored 
     * on the server for the user
     */
    readonly data_size: number;
    /**
     * The maximum size of FIDO device data that can be 
     * stored on the server for the user
     */
    readonly max_size: number;
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

/**
 * API for managing FIDO2/WebAuthn hardware security keys and biometric authentication.
 */
export interface FidoApi {
    /**
     * Checks if the current browser supports the FIDO authentication API.
     * @returns True if WebAuthn is supported in the current browser
     */
    isSupported(): boolean;

    /**
     * Gets FIDO credential options from the server for a currently logged-in user.
     * @param options - Optional password and request configuration
     * @returns Promise resolving to server options for the FIDO API
     */
    beginRegistration: (options?: Partial<FidoRequestOptions>) => Promise<PublicKeyCredentialCreationOptionsJSON>;

    /**
     * Creates a new credential for the currently logged-in user.
     * @param credential - The credential registration response from the authenticator
     * @param commonName - Friendly name for this device
     * @returns Promise resolving to operation status
     */
    registerCredential: (credential: RegistrationResponseJSON, commonName: string) => Promise<AccountRpcResponse<string>>;
    
    /**
     * Registers the default device for the currently logged-in user.
     * @param commonName - Friendly name for this device
     * @param options - Optional password for verification
     * @returns Promise resolving to operation status
     */
    registerDefaultDevice: (commonName: string, options?: Partial<FidoRequestOptions>) => Promise<AccountRpcResponse<string>>;

    /**
     * Disables a device for the currently logged-in user.
     * May require a password to be passed in the options.
     * @param device - The device descriptor to disable
     * @param options - Optional password for verification
     * @returns Promise resolving to operation status
     */
    disableDevice: (device: FidoDevice, options?: Partial<FidoRequestOptions>) => Promise<AccountRpcResponse<string>>;

    /**
     * Disables all devices for the currently logged-in user.
     * May require a password to be passed in the options.
     * @param options - Optional password for verification
     * @returns Promise resolving to operation status
     */
    disableAllDevices: (options?: Partial<FidoRequestOptions>) => Promise<AccountRpcResponse<string>>;
}

/**
 * Overloaded function signature for creating FIDO API with optional request sender.
 */
export interface UseFidoApi {
    /**
     * Creates a minimal FIDO API for checking browser support.
     * @returns FIDO API with only isSupported method
     */
    (): Pick<FidoApi, 'isSupported'>;
    /**
     * Creates a full FIDO API with server communication capabilities.
     * @param options - MFA request sender for server operations
     * @returns Complete FIDO API instance
     */
    (options: Pick<MfaApi, 'sendRequest'>): FidoApi;
}

/**
 * Creates a FIDO API for configuration and management of FIDO client devices.
 * @param options - Optional MFA request sender from useMfaApi
 * @returns FIDO API instance with device management methods
 */
export const useFidoApi: UseFidoApi = (options?: Pick<MfaApi, 'sendRequest'>): FidoApi =>{

    const sendRequest = options?.sendRequest ?? (() => { throw new Error('No sendRequest function provided') });

    const beginRegistration = async (options?: Partial<FidoRequestOptions>) : Promise<FidoServerOptions> => {
        const data = await sendRequest<FidoServerOptions>({ 
             ...options,
            type: 'fido',
            action: 'prepare_device'
        });
        return data.getResultOrThrow();
    }

    const registerCredential = (reg: RegistrationResponseJSON, commonName: string, options?: Partial<FidoRequestOptions>): Promise<AccountRpcResponse<string>> => {

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

    const registerDefaultDevice = async (commonName: string, options?: Partial<FidoRequestOptions>): Promise<AccountRpcResponse<string>> => {
        //begin registration
        const serverOptions = await beginRegistration(options);

        const reg = await startRegistration({ optionsJSON: serverOptions });
    
        return await registerCredential(reg, commonName, options);
    }

    const disableDevice = async (device: FidoDevice, options?: Partial<FidoRequestOptions>): Promise<AccountRpcResponse<string>> => {
        return sendRequest<string>({
            ...options,
            type: 'fido',
            action: 'disable_device',
            device_id: device.id
        })
    }

    const disableAllDevices = async (options?: Partial<FidoRequestOptions>): Promise<AccountRpcResponse<string>> => {
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

interface IFidoMfaFlow extends MfaFlow<'fido'> {
    fido: PublicKeyCredentialRequestOptionsJSON;
}

/**
 * Enables FIDO as a supported multi-factor authentication method.
 * @returns MFA login processor for FIDO multi-factor authentication
 */
export const fidoMfaProcessor = (): MfaTypeProcessor => {

    const getContinuation = (payload: MfaMessage, state: MfaUpgradeState) : Promise<IFidoMfaFlow> => {

        if(!('fido' in payload)){
            throw new Error('Fido mfa flow is not supported by the server. This is an internal error.');
        }

        const { fido } = (payload as any) as { fido: PublicKeyCredentialRequestOptionsJSON };

        return Promise.resolve({
            ...payload,
            fido,
            type: 'fido',
            submit: state.submit,
        })
    }

    return{
        type: "fido",
        getContinuation,
        isSupported: browserSupportsWebAuthn
    }
}

/**
 * Options for authenticating with FIDO during MFA login flow.
 */
export interface FidoAuthenticateOptions {
    /**
     * Whether to use browser autofill for FIDO authentication.
     * @defaultValue false
     */
    useAutoFill?: boolean;
    /**
     * Optional password and request configuration.
     */
    options?: Partial<FidoRequestOptions>;
}

/**
 * Authenticates a user using FIDO multi-factor authentication from a pending MFA flow.
 * @param flow - The MFA flow to authenticate with
 * @param options - Optional autofill and request configuration
 * @returns Promise resolving to authentication result
 */
export const fidoMfaAuthenticate = async <T>(flow: MfaFlow<'fido'>, options?: FidoAuthenticateOptions): Promise<WebMessage<T>> => {

     const fidoResult = await startAuthentication({ 
        optionsJSON: (flow as IFidoMfaFlow).fido, 
        useBrowserAutofill: defaultTo(options?.useAutoFill, false)
    })

    const result = await flow.submit<T>({ fido: fidoResult, ...options });
    result.getResultOrThrow();

    return result;
}

/**
 * Gets the FIDO mfa data for the user
 * @param mfaData The mfa data object returned from the server
 * @returns The FIDO mfa data for the user, or undefined if not found
 */
export const fidoGetMfaData = (mfaData : MfaGetResponse): FidoRpcGetData | undefined => {
    return mfaGetDataFor<FidoRpcGetData>(mfaData, 'fido');
}