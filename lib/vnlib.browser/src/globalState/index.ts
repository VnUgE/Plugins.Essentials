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

import { merge } from "lodash-es";
import { type StorageLikeAsync } from "@vueuse/core";
import type { SessionConfig } from "../session";
import type { AccountRpcApiConfig } from "../account/types";
import type { AxiosInstance, AxiosRequestConfig } from "axios";
import { manualComputed, ReadonlyManualRef } from "../storage";

export interface GlobalSessionConfig extends SessionConfig  {
}

export interface GlobalAxiosConfig extends AxiosRequestConfig {
    tokenHeader: string;
    configureAxios?: (axios: AxiosInstance) => AxiosInstance;
}

export interface GlobalApiConfig {
    readonly session: GlobalSessionConfig;
    readonly axios: GlobalAxiosConfig;
    readonly account: AccountRpcApiConfig;
    readonly storage: StorageLikeAsync;
}

export interface GlobalConfigUpdate {
    readonly session?: Partial<GlobalSessionConfig>;
    readonly axios?: Partial<GlobalAxiosConfig>;
    readonly account?: Partial<AccountRpcApiConfig>;
    readonly storage?: StorageLikeAsync;
} 

export type StorageKey = '_vn-session' | '_vn-keys';

/**
 * Gets the default/fallback axios configuration
 * @returns The default axios configuration
 */
const getDefaultAxiosConfig = (): GlobalAxiosConfig => {
    return {
        timeout: 60 * 1000,
        withCredentials: false,
        tokenHeader: 'X-Web-Token'
    }
}

/**
 * Gets the default/fallback session configuration
 * @returns The default session configuration
 */
const getDefaultSessionConfig = (): GlobalSessionConfig & SessionConfig => {
    return {
        browserIdSize: 32,
        signatureAlgorithm: 'HS256',

        cookiesEnabled: navigator?.cookieEnabled === true,
        loginCookieName: 'li',

        keyAlgorithm: {
            name: 'RSA-OAEP',
            modulusLength: 4096,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' },
        } as RsaHashedKeyAlgorithm,
    } 
}

/**
 * Get the default/fallback user configuration
 * @returns The default user configuration
 */
const getDefaultUserConfig = (): AccountRpcApiConfig => {
    return {
        endpointUrl: '/account'
    }
};

const _globalState: GlobalApiConfig = {
    axios: getDefaultAxiosConfig(),
    session: getDefaultSessionConfig(),
    account: getDefaultUserConfig(),
    storage: localStorage
};

export const getGlobalStateInternal = (): ReadonlyManualRef<GlobalApiConfig> => {
    return manualComputed(() =>_globalState);
}

/**
 * Sets the global api configuration
 * @param config The new configuration
 */
export const setApiConfigInternal = (config: GlobalConfigUpdate): void => {

    //merge with current configuration
    const newConfig = {
        axios: merge(_globalState.axios, config.axios),
        session: merge(_globalState.session, config.session),
        user: merge(_globalState.account, config.account),
        storage: config.storage
    }

    //Update the global state
    merge(_globalState, newConfig)
}