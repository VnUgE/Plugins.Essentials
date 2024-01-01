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
import { ref, type ToRefs, type Ref } from "vue";
import { toRefs, type StorageLike, set } from "@vueuse/core";
import { toReactive, createStorageRef } from "./storage";
import type { SessionConfig } from "../session";
import type { UserConfig } from "../user";
import type { AxiosRequestConfig } from "axios";

export interface GlobalSessionConfig extends SessionConfig  {
    readonly cookiesEnabled: boolean;
    readonly loginCookieName: string;
}

export interface GlobalAxiosConfig extends AxiosRequestConfig {
    tokenHeader: string;
}

export interface GlobalApiConfig {
    readonly session: GlobalSessionConfig;
    readonly axios: GlobalAxiosConfig;
    readonly user: UserConfig;
    readonly storage: StorageLike;
}

export interface GlobalConfigUpdate {
    readonly session?: Partial<GlobalSessionConfig>;
    readonly axios?: Partial<GlobalAxiosConfig>;
    readonly user?: Partial<UserConfig>;
    readonly storage?: StorageLike;
} 

export enum StorageKey {
    Session = '_vn-session',
    Keys = "_vn-keys",
    User = '_vn-user'
}


/**
 * Gets the default/fallback axios configuration
 * @returns The default axios configuration
 */
const getDefaultAxiosConfig = (): GlobalAxiosConfig => {
    return {
        baseURL: '/',
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
const getDefaultUserConfig = (): UserConfig => {
    return {
        accountBasePath: '/account',
    }
};

const _globalState = ref<GlobalApiConfig>({
    axios: getDefaultAxiosConfig(),
    session: getDefaultSessionConfig(),
    user: getDefaultUserConfig(),
    storage: localStorage
});

//Get refs to the state
const _refs = toRefs(_globalState);

//Store reactive storage
const rStorage = toReactive(_refs.storage);

export const getGlobalStateInternal = (): Readonly<ToRefs<GlobalApiConfig>> => _refs

/**
 * Gets a reactive storage slot that will work from the 
 * global configuration storage
 */
export const createStorageSlot = <T>(key: StorageKey, defaultValue: T): Ref<T> => createStorageRef(rStorage, key, defaultValue);

/**
 * Sets the global api configuration
 * @param config The new configuration
 */
export const setApiConfigInternal = (config: GlobalConfigUpdate): void => {

    //merge with defaults
    const newConfig = {
        axios: merge(getDefaultAxiosConfig(), config.axios),
        session: merge(getDefaultSessionConfig(), config.session),
        user: merge(getDefaultUserConfig(), config.user),
        storage: config.storage
    }

    //Update the global state
    set(_globalState, newConfig)
}