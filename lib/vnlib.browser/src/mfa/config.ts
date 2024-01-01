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

import { get } from "@vueuse/core";
import { type MaybeRef } from "vue";
import { useAxiosInternal } from "../axios"
import type { MfaMethod } from "./login"
import type { WebMessage } from '../types'

export type UserArg = object;

/**
 * Represents the server api for interacting with the user's 
 * mfa configuration
 */
export interface MfaApi{
    /**
     * disables the given mfa method
     * @param type The mfa method to disable
     * @param password The user's password
     */
    disableMethod(type : MfaMethod, password: string) : Promise<WebMessage>;
    
    /**
     * Initializes or updates the given mfa method configuration
     * @param type The mfa method to initialize or update
     * @param password The user's password
     * @param userConfig Optional extended configuration for the mfa method. Gets passed to the server
     */
    initOrUpdateMethod<T>(type: MfaMethod, password: string, userConfig?: UserArg) : Promise<WebMessage<T>>;

    /**
     * Refreshes the enabled mfa methods
     */
    getMethods(): Promise<MfaMethod[]>;
}

/**
 * Gets the api for interacting with the the user's mfa configuration
 * @param mfaEndpoint The server mfa endpoint relative to the base url
 * @returns An object containing the mfa api
 */
export const useMfaConfig = (mfaEndpoint: MaybeRef<string>): MfaApi =>{

    const axios = useAxiosInternal(null)

    const getMethods = async () => {
        //Get the mfa methods
        const { data } = await axios.value.get<MfaMethod[]>(get(mfaEndpoint));
        return data
    }

    const disableMethod = async (type: MfaMethod, password: string) : Promise<WebMessage> => {
        const { post } = get(axios);
        //Disable the mfa using the post method
        const { data } = await post<WebMessage>(get(mfaEndpoint), { type, password });
        return data;
    }

    const initOrUpdateMethod = async <T>(type: MfaMethod, password: string, userConfig?: UserArg) : Promise<WebMessage<T>> => {
        const { put } = get(axios);
        //enable or update the mfa using the put method
        const { data } = await put<WebMessage<T>>(get(mfaEndpoint), { type, password, ...userConfig });
        return data;
    }

    return {
        disableMethod,
        initOrUpdateMethod,
        getMethods
    }
}

