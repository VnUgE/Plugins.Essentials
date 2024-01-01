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

import { isNil, defaultTo, defaults } from 'lodash-es'
import { computed, watch, type Ref } from "vue"
import { get, set, toRefs } from '@vueuse/core'
import type { Axios, AxiosResponse } from "axios"
import type { ISession, ITokenResponse } from '../session'
import type { WebMessage } from '../types'
import type { User, UserConfig, UserProfile, ExtendedLoginResponse, UserState } from './types'

export enum AccountEndpoint {
    Login = "login",
    Logout = "logout",
    Register = "register",
    Reset = "reset",
    Profile = "profile",
    HeartBeat = "keepalive"
}

export interface IUserInternal extends User {
    getEndpoint: (endpoint: AccountEndpoint) => string;
}

export const createUser = (
    config: Readonly<Ref<UserConfig>>, 
    axios:Readonly<Ref<Axios>>,
    session: ISession, 
    state: Ref<UserState>
): IUserInternal => {


    //always set default value before call to toRefs
    defaults(state.value, { userName: undefined })

    const { accountBasePath } = toRefs(config);
    const { userName } = toRefs(state);

    const getEndpoint = (endpoint: AccountEndpoint) => `${get(accountBasePath)}/${endpoint}`;

    const prepareLogin = async () => {
        //Store a copy of the session data and the current time for the login request
        const finalize = async (response: ITokenResponse): Promise<void> => {
            //Update the session with the new credentials
            await session.updateCredentials(response);

            //Update the user state with the new username
            set(userName, (response as { email? : string }).email);
        }

        //Get or regen the client public key
        const { publicKey, browserId } = await session.getClientSecInfo();

        return {
            clientid: browserId,
            pubkey: publicKey,
            localtime: new Date().toISOString(),
            locallanguage: navigator.language,
            username: '',
            password: '',
            finalize
        }
    }

    //Expose the logged in state behind multiple refs
    const loggedIn = computed(() => session.loggedIn.value);

    //We want to watch the loggin ref and if it changes to false, clear the username
    watch(loggedIn, value => value === false ? set(userName, undefined) : undefined)

    const logout = async (): Promise<WebMessage> => {
        //Get axios with logout endpoint
        const { post } = get(axios);
        const ep = getEndpoint(AccountEndpoint.Logout);

        // Send a post to the account logout endpoint to logout
        const { data } = await post<WebMessage>(ep, {});

        //regen session credentials on successful logout
        await session.KeyStore.regenerateKeysAsync()

        // return the response
        return data
    }

    const login = async <T>(userName: string, password: string): Promise<ExtendedLoginResponse<T>> => {
        //Get axios and the login endpoint
        const { post } = get(axios);
        const ep = getEndpoint(AccountEndpoint.Login);

        const prepped = await prepareLogin();

        //Set the username and password
        prepped.username = userName;
        prepped.password = password;

        //Send the login request
        const { data } = await post<ITokenResponse<T>>(ep, prepped);

        // Check the response
        if(data.success === true) {

            // If the server returned a token, complete the login
            if (!isNil(data.token)) {
                await prepped.finalize(data)
            }
        }

        return {
            ...data,
            finalize: prepped.finalize
        }
    }

    const getProfile = async <T extends UserProfile>(): Promise <T> => {
        //Get axios and the profile endpoint
        const ax = get(axios)
        const ep = getEndpoint(AccountEndpoint.Profile);

        // Get the user's profile from the profile endpoint
        const response = await ax.get<T>(ep);

        //Update the internal username if it was set by the server
        const newUsername = defaultTo(response.data.email, get(userName));

        //Update the user state with the new username from the server
        set(userName, newUsername);

        // return response data
        return response.data
    }

    const resetPassword = async (current: string, newPass: string, args: object): Promise<WebMessage> => {
        //Get axios and the reset password endpoint
        const { post } = get(axios);
        const ep = getEndpoint(AccountEndpoint.Reset);

        // Send a post to the reset password endpoint
        const { data } = await post<WebMessage>(ep, {
            current,
            new_password: newPass,
            ...args
        })

        return data
    }

    const heartbeat = async (): Promise <AxiosResponse> => {
        //Get axios and the heartbeat endpoint
        const { post } = get(axios);
        const ep = getEndpoint(AccountEndpoint.HeartBeat);

        // Send a post to the heartbeat endpoint
        const response = await post<ITokenResponse>(ep);
        
        //If success flag is set, update the credentials
        if(response.data.success){
            //Update credential
            await session.updateCredentials(response.data);
        }
        return response;
    }

    return{
        userName,
        prepareLogin,
        logout,
        login,
        getProfile,
        resetPassword,
        heartbeat,
        getEndpoint,
    }
}
