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

import { find, first, isArray, isEqual, map } from "lodash-es";
import { Mutable, get } from "@vueuse/core";
import Cookies from "universal-cookie";
import { useUser } from "../user";
import { useAxios } from "../axios";
import { useSession, type ITokenResponse } from "../session";
import { type WebMessage } from "../types";
import { type AxiosRequestConfig } from "axios";

export type SocialServerSetQuery = 'invalid' | 'expired' | 'authorized';

/**
 * A continuation function that is called after a successful logout
 */
export type SocialLogoutContinuation = () => Promise<void>



export interface SocialLoginApi<T>{
    /**
     * The collection of registred authentication methods
     */
    readonly methods: T[]
    /**
     * Begins an OAuth2 social web authentication flow against the server
     * handling encryption and redirection of the browser
     * @param method The desired method to use for login
     */
    beginLoginFlow(method: T): Promise<void>;
    /**
     * Completes a login flow if authorized, otherwise throws an error
     * with the message from the server
     * @returns A promise that resolves when the login is complete 
     */
    completeLogin(): Promise<void>;
    /**
     * Logs out of the current session
     * @returns A promise that resolves to true if the logout could be handled by 
     * the current method, otherwise false
     */
    logout(): Promise<boolean>;
    /**
     * Gets the active method for the current session if the 
     * user is logged in using a social login method that is defined
     * in the methods collection
     */
    getActiveMethod(): T | undefined;
}

/**
 * A social OAuth portal that defines a usable server 
 * enabled authentication method
 */
export interface SocialOAuthPortal {
    readonly id: string;
    readonly login: string;
    readonly logout?: string;
    readonly icon?: string;
}

/**
 * An social OAuth2 authentication method that can be used to
 * authenticate against a server for external connections 
 */
export interface OAuthMethod {
    /**
     * The unique id of the method
     */
    readonly id: string;
    /**
     * Optional bas64encoded icon image url for the method
     */
    readonly icon?: string;
    /**
     * Determines if the current flow is active for this method
     */
    isActiveLogin(): boolean
    /**
     * Begins the login flow for this method
     */
    beginLoginFlow(): Promise<void>
    /**
     * Completes the login flow for this method
     */
    completeLogin(): Promise<void>
    /**
     * Logs out of the current session
     */
    logout(): Promise<SocialLogoutContinuation | void>
}

export interface SocialOauthMethod {
    /**
     * Gets the url to the login endpoint for this method
     */
    readonly id: string
    /**
     * Optional bas64encoded icon image url for the method
     */
    readonly icon?: string
    /**
     * The endpoint to submit the authentication request to
     */
    loginUrl(): string
    /**
     * Called when the login to this method was successful
     */
    onSuccessfulLogin?: () => void
    /**
     * Called when the logout to this method was successful
     */
    onSuccessfulLogout?: (responseData: unknown) => SocialLogoutContinuation | void
    /**
    * Gets the data to send to the logout endpoint, if this method
    * is undefined, then the logout will be handled by the normal user logout
    */
    getLogoutData?: () => { readonly url: string; readonly args: unknown }
}


interface SocialLogoutResult{
    readonly url: string | undefined;
}

/**
 * Creates a new social login api for the given methods
 */
export const useOauthLogin = <T extends OAuthMethod>(methods: T[]): SocialLoginApi<T> => {

    const cookieName = 'active-social-login';

    const { loggedIn } = useSession();

    //A cookie will hold the status of the current login method
    const c = new Cookies(null, { sameSite: 'strict', httpOnly: false });

    const getActiveMethod = (): T | undefined => {
        const methodName = c.get(cookieName)
        return find(methods, method => isEqual(method.id, methodName))
    }

    const beginLoginFlow =  (method: T): Promise<void> => {
        return method.beginLoginFlow()
    }

    const completeLogin = async () => {

        const method = find(methods, method => method.isActiveLogin());

        if (!method) {
            throw new Error('The current url is not a valid social login url');
        }

        await method.completeLogin();

        //Set the cookie to the method id
        c.set(cookieName, method.id);
    }

    const logout = async (): Promise<boolean> => {
        if (!get(loggedIn)) {
            return false;
        }

        //see if any methods are active, then call logout on the active method
        const method = getActiveMethod();

        if(!method){
           return false;
        }

        const result = await method.logout();

        //clear cookie on success
        c.remove(cookieName);

        if (result) {
            await result();
        }

        return true;
    }

    return {
        beginLoginFlow,
        completeLogin,
        getActiveMethod,
        logout,
        methods
    }
}

/**
 * Creates a new oauth2 login api for the given methods
 */
export const fromSocialConnections = <T extends SocialOauthMethod>(methods: T[], axiosConfig?: Partial<AxiosRequestConfig>): OAuthMethod[] =>{

    const { KeyStore } = useSession();
    const { prepareLogin, logout:userLogout } = useUser();
    const axios = useAxios(axiosConfig);

    const getNonceQuery = () => new URLSearchParams(window.location.search).get('nonce');
    const getResultQuery = () => new URLSearchParams(window.location.search).get('result');

    const checkForValidResult = () => {
        //Get auth result from query params
        const result = getResultQuery();
        switch (result) {
            case 'invalid':
                throw new Error('The request was invalid, and you could not be logged in. Please try again.');
            case 'expired':
                throw new Error('The request has expired. Please try again.');

            //Continue with login
            case 'authorized':
                break;

            default:
                throw new Error('There was an error processing the login request. Please try again.')
        }
    }

    return map(methods, method => {
        return{
            id: method.id,
            icon: method.icon,

            async beginLoginFlow() {
                //Prepare the login claim`
                const claim = await prepareLogin()
                const { data } = await axios.put<WebMessage<string>>(method.loginUrl(), claim)
                const encDat = data.getResultOrThrow()
                // Decrypt the result which should be a redirect url
                const result = await KeyStore.decryptDataAsync(encDat)
                // get utf8 text
                const text = new TextDecoder('utf-8').decode(result)
                // Recover url
                const redirect = new URL(text)
                // Force https
                redirect.protocol = 'https:'
                // redirect to the url
                window.location.href = redirect.href
            },
            async completeLogin() {
                checkForValidResult();

                //Recover the nonce from query params
                const nonce = getNonceQuery();
                if (!nonce) {
                    throw new Error('The current session has not been initialized for social login');
                }

                //Prepare the session for a new login
                const login = await prepareLogin();

                //Send a post request to the endpoint to complete the login and pass the nonce argument
                const { data } = await axios.post<ITokenResponse>(method.loginUrl(), { ...login, nonce })

                //Verify result
                data.getResultOrThrow()

                //Complete login authorization
                await login.finalize(data);
            },
            isActiveLogin() {
                const loginUrl = method.loginUrl();
                //Check for absolute url, then check if the path is the same
                if (loginUrl.startsWith('http')) {
                    const asUrl = new URL(loginUrl);
                    return isEqual(asUrl.pathname, window.location.pathname);
                }
                //Relative url
                return isEqual(loginUrl, window.location.pathname);
            },
            async logout() {
                /**
                 * If no logout data method is defined, then the logout 
                 * is handled by a normal account logout
                 */
                if (!method.getLogoutData) {
                    //Normal user logout
                    const result = await userLogout();

                    if (method.onSuccessfulLogout) {
                        method.onSuccessfulLogout(result);
                    }

                    return;
                }

                const { url, args } = method.getLogoutData();

                //Exec logout post request against the url
                const { data } = await axios.post(url, args);

                //Signal the method that the logout was successful
                return method.onSuccessfulLogout ? method.onSuccessfulLogout(data) : undefined; 
            },
        } as OAuthMethod
    });
}

/**
 * Adds a default logout function to the social login api that will
 * call the user supplied logout function if the social logout does not
 * have a registered logout method
 */
export const useSocialDefaultLogout = <T>(socialOauth: SocialLoginApi<T>, logout: () => Promise<unknown>): SocialLoginApi<T> => {
    //Store old logout function for later use
    const logoutFunc = socialOauth.logout;

    (socialOauth as Mutable<SocialLoginApi<T>>).logout = async (): Promise<boolean> => {
        //If no logout was handled by social, fall back to user supplied logout
        if (await logoutFunc() === false) {
            await logout()
        }
        return true;
    }

    return socialOauth;
}

export const fromSocialPortals = (portals: SocialOAuthPortal[]): SocialOauthMethod[] => {
    return map(portals, p => {
        return {
            id: p.id,
            icon: p.icon,
            loginUrl : () => p.login,
            //Get the logout data from the server
            getLogoutData: () => ({ url: p.logout!, args: {}}),
            //Redirect to the logout url returned by the server
            onSuccessfulLogout: (data: SocialLogoutResult) => {
                if (data.url) {
                    return () => {
                        window.location.assign(data.url!);
                        return Promise.resolve();
                    }
                }
            },
            onSuccessfulLogin: () => {}
        } as SocialOauthMethod
    })
}

export const fetchSocialPortals = async (portalEndpoint: string, axiosConfig?: Partial<AxiosRequestConfig>): Promise<SocialOAuthPortal[]> => {
    //Get axios instance
    const axios = useAxios(axiosConfig)

    //Get all enabled portals
    const { data } = await axios.get<SocialOAuthPortal[]>(portalEndpoint);

    /**
     * See if the response was a json array.
     * 
     * Sometimes axios will parse HTML as json and still
     * return an object array, so if its an array, then
     * verify that at least one element is a valid portal
     */
    if (isArray(data)) {
        if(data.length === 0){
            return [];
        }
       
        return first(data)?.id ? data : [];
    }

    throw new Error('The response from the server was not a valid json array');
}