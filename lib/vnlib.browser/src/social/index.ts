import { find, isEqual } from "lodash-es";
import { get } from "@vueuse/core";
import { MaybeRef } from "vue";
import Cookies from "universal-cookie";
import { useUser } from "../user";
import { useAxios } from "../axios";
import { useSession, type ITokenResponse } from "../session";
import { type WebMessage } from "../types";
import { type AxiosRequestConfig } from "axios";

export type SocialServerSetQuery = 'invalid' | 'expired' | 'authorized';

export interface OAuthMethod{
    /**
     * Gets the url to the login endpoint for this method
     */
    readonly Id: string
    /**
     * The endpoint to submit the authentication request to
     */
    loginUrl(): string
    /**
     * Called when the login to this method was successful
     */
    onSuccessfulLogin?:() => void
    /**
     * Called when the logout to this method was successful
     */
    onSuccessfulLogout?:(responseData: unknown) => void
    /**
    * Gets the data to send to the logout endpoint, if this method
    * is undefined, then the logout will be handled by the normal user logout
    */
    getLogoutData?: () => { readonly url: string; readonly args: unknown }
}

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
 * Creates a new social login api for the given methods
 */
export const useSocialOauthLogin = <T extends OAuthMethod>(methods: T[], axiosConfig?: Partial<AxiosRequestConfig>): SocialLoginApi<T> =>{

    const cookieName = 'active-social-login';

    const { loggedIn, KeyStore } = useSession();
    const { prepareLogin, logout:userLogout } = useUser();
    const axios = useAxios(axiosConfig);

    //A cookie will hold the status of the current login method
    const c = new Cookies(null, { path: '/', sameSite: 'strict', httpOnly:false });

    const getNonceQuery = () => new URLSearchParams(window.location.search).get('nonce');
    const getResultQuery = () => new URLSearchParams(window.location.search).get('result');
    const selectMethodForCurrentUrl = () => find(methods, method => {
        const loginUrl = method.loginUrl();
        //Check for absolute url, then check if the path is the same
        if(loginUrl.startsWith('http')){
            const asUrl = new URL(loginUrl);
            return isEqual(asUrl.pathname, window.location.pathname);
        }
        //Relative url
        return isEqual(loginUrl, window.location.pathname);
    })

    const getActiveMethod = (): T | undefined => {
       const methodName = c.get(cookieName)
       return find(methods, method => isEqual(method.Id, methodName))
    }

    const beginLoginFlow = async (method: T): Promise<void> => {
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
    }

    const completeLogin = async () => {

        //Get auth result from query params
        const result = getResultQuery();
        switch(result){
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

        const method = selectMethodForCurrentUrl();

        if(!method){
            throw new Error('The current url is not a valid social login url');
        }

        //Recover the nonce from query params
        const nonce = getNonceQuery();
        if(!nonce){
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

        //Signal the method that the login was successful
        if(method.onSuccessfulLogin){
            method.onSuccessfulLogin();
        }

        //Set the cookie to the method id
        c.set(cookieName, method.Id);
    }

    const logout = async (): Promise<boolean> => {
        if(!get(loggedIn)){
            return false;
        }

        //see if any methods are active
        const method = getActiveMethod();

        if(!method){
            return false;
        }

        /**
         * If no logout data method is defined, then the logout 
         * is handled by a normal account logout
         */
        if(!method.getLogoutData){
            //Normal user logout
            const result = await userLogout();

            if(method.onSuccessfulLogout){
                method.onSuccessfulLogout(result);
            }
            
            return true;
        }

        const { url, args } = method.getLogoutData();

        //Exec logout post request against the url
        const { data } = await axios.post(url, args);

        //clear cookie on success
        c.remove(cookieName);

        //Signal the method that the logout was successful
        if (method.onSuccessfulLogout) {
            method.onSuccessfulLogout(data);
        }

        return true;
    }

    return{
        beginLoginFlow,
        completeLogin,
        getActiveMethod,
        logout,
        methods
    }
}

/**
 * Creates a new simple social OAuth method used for login
 * @example
 * const google = createSocialMethod('google', 'https://accounts.google.com/o/oauth2/v2/auth')
 * const facebook = createSocialMethod('facebook', 'https://www.facebook.com/v2.10/dialog/oauth')
 */
export const createSocialMethod = (id: string, path: MaybeRef<string>): OAuthMethod => {
    return{
        Id: id,
        loginUrl: () => get(path),
    }
}