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

import { defer, isEmpty, isNil } from 'lodash-es';
import { SignJWT } from 'jose'
import { getCryptoOrThrow, decryptAsync, getRandomHex } from "../webcrypto";
import { ArrayBuffToBase64, Base64ToUint8Array } from '../binhelpers'
import { debugLog } from "../util";
import { type AsyncStorageItem, type ReadonlyManualRef } from '../storage'
import type { ISession, ISessionKeyStore, ITokenResponse, ClientCredential, SessionConfig } from './types'
import type Cookies from 'universal-cookie';

export interface IStateStorage {
    token: string | null;
    browserId: string | null;
}
export interface IKeyStorage {
    priv: string | null;
    pub: string | null;
}

interface IInternalKeyStore extends ISessionKeyStore {
    getPublicKey(): Promise<string>;
    clearKeys(): void;
}
const keyStore = (
    storage: AsyncStorageItem<IKeyStorage>, 
    config: ReadonlyManualRef<SessionConfig>
): IInternalKeyStore => {

    const { priv, pub } = storage;

    const getPublicKey = async (): Promise<string> => {

        let pubKey = await pub.get();

        //Check if we have a public key
        if (isNil(pubKey)) {
            //If not, generate a new key pair
            await checkAndSetKeysAsync();
            return await pub.get() || "";
        }
        
        return pubKey;
    }

    const setCredentialAsync = async (keypair: CryptoKeyPair): Promise<void> => {
        const crypto = getCryptoOrThrow();

        // Store the private key
        const newPrivRaw = await crypto.exportKey('pkcs8', keypair.privateKey);
        const newPubRaw = await crypto.exportKey('spki', keypair.publicKey);

        //Store keys as base64 strings
        await Promise.all([
            priv.set(ArrayBuffToBase64(newPrivRaw)),
            pub.set(ArrayBuffToBase64(newPubRaw))
        ]);
    }

    const clearKeys = async (): Promise<void> => {
        await Promise.all([
            priv.set(null), //Set null in parallel 
            pub.set(null)
        ]);
    }

    const checkAndSetKeysAsync = async (): Promise<void> => {
        const pubKey = await pub.get();
        const privKey = await priv.get();
        
        // Check if we have a key pair already
        if (!isNil(pubKey) && !isNil(privKey)) {
            return;
        }

        const crypto = getCryptoOrThrow();

        const { keyAlgorithm } = config.get();

        // If not, generate a new key pair
        const keypair = await crypto.generateKey(keyAlgorithm, true, ['encrypt', 'decrypt']) as CryptoKeyPair;
       
        await setCredentialAsync(keypair);

        debugLog("Generated new client keypair, none were found")
    }

    const regenerateKeysAsync = (): Promise<void> => {
        //Clear keys and generate new ones
        clearKeys();
        return checkAndSetKeysAsync();
    }

    const decryptDataAsync = async (data: string | ArrayBuffer): Promise<ArrayBuffer> => {
        const secKey = await priv.get();
        
        // Convert the private key to a Uint8Array from its base64 string
        const keyData = Base64ToUint8Array(secKey || "")

        const crypto = getCryptoOrThrow();

        const { keyAlgorithm } = config.get();

        //import private key as pkcs8
        const privKey = await crypto.importKey('pkcs8', keyData, keyAlgorithm, false, ['decrypt'])
       
        return await decryptAsync(keyAlgorithm, privKey, data, false) as ArrayBuffer
    }

    const decryptAndHashAsync = async (data: string | ArrayBuffer): Promise<string> => {
        // Decrypt the data
        const decrypted = await decryptDataAsync(data)

        const crypto = getCryptoOrThrow();

        // Hash the decrypted data
        const hashed = await crypto.digest({ name: 'SHA-256' }, decrypted)

        // Convert the hash to a base64 string
        return ArrayBuffToBase64(hashed)
    }

    return {
        getPublicKey,
        clearKeys,
        regenerateKeysAsync,
        decryptDataAsync,
        decryptAndHashAsync
    }
}

export const createSession = (
    config: ReadonlyManualRef<SessionConfig>, 
    keyStorage: AsyncStorageItem<IKeyStorage>,
    state: AsyncStorageItem<IStateStorage>,
    cookies: Cookies
): ISession =>
{
    const otpNonceSize = 16;

    //Create session state and key store
    const { browserId, token } = state;
    const KeyStore = keyStore(keyStorage, config);

    const getBrowserId = async (): Promise<string> => {

        let val = await browserId.get();

        // Check browser id
        if (isNil(val)) {
            const { browserIdSize } = config.get();
            // generate a new random value and store it
            val = getRandomHex(browserIdSize);
            await browserId.set(val);
            debugLog("Generated new browser id, none was found")
        }

        return val;
    }

    const updateCredentials = async (response: ITokenResponse): Promise<void> => {
        /*
        * The server sends an encrypted HMAC key 
        * using our public key. We need to decrypt it 
        * and use it to sign messages to the server.
        */
        const decrypted = await KeyStore.decryptDataAsync(response.token)

        // Convert the hash to a base64 string and store it
        await token.set(ArrayBuffToBase64(decrypted));
    }

    const generateOneTimeToken = async (path: string): Promise<string | null> => {
        const tokenVal = await token.get();

        //we need to get the shared key from storage and decode it, it may be null if not set
        const sharedKey = tokenVal ? Base64ToUint8Array(tokenVal) : null

        if (!sharedKey) {
            return null;
        }

        //Inint jwt with a random nonce
        const nonce = getRandomHex(otpNonceSize);
 
        //Get the user desired signature algorithm
        const { signatureAlgorithm: alg } = config.get();

        const jwt = new SignJWT({ 'nonce': nonce, path })
        //Set alg
        jwt.setProtectedHeader({ alg })
            //Iat is the only required claim at the current time utc
            .setIssuedAt()
            .setAudience(window.location.origin)

        //Sign the jwt
        const signedJWT = await jwt.sign(sharedKey)

        return signedJWT;
    }

    const clearLoginState = (): void => {
        browserId.set(null);
        token.set(null);
        KeyStore.clearKeys();
    }

    const getClientSecInfo = async (): Promise<ClientCredential> => {
        //Generate and get the credential info
        const publicKey = await KeyStore.getPublicKey();
        const browserId = await getBrowserId();
        return { publicKey, browserId };
    }

    const getCookie = () => {
        const { cookiesEnabled, loginCookieName } = config.get();

        const value = cookiesEnabled
            ? cookies.get<string>(loginCookieName || '', { doNotParse: true })
            : undefined;

        return {
            enabled: cookiesEnabled,
            cookieValue: value,
        }
    }

    const isTokenSet = (token: string | null) => {
        return !isEmpty(token);
    }

    const isCookieValueValid = (cookieValue: string | undefined) => {
        return cookieValue === "1" || cookieValue === "2";
    }

    const isLoggedIn = async (): Promise<boolean> => {
        const tokenVal = await state.token.get();
        const { enabled, cookieValue } = getCookie();

        return isTokenSet(tokenVal) && (enabled ? isCookieValueValid(cookieValue) : true);
    }

    const isLocalAccount = async () => {
        const { cookieValue } = getCookie();
        return cookieValue === "1";
    }

    const reconcileState = (): void => {

        defer(async () => {
            /**
             * If
             *  - cookies are enabled,
             *  - there is no cookie value
             * 
             * Then the token can be cleared so ui is reset and ready for the 
             * next login
             */

            const { enabled, cookieValue } = getCookie();

            if (enabled && isNil(cookieValue)) {
                await token.set(null);
            }
        })
    }

    const addChangeListener = (callback: () => void) => {
        cookies.addChangeListener(callback);
    }

    return {
        KeyStore,
        isLoggedIn,
        isLocalAccount,
        updateCredentials,
        generateOneTimeToken,
        clearLoginState,
        getClientSecInfo,
        reconcileState,
        addChangeListener
    }
}