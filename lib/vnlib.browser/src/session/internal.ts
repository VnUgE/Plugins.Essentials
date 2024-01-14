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

import { defaults, isEmpty, isNil } from 'lodash-es';
import { computed, watch, type Ref } from "vue";
import { get, set, toRefs } from '@vueuse/core';
import { SignJWT } from 'jose'
import crypto, { decryptAsync, getRandomHex } from "../webcrypto";
import { ArrayBuffToBase64, Base64ToUint8Array } from '../binhelpers'
import { debugLog } from "../util";
import type { CookieMonitor } from './cookies'
import type { ISession, ISessionKeyStore, ITokenResponse, ClientCredential, SessionConfig } from './types'

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


enum ServerLiTokenValues{
    NoToken = 0,
    LocalAccount = 1,
    ExternalAccount = 2
}

const createKeyStore = (storage: Ref<IKeyStorage>, keyAlg: Ref<AlgorithmIdentifier>): IInternalKeyStore => {

    const { priv, pub } = toRefs(storage)

    const getPublicKey = async (): Promise<string> => {
        //Check if we have a public key
        if (isNil(pub.value)) {
            //If not, generate a new key pair
            await checkAndSetKeysAsync();
            return pub.value!;
        }
        return pub.value;
    }

    const setCredentialAsync = async (keypair: CryptoKeyPair): Promise<void> => {
        // Store the private key
        const newPrivRaw = await crypto.exportKey('pkcs8', keypair.privateKey);
        const newPubRaw = await crypto.exportKey('spki', keypair.publicKey);

        //Store keys as base64 strings
        priv.value = ArrayBuffToBase64(newPrivRaw);
        pub.value = ArrayBuffToBase64(newPubRaw);
    }

    const clearKeys = async (): Promise<void> => {
        set(priv, null);
        set(pub, null);
    }

    const checkAndSetKeysAsync = async (): Promise<void> => {
        // Check if we have a key pair already
        if (!isNil(priv.value) && !isNil(pub.value)) {
            return;
        }

        // If not, generate a new key pair
        const keypair = await crypto.generateKey(keyAlg.value, true, ['encrypt', 'decrypt']) as CryptoKeyPair;

        //Set credential
        await setCredentialAsync(keypair);

        debugLog("Generated new client keypair, none were found")
    }

    const regenerateKeysAsync = (): Promise<void> => {
        //Clear keys and generate new ones
        clearKeys();
        return checkAndSetKeysAsync();
    }

    const decryptDataAsync = async (data: string | ArrayBuffer): Promise<ArrayBuffer> => {
        // Convert the private key to a Uint8Array from its base64 string
        const keyData = Base64ToUint8Array(priv.value || "")

        //import private key as pkcs8
        const privKey = await crypto.importKey('pkcs8', keyData, keyAlg.value, false, ['decrypt'])

        // Decrypt the data and return it
        return await decryptAsync(keyAlg.value, privKey, data, false) as ArrayBuffer
    }

    const decryptAndHashAsync = async (data: string | ArrayBuffer): Promise<string> => {
        // Decrypt the data
        const decrypted = await decryptDataAsync(data)

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

const createUtil = (utilState: Ref<SessionConfig>, sessionStorage: Ref<IStateStorage>, keyStorage: Ref<IKeyStorage>) => {

    const otpNonceSize = 16;
    const { browserIdSize, signatureAlgorithm: sigAlg, keyAlgorithm: keyAlg } = toRefs(utilState);

    const KeyStore = createKeyStore(keyStorage, keyAlg);

    //Create session state and key store
    const { browserId, token } = toRefs(sessionStorage);

    const getBrowserId = (): string => {
        // Check browser id
        if (isNil(browserId.value)) {
            // generate a new random value and store it
            browserId.value = getRandomHex(browserIdSize.value);
            debugLog("Generated new browser id, none was found")
        }

        return browserId.value;
    }

    const updateCredentials = async (response: ITokenResponse): Promise<void> => {
        /*
        * The server sends an encrypted HMAC key 
        * using our public key. We need to decrypt it 
        * and use it to sign messages to the server.
        */
        const decrypted = await KeyStore.decryptDataAsync(response.token)

        // Convert the hash to a base64 string and store it
        token.value = ArrayBuffToBase64(decrypted)
    }

    const generateOneTimeToken = async (path: string): Promise<string | null> => {
        //we need to get the shared key from storage and decode it, it may be null if not set
        const sharedKey = token.value ? Base64ToUint8Array(token.value) : null

        if (!sharedKey) {
            return null;
        }

        //Inint jwt with a random nonce
        const nonce = getRandomHex(otpNonceSize);

        //Get the alg from the config
        const alg = get(sigAlg);

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
        set(browserId, null);
        set(token, null);
        KeyStore.clearKeys();
    }

    const getClientSecInfo = async (): Promise<ClientCredential> => {
        //Generate and get the credential info
        const publicKey = await KeyStore.getPublicKey();
        const browserId = getBrowserId();
        return { publicKey, browserId };
    }

    return { 
        KeyStore,
        getClientSecInfo, 
        updateCredentials,
        generateOneTimeToken,
        clearLoginState 
    };
}

export const createSession = (
    sessionConfig: Readonly<Ref<SessionConfig>>, 
    cookies: CookieMonitor<number>, 
    keys: Ref<IKeyStorage>, 
    state: Ref<IStateStorage>
): ISession =>{

    //assign defaults to storage slots before toRefs call
    defaults(state.value, { token: null, browserId: null });
    defaults(keys.value, { priv: null, pub: null });

    //Create the session util
    const util = createUtil(sessionConfig, state, keys);
    const { token } = toRefs(state);
    const isServerTokenSet = computed<boolean>(() => !isEmpty(token.value));

    //Translate the cookie value to a LoginCookieValue
    const { enabled, cookieValue } = cookies

    //If cookies are disabled, only allow the user to be logged in if the token is set
    const loggedIn = computed<boolean>(() => enabled.value ? cookieValue.value > 0 && isServerTokenSet.value : isServerTokenSet.value);

    const isLocalAccount = computed<boolean>(() => cookieValue.value === ServerLiTokenValues.LocalAccount);

    //Watch the logged in value and if it changes from true to false, clear the token
    watch(loggedIn, value => value ? null : token.value = null);

    return { 
        loggedIn,
        isLocalAccount,
        ...util
    }
}

