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

/*************************
    EXPORTS
*************************/

export type { 
    WebMessage, 
    ServerValidationError, 
    StorageLikeAsync,
    Awaitable,
    GlobalApiConfig, 
    GlobalConfigUpdate
} from './default/types'

//Forward session public exports
export type * from './default/session'
export { useSession } from './default/session'

//App-data
export type { 
    AppDataGetOptions,
    AppDataSetOptions, 
    UserAppDataApi, 
    ScopedUserAppDataApi
} from './default/app-data'
export { useAppDataApi, useScopedAppDataApi } from './default/app-data'

//Axios exports
export { useAxios } from './default/axios'

//User exports
export type * from './default/account/types'
export { 
    useAccountRpc, 
    useAccount, 
    useProfile, 
    isLoggedIn, 
    isLocalAccount 
} from './default/account'

//Mfa exports
// Config exports
export type { 
    UserArg, 
    MfaMethodResponse,
    MfaGetResponse, 
    MfaRequestJson, 
    MfaApi 
} from './default/mfa/config'
export { useMfaApi, mfaGetDataFor } from './default/mfa/config'

// Login exports  
export type { 
    MfaMethod, 
    IMfaSubmission, 
    IMfaMessage, 
    IMfaFlow, 
    IMfaContinuation, 
    MfaUpgradeState, 
    IMfaTypeProcessor, 
    IMfaLoginManager 
} from './default/mfa/login'
export { useMfaLogin } from './default/mfa/login'

// PKI exports
export type { 
    PkOtpLogin, 
    PkiLogin, 
    PkiPublicKey, 
    OtpRpcGetData, 
    IOtpRequestOptions, 
    OtpApi 
} from './default/mfa/pki'
export { useOtpAuth, useOtpApi, otpGetMfaData } from './default/mfa/pki'

// FIDO exports
export type { 
    IFidoServerOptions, 
    IFidoRequestOptions, 
    IFidoDevice, 
    FidoRpcGetData, 
    IFidoApi, 
    UseFidoApi, 
    FidoAuthenticateOptions 
} from './default/mfa/fido'
export { useFidoApi, fidoMfaProcessor, fidoMfaAuthenticate, fidoGetMfaData } from './default/mfa/fido'

// TOTP exports
export type { TotpRequestOptions, TotpUpdateResponse, ITotpApi, TotpSubmitCodeOptions } from './default/mfa/totp'
export { useTotpApi, totpMfaProcessor, totpSubmitCode } from './default/mfa/totp'

//Social exports
export type { 
    SocialOAuthMethod, 
    SocialLoginRpcResponse, 
    BeginFlowArgs, 
    LogoutArguments, 
    LogoutResponse, 
    SocialLoginApi 
} from './default/social'
export { useOauthLogin } from './default/social'

//Export helpers
export { debugLog } from './default/helpers/debugLog'

// Binary helpers
export { 
    LongToArray, 
    IntToArray, 
    Base64ToArray, 
    Base64ToUint8Array, 
    Utf8StringToBuffer, 
    ArrayBuffToBase64, 
    ArrayToHexString 
} from './default/helpers/binhelpers'

// Webcrypto helpers
export { 
    isCryptoSupported, 
    getCryptoOrThrow, 
    hmacSignAsync, 
    decryptAsync, 
    getRandomHex 
} from './default/helpers/webcrypto'

// JRPC helpers  
export type { RpcMethodArgs, RpcClient } from './default/helpers/jrpc'
export { useJrpc } from './default/helpers/jrpc'

/*************************
    SETUP/LOCALS
*************************/

import { cloneDeep } from 'lodash-es';
import { setApiConfigInternal } from './default/globalState';
import type { GlobalConfigUpdate } from './default/types';

/**
 * Configures the global api settings for the entire library,
 * may be called at any time, but should be called in the main app component
 * before other stateful components are mounted.
 */
export const configureApi = (config: GlobalConfigUpdate) => setApiConfigInternal(cloneDeep(config));