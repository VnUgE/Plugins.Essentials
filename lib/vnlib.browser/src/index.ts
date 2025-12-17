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
    CORE CONFIG & TYPES
*************************/

// Core configuration
export { createApiConfig } from './default/config';
export { getDefaultSessionConfig } from './default/session';
export { getDefaultAccountConfig } from './default/account';
export { getDefaultAxiosRequestConfig } from './default/axios';

// Core types
export type { 
    WebMessage, 
    ServerValidationError,
    ApiConfig,
    ApiConfigOverrides,
    SessionConfig,
    Awaitable,
    ConfigScopeToken
} from './default/types';

/*************************
    SESSION
*************************/

export type { 
    ISession,
    ITokenResponse,
    ClientCredential
} from './default/session';
export { useSession } from './default/session';

/*************************
    ACCOUNT & AUTH
*************************/

export type { 
    AccountApi,
    AccountRpcApi,
    AccountRpcApiConfig,
    AccountRpcGetResult,
    AccountRpcRequest,
    AccountRpcResponse,
    ExtendedLoginResponse,
    IUserLoginRequest,
    ProfileApi,
    UserLoginCredential,
    UserProfile
} from './default/account/types';

export { 
    useAccount, 
    useAccountRpc, 
    useProfile, 
    isLoggedIn, 
    isLocalAccount 
} from './default/account';

/*************************
    AXIOS
*************************/

export { 
    useAxios, 
    type AxiosConfig 
} from './default/axios';

/*************************
    APP DATA
*************************/

export type {
    AppDataApiOptions,
    AppDataGetOptions,
    AppDataSetOptions,
    ScopedUserAppDataApi,
    UserAppDataApi
} from './default/app-data';

export { 
    useAppDataApi,
    useScopedAppDataApi
} from './default/app-data';

/*************************
    MFA
*************************/

// MFA types and core
export type {
    IMfaFlow,
    IMfaLoginManager,
    IMfaMessage,
    IMfaSubmission,
    IMfaContinuation,
    IMfaTypeProcessor,
    MfaMethod,
    MfaLoginOptions,
    MfaUpgradeState
} from './default/mfa/login';

export { useMfaLogin } from './default/mfa/login';

export type {
    MfaApi,
    MfaGetResponse,
    MfaMethodResponse,
    MfaRequestJson,
    UserArg
} from './default/mfa/config';

export { 
    useMfaApi,
    mfaGetDataFor
} from './default/mfa/config';

// FIDO
export type {
    FidoAuthenticateOptions,
    FidoRpcGetData,
    IFidoApi,
    IFidoDevice,
    IFidoRequestOptions,
    IFidoServerOptions,
    UseFidoApi
} from './default/mfa/fido';

export {
    useFidoApi,
    fidoMfaProcessor,
    fidoMfaAuthenticate,
    fidoGetMfaData
} from './default/mfa/fido';

// TOTP
export type {
    ITotpApi,
    TotpRequestOptions,
    TotpSubmitCodeOptions,
    TotpUpdateResponse
} from './default/mfa/totp';

export {
    useTotpApi,
    totpMfaProcessor,
    totpSubmitCode
} from './default/mfa/totp';

// PKI/OTP
export type {
    IOtpRequestOptions,
    OtpApi,
    OtpAuthOptions,
    OtpRpcGetData,
    PkiLogin,
    PkiPublicKey,
    PkOtpLogin
} from './default/mfa/pki';

export {
    useOtpApi,
    useOtpAuth,
    otpGetMfaData
} from './default/mfa/pki';

/*************************
    SOCIAL/OAUTH
*************************/

export type {
    BeginFlowArgs,
    LogoutArguments,
    LogoutResponse,
    OauthLoginOptions,
    SocialLoginApi,
    SocialLoginRpcResponse,
    SocialOAuthMethod
} from './default/social';

export { useOauthLogin } from './default/social';

/*************************
    HELPERS
*************************/

export type {
    RpcClient,
    RpcMethodArgs
} from './default/helpers/jrpc';

export { useJrpc } from './default/helpers/jrpc';

export type { AsyncStorageItem } from './default/helpers/storage';
export { createStorageSlot } from './default/helpers/storage';

export type { CryptoContext } from './default/helpers/webcrypto';
export {
    isCryptoSupported,
    getCryptoContext,
    getCryptoOrThrow,
    hmacSignAsync,
    decryptAsync,
    getRandomHex
} from './default/helpers/webcrypto';

export {
    LongToArray,
    IntToArray,
    Base64ToArray,
    Base64ToUint8Array,
    Utf8StringToBuffer,
    ArrayBuffToBase64,
    ArrayToHexString
} from './default/helpers/binhelpers';

export { debugLog } from './default/helpers/debugLog';