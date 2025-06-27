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
export * from './default/app-data'

//Axios exports
export { useAxios } from './default/axios'

//User exports
export * from './default/account'

//Mfa exports
export * from './default/mfa/login'
export * from './default/mfa/pki'
export * from './default/mfa/config'
export * from './default/mfa/fido'
export * from './default/mfa/totp'

//Social exports
export * from './default/social'

//Export helpers
export { debugLog } from './default/helpers/debugLog'
export * from './default/helpers/binhelpers'
export * from './default/helpers/webcrypto'
export * from './default/helpers/jrpc'

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