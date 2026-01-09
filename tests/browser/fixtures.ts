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

import { createApiConfig, type UserLoginCredential } from '@vnuge/vnlib.browser'
import Axios from 'axios'

/**
 * Shared test user credentials for e2e tests.
 * This user must exist on the test server for the tests to pass.
 */
export const testUser: UserLoginCredential = {
    userName: 'test@test.com',
    password: 'Password12!'
}


export const vnlib = createApiConfig({
    account: {
        endpointUrl: '/api/account'
    },
    axios: {
        instance: Axios.create({
            baseURL: "/test",
            withCredentials: true
        }),
    },
    session: {}
    // storage auto-detected: uses wrapped localStorage in browser/jsdom
})