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

import type { AxiosInstance, AxiosRequestConfig } from "axios";
import { StorageLikeAsync } from "../types";

export interface SessionConfig {
    readonly browserIdSize: number;
    readonly signatureAlgorithm: string;
    readonly keyAlgorithm: AlgorithmIdentifier;
}

export interface AccountRpcApiConfig{
    readonly endpointUrl: string;
}

export interface GlobalSessionConfig extends SessionConfig  {
}

export interface GlobalAxiosConfig extends AxiosRequestConfig {
    tokenHeader: string;
    configureAxios?: (axios: AxiosInstance) => AxiosInstance;
}

export interface GlobalApiConfig {
    readonly session: GlobalSessionConfig;
    readonly axios: GlobalAxiosConfig;
    readonly account: AccountRpcApiConfig;
    readonly storage: StorageLikeAsync;
}

export interface GlobalConfigUpdate {
    readonly session?: Partial<GlobalSessionConfig>;
    readonly axios?: Partial<GlobalAxiosConfig>;
    readonly account?: Partial<AccountRpcApiConfig>;
    readonly storage?: StorageLikeAsync;
} 