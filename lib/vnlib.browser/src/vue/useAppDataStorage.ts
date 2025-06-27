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

import { first } from "lodash-es"
import type { StorageLikeAsync } from "@vueuse/core"
import type { UserAppDataApi } from "../default/app-data"

/**
 * Creates a StorageLikeAsync object that uses the given UserAppDataApi
 * @param api The UserAppDataApi instance to use
 * @returns The StorageLikeAsync object
 */
export const useAppDataAsyncStorage = (api: UserAppDataApi): StorageLikeAsync => {
    return{
        getItem: async (key: string) => {
            const result = await api.get<string[]>(key)
            return first(result) || null
        },
        setItem: (key: string, value: string) => {
            //NOTE: An array is used to force axios to serialize the
            //value and send the data to the server a file
            return api.set(key, [value])
        },
        removeItem: async (key: string) => {
            return api.remove(key)
        }
    }
}